import boto3
import os
import logging
import time
import re
import concurrent.futures
from ec2_post_orc_sanity import windows_final_configuration_post_orc
from botocore.exceptions import ClientError
from crowdstrike_api import crowdstrike_falcon_api
from splunk_api import splunk_api_details

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cross_account_role_name = os.environ['CROSS_ACCOUNT_ORC_ROLE']


valid_windows_os_versions = ['2016', '2019', '2022']

splunk_version = "9.2.1"
aws_ssm_agent_version = "3.3.1"
cloudwatch_agent_version = "1.4"
carbon_block_version = "8.8"
crowdstrike_version = "7.11"


required_splunk_raw = tuple(map(int, splunk_version.split('.')))
required_aws_ssm_agent_version_raw = tuple(map(int, aws_ssm_agent_version.split('.')))
required_cloudwatch_agent_version_raw = tuple(map(int, cloudwatch_agent_version.split('.')))
required_carbon_block_version_raw = tuple(map(int, carbon_block_version.split('.')))
required_crowdstrike_version_raw = tuple(map(int, crowdstrike_version.split('.')))



commandsList = {
    'Server hostname': "$env:COMPUTERNAME",
    'Firewall Status': 'Get-NetFirewallProfile | Select Name,Enabled',
    'ECN Capability':'(Get-NetTCPSetting -Setting Internet).EcnCapability',
    'NTP Server Details':'w32tm /query /status | Findstr "Source:"',
    'DNS Resolution Output':'', #this command is dynamically generated at the later stage,
    'IPv6 Enabled' : (
    'if (Get-NetAdapterBinding -ComponentID ms_tcpip6 | '
    'Where-Object { $_.Enabled -eq $true } | Select-Object -First 1) '
    '{ Write-Output "true" } else { Write-Output "false" }'
    ),
    "DHCP Status": 'Get-NetIPInterface | Where-Object { $_.InterfaceAlias -like "Ethernet*" } | ForEach-Object { "$($_.InterfaceAlias): $($_.Dhcp)" }',
    'Server OperatingSystem Version':'(Get-CimInstance Win32_OperatingSystem).Caption',
    'Splunk Version':"(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object{$_.DisplayName -like '*UniversalForwarder*'}).DisplayVersion",
    'SSM Agent Version':"(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object{$_.DisplayName -like '*Amazon SSM Agent*'}).DisplayVersion",
    'Cloudwatch Agent Version':"(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object{$_.DisplayName -like '*Amazon CloudWatch Agent*'}).DisplayVersion",
    'Carbon Black App Control Agent Version':"(Get-ItemProperty HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object{$_.DisplayName -like '*Carbon Black App Control Agent*'}).DisplayVersion",
    'Crowdstrike Agent Version':"(Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object{$_.DisplayName -like '*CrowdStrike Windows Sensor*'}).DisplayVersion",
    'PV Drivers Version':"(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object{$_.DisplayName -like '*AWS PV Drivers*'}).DisplayVersion",
    'ENA Adapter Version': '(Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*Elastic Network Adapter*" }).DriverVersion',
    'NVMe Adapter Version': '(Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*NVMe*" }).DriverVersion',
    'TEC AD OU Check':"(Get-WmiObject -Class Win32_ComputerSystem).Domain",
    "Admin Group Membership Check": (
        '$admin = "G-HCP-Admin-$env:COMPUTERNAME"; '
        '$members = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -like "*$admin*" }; '
        'if ($members) { $members.Name } else { "no" }'
        ),
    "RDP Group Membership Check": (
        '$rdp = "G-HCP-RDPUser-$env:COMPUTERNAME"; '
        '$members = Get-LocalGroupMember -Group "Remote Desktop Users" | Where-Object { $_.Name -like "*$rdp*" }; '
        'if ($members) { $members.Name } else { "no" }'
        )
    }


def send_ssm_command(title, cmd, ssm_client, instance_id):
    try:
        resp = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={'commands': [cmd]}
        )
        command_id = resp['Command']['CommandId']
        time.sleep(2)

        for _ in range(30):
            output = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            if output['Status'] in ["Success", "Failed", "Cancelled", "TimedOut"]:
                break
            time.sleep(1)

        if output['Status'] != "Success":
            logger.warning(f"Command {title} failed: {output.get('StandardErrorContent', '')}")
            return title, f"Command Failed: {output.get('StandardErrorContent', '').strip()}"

        return title, output['StandardOutputContent'].strip()

    except Exception as e:
        logger.warning(f"Failed to run command {title}: {e}")
        return title, "Command Failed"



def ec2_windows_os_checks(received_event):
    input_event = received_event[0]["info"]
    instance_id = input_event['resource_id']
    region = input_event['region']
    account_id = input_event['account_id']
    patch_tag = input_event['patch_tag']
    account_name = input_event['account_name']
    boundary_onboarding_result = received_event[1]["Boundary Onboarding Status"]

    windows_os_checks = []
    cross_account_role = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"

    try:
        sts = boto3.client('sts')
        assumed_role = sts.assume_role(
            RoleArn=cross_account_role,
            RoleSessionName='CrossAccountRole',
            DurationSeconds=3600
        )
        creds = assumed_role['Credentials']
        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region
        )
        try:
            ec2_client = session.client('ec2')
            ssm_client = session.client('ssm')
            sns_client = session.client('sns')
            kms_client = session.client('kms')

            ec2_response = ec2_client.describe_instances(InstanceIds=[instance_id])

            console_hostname = "NA"
            asec_djo_value = "NA"
            domain_name = "NA"
            appliance_tag = "NA"
            custom_ami_tag = "NA"

            if ec2_response['Reservations']:
                tags = ec2_response['Reservations'][0]['Instances'][0].get('Tags', [])
                for tag in tags:
                    key_lower = tag['Key'].lower()
                    value = tag.get('Value', 'NA')

                    if key_lower == 'name':
                        console_hostname = value
                    if key_lower == 'asec-djo':
                        asec_djo_value = value
                        domain_name = f"{asec_djo_value}.com" if asec_djo_value != "NA" else "NA"
                    if key_lower == 'is-appliance':
                        appliance_tag = value
                    if key_lower == 'is-custom-ami':
                        custom_ami_tag = value

                        
            ## FQDN of EC2 based on asec-djo tag 
            ec2_fqdn = f"{console_hostname}.{domain_name}"
            if asec_djo_value != "NA":
                commandsList["DNS Resolution Match"] = f'if ((nslookup "{ec2_fqdn}" 2>&1 | Select-String "Name:")) {{ Write-Output "True" }} else {{ Write-Output "False" }}'
            
            ssm_status = ssm_client.get_connection_status(Target=instance_id)
            if ssm_status['Status'] != 'connected':
                received_event[0]['OS Level Checks'] = [{
                    "Check-Name": "SSM Connectivity",
                    "Resource ID": instance_id,
                    "Expected Result": "Connected",
                    "Actual Result": ssm_status['Status'],
                    "Remarks": "FAIL"
                }]
                return received_event

            commandoutput = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(send_ssm_command, title, cmd, ssm_client, instance_id): title
                    for title, cmd in commandsList.items()
                }
                for future in concurrent.futures.as_completed(futures):
                    title, output = future.result()
                    commandoutput[title] = output

            # Hostname check
            hostname_actual = commandoutput.get("Server hostname", "NA").strip()
            hostname_remarks = "PASS" if hostname_actual.upper() == console_hostname.upper() else "FAIL"
            windows_os_checks.append({
                "Check-Name": "Server hostname check as per console",
                "Expected Result": console_hostname.upper(),
                "Actual Result": hostname_actual.upper(),
                "Remarks": hostname_remarks
            })
            
            ## hashicorp boundary check
            
            
            ## admin group check
            
            if hostname_remarks == "FAIL":
                admin_group_remarks = "Skipping Check as hostname check was unsuccessful"
                admin_actual_group_name = "cannot be determined"
                admin_boundary_check = "cannot be determined"
            else:
                admin_actual_group_name = f"G-HCP-Admin-{console_hostname}"
                admin_boundary_check_raw = commandoutput.get("Admin Group Membership Check", "NA").strip()

                admin_boundary_check = re.sub(r'^.*?\\', '', admin_boundary_check_raw)
                if admin_boundary_check == "no":
                    admin_group_remarks = "FAIL"
                elif admin_boundary_check == admin_actual_group_name:
                    admin_group_remarks = "PASS"
                else:
                    admin_group_remarks = "FAIL"

            windows_os_checks.append({
            "Check-Name": "Admin Boundary Group Present",
            "Expected Result": admin_actual_group_name,
            "Actual Result": admin_boundary_check,
            "Remarks": admin_group_remarks
            })
            
            if admin_group_remarks == "PASS":
                received_event[0]["EC2 Associated Informations"][0]["Admin Active Directory Group"] = admin_actual_group_name
                
        
            ## RDP group check
            
            if hostname_remarks == "FAIL":
                rdp_group_remarks = "Skipping Check as hostname check was unsuccessful"
                rdp_actual_result = "cannot be determined"
                rdp_boundary_check = "cannot be determined"
            else:
                rdp_actual_result = f"G-HCP-RDPUser-{console_hostname}"
                rdp_boundary_check_raw = commandoutput.get("RDP Group Membership Check").strip()
                rdp_boundary_check = re.sub(r'^.*?\\', '', rdp_boundary_check_raw)
                if rdp_boundary_check == "no":
                    rdp_group_remarks = "FAIL"
                elif rdp_boundary_check == rdp_actual_result:
                    rdp_group_remarks = "PASS"
                else:
                    rdp_group_remarks = "FAIL"

            windows_os_checks.append({
            "Check-Name": "RDP Boundary Group Present",
            "Expected Result": rdp_actual_result,
            "Actual Result": rdp_boundary_check,
            "Remarks": rdp_group_remarks
            })
            
            if admin_group_remarks == "PASS":
                received_event[0]["EC2 Associated Informations"][0]["RDP Active Directory Group"] = rdp_actual_result
            
            ## Onboarded in Hashicorp Boundary Check (Database Oriented)
            
            
            windows_os_checks.append({
                "Check-Name": "Hashicorp Boundary Onboarding Status",
                "Expected Result": "Onboarded in Boundary",
                "Actual Result": boundary_onboarding_result,
                "Remarks": "PASS" if boundary_onboarding_result == "Onboarded in Boundary" else "FAIL"
                })
            
            ## Onboarded in CrowdStrike Falcon
            crwd_result = crowdstrike_falcon_api(instance_id)
            
            windows_os_checks.append({
                "Check-Name": "Onboarded into Crowdstrike",
                "Expected Result": "Yes",
                "Actual Result": crwd_result,
                "Remarks": "PASS" if crwd_result == "Yes" else "FAIL"
                })
            
            ## Onboarded in Splunk
            
            splunk_api_results = splunk_api_details(hostname_actual)
            
            windows_os_checks.append({
                "Check-Name": "Onboarded into Splunk",
                "Expected Result": "Yes",
                "Actual Result": splunk_api_results,
                "Remarks": "PASS" if splunk_api_results == "Yes" else "FAIL"
                })
            
            ## TEC AD OU Check
            
            ou_domain_check = commandoutput.get("TEC AD OU Check", "").strip()
            
            if domain_name!= "NA":
                ad_ou_result = ou_domain_check
            else:
                ad_ou_result = "cannot verify, domain join tag asec-djo is missing or incorrect",
            
            windows_os_checks.append({
                "Check-Name": "Domain Join Details",
                "Expected Result": domain_name,
                "Actual Result": ad_ou_result,
                "Remarks": "PASS" if ad_ou_result == domain_name else "FAIL"
            })
            
            
            # DNS Resolution Check
            dns_result = commandoutput.get("DNS Resolution Match", "").strip().lower() 
            
            if domain_name != "NA":
                actual_result = dns_result
            else:
                actual_result = "cannot verify, domain join tag asec-djo is missing",

            windows_os_checks.append({
                "Check-Name": "DNS Resolution Status",
                "Expected Result": "true",
                "Actual Result": actual_result,
                "Remarks": "PASS" if dns_result == "true" else "FAIL"
            })
            
            ## ECN Capability Check
            
            ecn_capability = commandoutput.get("ECN Capability", "NA").strip()
            windows_os_checks.append({
                "Check-Name": "ECN Capability Check",
                "Expected Result": 'Disabled',
                "Actual Result": ecn_capability,
                "Remarks": 'PASS' if ecn_capability == 'Disabled' else 'FAIL'
            })
            
            ## DHCP Status Check
            
            dhcp_status_raw = commandoutput.get("DHCP Status", "").strip().lower().splitlines()
            dhcp_summary = []
            fail_found = False

            for line in dhcp_status_raw:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                adapter, status = map(str.strip, line.split(":", 1))
                dhcp_summary.append(f"{adapter.capitalize()}: {status.capitalize()}")
                if status != "enabled":
                    fail_found = True

            windows_os_checks.append({
                "Check-Name": "Ethernet DHCP Configuration",
                "Expected Result": "All Ethernet adapters should have DHCP enabled",
                "Actual Result": ", ".join(dhcp_summary) if dhcp_summary else "No adapter info found",
                "Remarks": "FAIL" if fail_found else "PASS"
            })

            
            # Firewall check
            
            firewall_raw = commandoutput.get("Firewall Status", "")
            enabled_profiles = [line.split()[0] for line in firewall_raw.splitlines() if 'True' in line]
            actual_result = ", ".join(enabled_profiles) if enabled_profiles else "No"
            remarks = "FAIL" if enabled_profiles else "PASS"
            windows_os_checks.append({
                "Check-Name": "Windows Firewall Enabled",
                "Expected Result": "No",
                "Actual Result": actual_result,
                "Remarks": remarks
            })
            
            ipv6_status = commandoutput.get("IPv6 Enabled", "").strip().lower()
            remarks = "PASS" if ipv6_status == "false" else "FAIL"

            windows_os_checks.append({
                "Check-Name": "IPv6 Status",
                "Expected Result": "false",
                "Actual Result": ipv6_status,
                "Remarks": remarks
            })
            
            # NTP Server Details Check
            ntp_output = commandoutput.get("NTP Server Details", "").strip()
            ntp_server = "No Output"
            remarks = "FAIL"

            if "Source:" in ntp_output:
                ntp_server = ntp_output.split("Source:")[-1].strip()
                if domain_name == "NA":
                    remarks = "FAIL"
                elif ntp_server.lower().endswith(domain_name):
                    remarks = "PASS"

            windows_os_checks.append({
                "Check-Name": "NTP Configuration Status",
                "Expected Result": f"*.{domain_name}" if domain_name != "NA" else "cannot verify, domain join tag asec-djo is missing",
                "Actual Result": ntp_server,
                "Remarks": remarks
            })
            
            ## Server Operating System Version
            
            os_version_raw = commandoutput.get("Server OperatingSystem Version", "").strip()

            if custom_ami_tag != "NA" and appliance_tag != "NA":
                os_version = "Custom AMI, Skipping OS Version Check"
                remarks = "PASS"
            else:
                match = re.search(r"\b(2016|2019|2022)\b", os_version_raw)
                if match:
                    os_version = match.group(1)
                    remarks = "PASS"
                else:
                    os_version = os_version_raw or "Unknown"
                    remarks = "FAIL"

            windows_os_checks.append({
                "Check-Name": "Operating System Version",
                "Expected Result": "2016, 2019, or 2022",
                "Actual Result": os_version,
                "Remarks": remarks
            })
                
            ## Splunk Version
            
            splunk_raw = commandoutput.get("Splunk Version", "").strip()
            actual_splunk_version = tuple(map(int, splunk_raw.split('.'))) if splunk_raw else ()

            if actual_splunk_version and actual_splunk_version >= required_splunk_raw:
                actual_result = splunk_raw
                remarks = "PASS"
            elif not actual_splunk_version:
                actual_result = "No version found"
                remarks = "FAIL"
            else:
                actual_result = splunk_raw
                remarks = "FAIL"

            windows_os_checks.append({
                "Check-Name": f"Splunk Version Check",
                "Expected Result": f">={splunk_version}",
                "Actual Result": actual_result,
                "Remarks": remarks
            })
            
            ## aws ssm agent version
            
            aws_ssm_agent_raw = commandoutput.get("SSM Agent Version", "").strip()

            def parse_version(raw):
                try:
                    # only keep digits and dots, skip if invalid
                    if not raw or not raw[0].isdigit():
                        return ()
                    return tuple(map(int, raw.split('.')))
                except Exception:
                    return ()

            actual_aws_ssm_agent = parse_version(aws_ssm_agent_raw)

            if actual_aws_ssm_agent and actual_aws_ssm_agent >= required_aws_ssm_agent_version_raw:
                actual_result = aws_ssm_agent_raw
                remarks = "PASS"
            elif not actual_aws_ssm_agent:
                actual_result = "No version found"
                remarks = "FAIL"
            else:
                actual_result = aws_ssm_agent_raw
                remarks = "FAIL"

            windows_os_checks.append({
                "Check-Name": "AWS SSM Agent Version Check",
                "Expected Result": f">={aws_ssm_agent_version}",
                "Actual Result": actual_result,
                "Remarks": remarks
            })
            
            ## cloudwatch agent version

            cloudwatch_agent_raw = commandoutput.get("Cloudwatch Agent Version", "").strip()
            actual_cw_agent = tuple(map(int, cloudwatch_agent_raw.split('.'))) if cloudwatch_agent_raw else ()

            if actual_cw_agent and actual_cw_agent >= required_cloudwatch_agent_version_raw:
                actual_result = cloudwatch_agent_raw
                remarks = "PASS"
            
            elif not actual_cw_agent:
                actual_result = "No version found"
                remarks = "FAIL"
            else:
                actual_result = actual_cw_agent
                remarks = "FAIL"

            windows_os_checks.append({
                "Check-Name": f"Cloudwatch Agent Version Check",
                "Expected Result": f">={cloudwatch_agent_version}",
                "Actual Result": actual_result,
                "Remarks": remarks
            })
            
            ## Carbon Black Version
            
            carbon_black_raw = commandoutput.get("Carbon Black App Control Agent Version", "").strip()           
            actual_cb_version =  tuple(map(int, carbon_black_raw.split('.'))) if carbon_black_raw else ()
            
            if actual_cb_version and actual_cb_version >= required_carbon_block_version_raw:
                actual_result = carbon_black_raw
                remarks = "PASS"
            
            elif not actual_cb_version:
                actual_result = "No version found"
                remarks = "FAIL"
            else:
                actual_result = carbon_black_raw
                remarks = "FAIL"

            windows_os_checks.append({
                "Check-Name": f"Carbon Black Agent Version Check",
                "Expected Result": f">={carbon_block_version}",
                "Actual Result": actual_result,
                "Remarks": remarks
            })

            ## Crowdstrike Version
            
            crowd_strike_raw = commandoutput.get("Crowdstrike Agent Version", "").strip()           
            
            actual_cs_version =  tuple(map(int, crowd_strike_raw.split('.'))) if crowd_strike_raw else ()
            
            if actual_cs_version and actual_cs_version >= required_crowdstrike_version_raw:
                actual_result = crowd_strike_raw
                remarks = "PASS"
            
            elif not actual_cs_version:
                actual_result = "No version found"
                remarks = "FAIL"
            else:
                actual_result = crowd_strike_raw
                remarks = "FAIL"

            windows_os_checks.append({
                "Check-Name": f"Crowd Strike Agent Version Check",
                "Expected Result": f">={crowdstrike_version}",
                "Actual Result": actual_result,
                "Remarks": remarks
            })
            
            ## Existance of PV Drivers Version
            
            pv_driver_version = commandoutput.get("PV Drivers Version", "").strip()
            
            windows_os_checks.append({
                "Check-Name": f"PV Drivers Exist",
                "Expected Result": "Yes",
                "Actual Result": f"Yes:- {pv_driver_version}" if pv_driver_version else "Not Available",
                "Remarks": "PASS" if pv_driver_version else "FAIL"
            })
            
            ## Existance of ENA Adapter Version
            
            ena_driver_version = commandoutput.get("ENA Adapter Version", "").strip()
            
            windows_os_checks.append({
                "Check-Name": f"ENA Adapter Drivers Exist",
                "Expected Result": "Yes",
                "Actual Result": f"Yes:- {ena_driver_version}" if ena_driver_version else "Not Available",
                "Remarks": "PASS" if ena_driver_version else "FAIL"
            })
            
            ## NVME Drivers Exist
            
            nvme_driver_version_raw = commandoutput.get("NVMe Adapter Version", "").strip()
            if nvme_driver_version_raw:
                versions = list({v.strip() for v in nvme_driver_version_raw.splitlines() if v.strip()})
                nvme_driver_version = ", ".join(versions)
            else:
                nvme_driver_version = ""

            windows_os_checks.append({
                "Check-Name": "NVMe Drivers Exist",
                "Expected Result": "Yes",
                "Actual Result": f"Yes:- {nvme_driver_version}" if nvme_driver_version else "Not Available",
                "Remarks": "PASS" if nvme_driver_version else "FAIL"
            })
                        
            
            received_event[0]['OS Level Checks'] = windows_os_checks
            
            received_event[0]["Post ORC Tasks"] = windows_final_configuration_post_orc(sns_client, kms_client , account_name , ssm_client, instance_id, patch_tag, domain_name) 
            return received_event
        
        
        
        except ClientError as ce:
            logger.error(f"ClientError: {ce}")
            input_event.update({
                'error': str(ce),
                'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            return [{"info": input_event}]

        except Exception as e:
            logger.exception("Unexpected error occurred")
            input_event.update({
                'error': f"Unexpected error: {str(e)}",
                'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            return [{"info": input_event}]

    except ClientError as ce:
        logger.error(f"ClientError: {ce}")
        input_event.update({
            'error': str(ce),
            'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return [{"info": input_event}]

    except Exception as e:
        logger.exception("Unexpected error occurred")
        input_event.update({
            'error': f"Unexpected error: {str(e)}",
            'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return [{"info": input_event}]