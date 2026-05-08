import boto3
import os
import logging
import time
import re
import concurrent.futures
from ec2_post_orc_sanity_linux import linux_final_configuration_post_orc
from crowdstrike_api import crowdstrike_falcon_api
from botocore.exceptions import ClientError
from splunk_api import splunk_api_details

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cross_account_role_name = os.environ['CROSS_ACCOUNT_ORC_ROLE']


splunk_version = "9.2.1"
aws_ssm_agent_version = "3.3.1"
cloudwatch_agent_version = "1.4"
carbon_black_version = "8.8"
crowdstrike_version = "7.11"
tanium_version = '7.6'


required_splunk_raw = tuple(map(int, splunk_version.split('.')))
required_aws_ssm_agent_version_raw = tuple(map(int, aws_ssm_agent_version.split('.')))
required_cloudwatch_agent_version_raw = tuple(map(int, cloudwatch_agent_version.split('.')))
required_carbon_black_version_raw = tuple(map(int, carbon_black_version.split('.')))
required_crowdstrike_version_raw = tuple(map(int, crowdstrike_version.split('.')))
required_tanium_version_raw = tuple(map(int, tanium_version.split('.')))

fstab_cmd = """
if grep -Ev '^\\s*#|^\\s*$' /etc/fstab | awk '{print $2}' | grep -qx '/'; then
echo true
else
echo false
fi
"""
dns_cmd = '''
ns_ip=$(nslookup "$(hostname)" 2>/dev/null | awk '/^Address: / {print $2}' | tail -n1)
local_ip=$(hostname -i)
if [ "$ns_ip" = "$local_ip" ]; then
echo true
else
echo false
fi
'''

commandsList = {
            'root login':"sudo su - | grep 'Last login:'",
            'Install nvme':"yum install nvme-cli -y | grep 'Complete'",            
            'fstab validation':fstab_cmd,
            'audit log':"ls -al /var/log/audit* | grep -o -m 1 'audit.log'",
            'motd banner':"cat /etc/motd | grep -o -m 1 'Takeda Information Security Notice'",            
            'ecn settings':"sysctl -a | grep 'net.ipv4.tcp_ecn ='",
            'ipv6 status':"sysctl -a | egrep 'net.ipv6.conf.all.disable_ipv6|net.ipv6.conf.default.disable_ipv6'",
            'os hardening':"systemctl status hardening.service | grep -m 1 'could not be found'",
            'Server hostname':'hostname -s',
            'OS Version':'cat /etc/os-release | grep PRETTY_NAME=',
            'rhel release version':"grep '^VERSION_ID' /etc/os-release",            
            'DNS Resolution Status':dns_cmd,
            'Amazon SSM Agent Version':"rpm -qa | grep -i 'amazon-ssm-agent'",
            'SSM Running Status':"systemctl status amazon-ssm-agent | grep 'Active:'",
            'Splunk Version':'cat /opt/splunkforwarder/etc/splunk.version | grep VERSION=',
            'Splunk Running Status':'/opt/splunkforwarder/bin/splunk status | grep splunkd',
            'Splunk deployment config':'sudo cat /opt/splunkforwarder/etc/system/local/deploymentclient.conf',            
            'Crowdstrike Sensor Version':'/opt/CrowdStrike/falconctl -g --version',
            'Crowdstrike Sensor running Status':'systemctl status falcon-sensor.service | grep Active:',
            'NTP Configuration':"timedatectl | grep -o -m 1 'active'",
            'NTP Server':'cat /etc/chrony.conf | grep -i server',
            'Chronyd Status':'systemctl status chronyd | grep Active:',
            'Amazon cloudwatch agent version':'rpm -qa | grep -i cloudwatch',
            'Amazon cloudwatch Agent Status':'systemctl status amazon-cloudwatch-agent | grep Active:',            
            'Carbon Black Version':'rpm -qa|grep -i b9',
            'Carbon Black Status':'systemctl status b9daemon | grep Active:'            
}


def send_ssm_command(title, cmd, ssm_client, instance_id):
    try:
        resp = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
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

def ec2_linux_os_checks(received_event):
    input_event = received_event[0]["info"]
    instance_id = input_event['resource_id']
    region = input_event['region']
    account_id = input_event['account_id']
    patch_tag = input_event['patch_tag']
    account_name = input_event['account_name']
    boundary_onboarding_result = received_event[1]["Boundary Onboarding Status"]

    linux_os_checks = []
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

            # sudo validation check
            sudo_check = commandoutput.get("root login", "NA").strip()
            remarks = "PASS" if 'Last login'.lower() in sudo_check.lower() else "FAIL"
            linux_os_checks.append({
                "Check-Name": "sudo validation status",
                "Expected Result": '"Last login" must be present',
                "Actual Result": sudo_check,
                "Remarks": remarks
            })

            # Hostname check
            hostname_actual = commandoutput.get("Server hostname", "NA").strip()            
            remarks = "PASS" if hostname_actual.upper() == console_hostname.upper() else "FAIL"
            linux_os_checks.append({
                "Check-Name": "Server hostname check as per console",
                "Expected Result": console_hostname.upper(),
                "Actual Result": hostname_actual.upper(),
                "Remarks": remarks
            })

            ## Onboarded in Hashicorp Boundary Check (Database Oriented)
            
            
            linux_os_checks.append({
                "Check-Name": "Hashicorp Boundary Onboarding Status",
                "Expected Result": "Onboarded in Boundary",
                "Actual Result": boundary_onboarding_result,
                "Remarks": "PASS" if boundary_onboarding_result == "Onboarded in Boundary" else "FAIL"
                })

            ## Onboarded in CrowdStrike Falcon
            crwd_result = crowdstrike_falcon_api(instance_id)
            
            linux_os_checks.append({
                "Check-Name": "Onboarded into Crowdstrike",
                "Expected Result": "Yes",
                "Actual Result": crwd_result,
                "Remarks": "PASS" if crwd_result == "Yes" else "FAIL"
                })
            
            ## Onboarded in Splunk
            
            splunk_api_results = splunk_api_details(hostname_actual)
            
            linux_os_checks.append({
                "Check-Name": "Onboarded into Splunk",
                "Expected Result": "Yes",
                "Actual Result": splunk_api_results,
                "Remarks": "PASS" if splunk_api_results == "Yes" else "FAIL"
                })
            

            fstab_info_status = commandoutput.get("fstab validation", "NA").strip()
            remarks = "PASS" if 'true' in fstab_info_status else "FAIL"
            linux_os_checks.append({
                "Check-Name": "fstab validation status",
                "Expected Result": 'TRUE',
                "Actual Result": fstab_info_status.upper(),
                "Remarks": remarks
            })

            # audit log validation

            auditlog_exist_status = commandoutput.get("audit log", "NA").strip()            
            remarks = "PASS" if 'audit.log'.lower() in auditlog_exist_status.lower() else "FAIL"
            linux_os_checks.append({
                "Check-Name": "audit log validation status",
                "Expected Result": 'audit.log must be present',
                "Actual Result": auditlog_exist_status,
                "Remarks": remarks
            })

            # motd banner validation            

            motd_banner_status = commandoutput.get("motd banner", "NA").strip()            
            remarks = "PASS" if 'Takeda Information Security Notice'.lower() in motd_banner_status.lower() else "FAIL"
            linux_os_checks.append({
                "Check-Name": "motd banner validation status",
                "Expected Result": "Takeda Information Security Notice should be present in motd banner",
                "Actual Result": f"{motd_banner_status} is Present" if remarks=='PASS' else f"{motd_banner_status} is Missing",
                "Remarks": remarks
            })

            # ecn settings validation           

            ecn_settings = commandoutput.get("ecn settings", "NA").strip()            
            remarks = "PASS" if '0' in ecn_settings else "FAIL"
            linux_os_checks.append({
                "Check-Name": "ecn settings validation status",
                "Expected Result": 'Disabled',
                "Actual Result": 'Disabled' if '0' in ecn_settings else "Enabled",
                "Remarks": remarks
            })

            # IPV6 status validation           

            ipv6_settings = commandoutput.get("ipv6 status", "NA").strip()               
            remarks = "FAIL" if '0' in ipv6_settings else "PASS"
            linux_os_checks.append({
                "Check-Name": "IPV6 status validation",
                "Expected Result": 'Disabled',
                "Actual Result": 'Enabled' if '0' in ipv6_settings else "Disabled",
                "Remarks": remarks
            })
            

            # os hardening status          

            os_hardening_check = commandoutput.get("os hardening", "NA").strip()            
            remarks = "PASS" if 'could not be found' in os_hardening_check else "FAIL"
            linux_os_checks.append({
                "Check-Name": "os hardening status validation",
                "Expected Result": 'Should not be present',
                "Actual Result": 'OS Hardening is not present' if 'could not be found' in os_hardening_check else os_hardening_check,
                "Remarks": remarks
            })

            # DNS Resolution Status Check

            dns_resolution_check = commandoutput.get("DNS Resolution Status", "NA").strip()            
            remarks = "PASS" if 'true' in dns_resolution_check.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "DNS Resolution Status",
                "Expected Result": 'TRUE',
                "Actual Result": dns_resolution_check.upper(),
                "Remarks": remarks
            })

            # NTP Configuration 

            ntp_config = commandoutput.get("NTP Configuration", "NA").strip()
            remarks = "PASS" if 'active' in ntp_config.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "NTP Configuration",
                "Expected Result": 'active',
                "Actual Result": ntp_config if remarks == 'PASS' else dns_resolution_check,
                "Remarks": remarks
            })
            
            # NTP Server

            ntp_server = commandoutput.get("NTP Server", "NA").strip()            
            remarks = "PASS" if '169.254' in ntp_server else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "NTP Server",
                "Expected Result": '169.254.*.*',
                "Actual Result": ntp_server.split(' ')[1] if 'server' in ntp_server else 'NTP server ip address not available',
                "Remarks": remarks
            })
            
            # Chronyd Status

            chronyd_status = commandoutput.get("Chronyd Status", "NA").strip()            
            remarks = "PASS" if 'active' in chronyd_status.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "Chronyd Status",
                "Expected Result": 'active (running)',
                "Actual Result": 'running' if remarks == 'PASS' else 'not running',
                "Remarks": remarks
            })
            
            # Amazon SSM Agent Version

            aws_ssm_agent_raw = commandoutput.get("Amazon SSM Agent Version", "").strip()            
            if 'failed' not in aws_ssm_agent_raw.lower():
                actual_aws_ssm_agent = tuple(map(int,list(filter(None,aws_ssm_agent_raw.replace('amazon-ssm-agent','').split('-')))[0].split('.'))) if aws_ssm_agent_raw else ()
            
                if actual_aws_ssm_agent and actual_aws_ssm_agent >= required_aws_ssm_agent_version_raw:
                    actual_result = list(filter(None,aws_ssm_agent_raw.replace('amazon-ssm-agent','').split('-')))[0]
                    remarks = "PASS"
                
                elif not actual_aws_ssm_agent:
                    actual_result = "No version found"
                    remarks = "FAIL"
                else:
                    actual_result = list(filter(None,aws_ssm_agent_raw.replace('amazon-ssm-agent','').split('-')))[0]
                    remarks = "FAIL"

                linux_os_checks.append({
                    "Check-Name": "AWS SSM Agent Version Check",
                    "Expected Result": f">={aws_ssm_agent_version}",
                    "Actual Result": actual_result,
                    "Remarks": remarks
                })
            else:
                linux_os_checks.append({
                    "Check-Name": "AWS SSM Agent Version Check",
                    "Expected Result": f">={aws_ssm_agent_version}",
                    "Actual Result": "SSM Agent is not installed",
                    "Remarks": "FAIL"
                })
            # SSM Running Status

            ssm_running_status = commandoutput.get("SSM Running Status", "NA").strip()            
            remarks = "PASS" if 'active' in ssm_running_status.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "SSM Agent Status",
                "Expected Result": 'running',
                "Actual Result": 'running' if remarks =='PASS' else 'not running',
                "Remarks": remarks
            })    

            # Splunk Version

            splunk_raw = commandoutput.get("Splunk Version", "").strip()
            if 'failed' not in splunk_raw:
                actual_splunk_version = tuple(map(int,splunk_raw.split('=')[1].split('.'))) if splunk_raw else ()

                if actual_splunk_version and actual_splunk_version >= required_splunk_raw:
                    actual_result = splunk_raw.split('=')[1].strip()
                    remarks = "PASS"
                elif not actual_splunk_version:
                    actual_result = "No version found"
                    remarks = "FAIL"
                else:
                    actual_result = splunk_raw.split('=')[1].strip()
                    remarks = "FAIL"

                linux_os_checks.append({
                    "Check-Name": f"Splunk Version Check",
                    "Expected Result": f">={splunk_version}",
                    "Actual Result": actual_result,
                    "Remarks": remarks
                })
            else:
                linux_os_checks.append({
                    "Check-Name": "Splunk Version Check",
                    "Expected Result": "Splunk must be installed",
                    "Actual Result": "Splunk is not installed",
                    "Remarks": "FAIL"
                })

            # Splunk Running Status                
            
            splunk_running_status = commandoutput.get("Splunk Running Status", "NA").strip()            
            remarks = "PASS" if 'running' in splunk_running_status.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "Splunk Running Status",
                "Expected Result": 'running',
                "Actual Result": 'running' if remarks == 'PASS' else 'not running',
                "Remarks": remarks
            }) 
                        
            # Crowdstrike Sensor Version

            cs_agent_raw = commandoutput.get("Crowdstrike Sensor Version", "").strip()            
            if 'failed' not in cs_agent_raw.lower():
                actual_cs_agent_raw = tuple(map(int,cs_agent_raw.split('=')[1].split('.'))) if cs_agent_raw else ()
            
                if actual_cs_agent_raw and actual_cs_agent_raw >= required_crowdstrike_version_raw:
                    actual_result = cs_agent_raw.split('=')[1].strip()
                    remarks = "PASS"
                
                elif not actual_cs_agent_raw:
                    actual_result = "No version found"
                    remarks = "FAIL"
                else:
                    actual_result = cs_agent_raw.split('=')[1].strip()
                    remarks = "FAIL"

                linux_os_checks.append({
                    "Check-Name": "Crowdstrike Agent Version Check",
                    "Expected Result": f">={crowdstrike_version}",
                    "Actual Result": actual_result,
                    "Remarks": remarks
                })
            else:
                linux_os_checks.append({
                    "Check-Name": "Crowdstrike Agent Version Check",
                    "Expected Result": "Crowdstrike Agent must be installed",
                    "Actual Result": "Crowdstrike Agent is not installed",
                    "Remarks": "FAIL"
                })

            # Crowdstrike Sensor running Status

            cs_running_status = commandoutput.get("Crowdstrike Sensor running Status", "NA").strip()
            remarks = "PASS" if 'running' in cs_running_status.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "Crowdstrike Sensor Running Status",
                "Expected Result": 'running',
                "Actual Result": 'running' if remarks == 'PASS' else 'not running',
                "Remarks": remarks
            })            

            # Carbon Black Client Version

            cb_agent_raw = commandoutput.get("Carbon Black Version", "").strip()            
            if 'failed' not in cb_agent_raw.lower():
                actual_cb_agent_raw = tuple(map(int,cb_agent_raw.split('-')[1].split('.'))) if cb_agent_raw else ()
            
                if actual_cb_agent_raw and actual_cb_agent_raw >= required_carbon_black_version_raw:
                    actual_result = cb_agent_raw.split('-')[1].strip()
                    remarks = "PASS"
                
                elif not actual_cb_agent_raw:
                    actual_result = "No version found"
                    remarks = "FAIL"
                else:
                    actual_result = cb_agent_raw.split('-')[1].strip()
                    remarks = "FAIL"

                linux_os_checks.append({
                    "Check-Name": "Carbon Black Client Version Check",
                    "Expected Result": f">={carbon_black_version}",
                    "Actual Result": actual_result,
                    "Remarks": remarks
                })
            else:
                linux_os_checks.append({
                    "Check-Name": "Carbon Black Client Version Check",
                    "Expected Result": f">={carbon_black_version}",
                    "Actual Result": "Carbon Black Client is not installed",
                    "Remarks": "FAIL"
                })

            # Carbon Black running Status

            cb_running_status = commandoutput.get("Carbon Black Status", "NA").strip()            
            remarks = "PASS" if 'running' in cb_running_status.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "Carbon Black Client Running Status",
                "Expected Result": 'running',
                "Actual Result": 'running' if remarks == "PASS" else 'not running',
                "Remarks": remarks
            })

            # Amazon Cloudwatch Agent Version

            cw_agent_raw = commandoutput.get("Amazon cloudwatch agent version", "").strip()                       
            if 'failed' not in cw_agent_raw.lower():
                actual_cw_agent_raw = tuple(map(int,cw_agent_raw.replace('amazon-cloudwatch-agent-','')[:3].split('.'))) if cw_agent_raw else ()                
                if actual_cw_agent_raw and actual_cw_agent_raw >= required_cloudwatch_agent_version_raw:
                    actual_result = cb_agent_raw.replace('amazon-cloudwatch-agent-','')[:3]
                    remarks = "PASS"
                
                elif not actual_cw_agent_raw:
                    actual_result = "No version found"
                    remarks = "FAIL"
                else:
                    actual_result = cw_agent_raw.replace('amazon-cloudwatch-agent-','')[:3]
                    remarks = "FAIL"

                linux_os_checks.append({
                    "Check-Name": "Amazon Cloudwatch Agent Version Check",
                    "Expected Result": f">={cloudwatch_agent_version}",
                    "Actual Result": actual_result,
                    "Remarks": remarks
                })
            else:
                linux_os_checks.append({
                    "Check-Name": "Amazon Cloudwatch Agent Version Check",
                    "Expected Result": f">={cloudwatch_agent_version}",
                    "Actual Result": "Amazon Cloudwatch Agent is not installed",
                    "Remarks": "FAIL"
                })

            # Amazon Cloudwatch Agent running Status

            cw_running_status = commandoutput.get("Amazon cloudwatch Agent Status", "NA").strip()            
            remarks = "PASS" if 'running' in cw_running_status.lower() else 'FAIL'
            linux_os_checks.append({
                "Check-Name": "Amazon cloudwatch Agent Status Running Status",
                "Expected Result": 'running',
                "Actual Result": 'running' if remarks == "PASS" else 'not running',
                "Remarks": remarks
            })

            
            received_event[0]['OS Level Checks'] = linux_os_checks
            received_event[0]["Post ORC Tasks"] = linux_final_configuration_post_orc(sns_client,kms_client,account_name,ssm_client, instance_id, patch_tag)

            return received_event

        except ClientError as ce:
                logger.error(f"ClientError: {ce}")
                input_event.update({
                    'error': str(ce),
                    'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
                    'overall_status': "errored",
                    'orc_request_type': "errored"
                })
                return {"info": input_event}

    except Exception as e:
            logger.exception("Unexpected error occurred")
            input_event.update({
                'error': f"Unexpected error: {str(e)}",
                'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            return {"info": input_event}

    except ClientError as ce:
        logger.error(f"ClientError: {ce}")
        input_event.update({
            'error': str(ce),
            'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return {"info": input_event}

    except Exception as e:
        logger.exception("Unexpected error occurred")
        input_event.update({
            'error': f"Unexpected error: {str(e)}",
            'orc_check_stage': "errored_at_ec2_orc_os_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return {"info": input_event}