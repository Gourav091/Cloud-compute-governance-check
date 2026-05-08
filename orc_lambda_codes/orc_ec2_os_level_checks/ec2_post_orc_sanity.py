import concurrent.futures
import logging
import time
from sns_creation import sns_topic_create_subscribe

logger = logging.getLogger()
logger.setLevel(logging.INFO)



post_orc_commands = {
    "os_hardening": (
        "$task = Get-ScheduledTask -TaskName 'oshardening' -ErrorAction SilentlyContinue;"
        "if ($task -and $task.State -ne 'Disabled') { Disable-ScheduledTask -TaskName 'oshardening' | Out-Null; 'disabled' } else { 'not required' }"
    ),
    "user_access_log": (
        "auditpol /set /subcategory:'Logon' /success:enable /failure:enable | Out-Null;"
        "auditpol /set /subcategory:'Logoff' /success:enable /failure:disable | Out-Null;"
        "auditpol /set /subcategory:'Account Lockout' /success:disable /failure:enable | Out-Null;"
        "'Configured successfully'"
    ),
    "windows_auto_update_enable":  (
        "$path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU';"
        "if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null };"
        "$val = (Get-ItemProperty -Path $path -Name AUOptions -ErrorAction SilentlyContinue).AUOptions;"
        "if ($null -eq $val) { Set-ItemProperty -Path $path -Name AUOptions -Value 3 | Out-Null;"
        "'Auto Update Configured to Option 3' } else { \"Already configured (AUOptions = $val)\" }"
    )
}

post_orc_tasks = []

def send_ssm_commands(title, cmd, ssm_client, instance_id):
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


def windows_final_configuration_post_orc(sns_client, kms_client , account_name , ssm_client, instance_id, patching_tag, domain_name):
    commandoutput = {}
    
    ## The Primary Domain Suffix Priority
    
    if domain_name != "NA":
        reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
        domain_suffix_command = (
        f"$regPath = '{reg_path}'; "
        f"$domain = '{domain_name}'; "
        "$existing = (Get-ItemProperty -Path $regPath -Name SearchList -ErrorAction SilentlyContinue).SearchList; "
        "$list = @(); "
        "if ($existing) { "
        "$list = $existing -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne $domain } }; "
        "$final = @($domain) + $list; "
        "Set-ItemProperty -Path $regPath -Name SearchList -Value ($final -join ',') | Out-Null; "
        f"Write-Output 'SearchList updated,configured for domain tag: {domain_name}'"
        )
        post_orc_commands["domain_suffix_update"] = domain_suffix_command

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(send_ssm_commands, title, cmd, ssm_client, instance_id): title
            for title, cmd in post_orc_commands.items()
        }
        for future in concurrent.futures.as_completed(futures):
            title, output = future.result()
            commandoutput[title] = output.strip()
    
    ## disable os-hardening
    
    post_orc_tasks.append({
        "Task Name": "Disable OS Hardening Script",
        "Remarks": commandoutput.get("os_hardening", "NA")
    })
    
    ## user access logging
    
    post_orc_tasks.append({
        "Task Name": "Configure User Access Logging Policy",
        "Remarks": commandoutput.get("user_access_log", "NA")
    })
    
    ## Windows Auto Update
    
    post_orc_tasks.append({
        "Task Name": "Enable Windows Auto Update",
        "Remarks": commandoutput.get("windows_auto_update_enable", "NA")
    })
    
    ## Primary Domain Suffix Priority
    
    post_orc_tasks.append({
        "Task Name": "Primary Domain Suffix Priority in DNS Search List",
        "Remarks":  commandoutput.get("domain_suffix_update", "Cannot Determine since domain tag is incorrectly configured")
    })
    
    ## creation of sns topic 
    
    sns_topic_creation,sns_arn = sns_topic_create_subscribe(sns_client,kms_client,account_name,"windows")
    
    post_orc_tasks.append({
        "Task Name": "SNS Topic Creation",
        "Remarks":  sns_topic_creation
    })
    
    post_orc_tasks.append({
        "Task Name": "SNS Topic Details",
        "Remarks":  sns_arn
    })
    
    ## install patches

    if patching_tag in ["S1","S2","S3","S4","S5","S6"]:
        try:
            patch_compliance_status = get_patch_compliance(ssm_client,instance_id)
            if not patch_compliance_status:
                response = ssm_client.send_command(
                    DocumentName="AWS-RunPatchBaseline",
                    DocumentVersion="1",
                    Targets=[{"Key": "InstanceIds", "Values": [instance_id]}],
                    Parameters={
                        "Operation": ["Install"],
                        "RebootOption": ["RebootIfNeeded"],
                        "StepTimeoutSeconds": ["10800"]
                    },
                    TimeoutSeconds=600,
                    MaxConcurrency="50",
                    MaxErrors="0"
                )
                command_id = response['Command']['CommandId']
                post_orc_tasks.append({
                    "Task Name": "Patch Installation",
                    "Remarks": f"Triggered successfully command_id: {command_id}"
                })
            else:
                post_orc_tasks.append({
                    "Task Name": "Patch Installation",
                    "Remarks": f"Not Required as the Server is Compliant"
                })
        except Exception as e:
            post_orc_tasks.append({
                "Task Name": "Patch Installation Trigger",
                "Remarks": f"Failed to trigger: {str(e)}"
            })
    else:
        post_orc_tasks.append({
            "Task Name": "Patch Installation",
            "Remarks": f"Skipping Patch as it doesn't have valid patching tag"
        })    

    return post_orc_tasks


def get_patch_compliance(ssm_client,instance_id):
    try:
        response = ssm_client.describe_instance_patch_states(
            InstanceIds=[instance_id]
        )
        if len(response['InstancePatchStates']) != 0:
            for state in response['InstancePatchStates']:
                instance_id = state['InstanceId']
                critical_non_compliant = state.get('CriticalNonCompliantCount',"NA")
                security_non_compliant = state.get('SecurityNonCompliantCount',"NA")
                other_non_compliant = state.get('OtherNonCompliantCount',"NA")
                missing_patches = state['MissingCount']
                total_non_compliant = critical_non_compliant + security_non_compliant + other_non_compliant + missing_patches
                if total_non_compliant > 0:
                    return False
                else:
                    return True

    except Exception as e:
        logger.info(f"Error getting patch compliance status: {str(e)}")
        return False