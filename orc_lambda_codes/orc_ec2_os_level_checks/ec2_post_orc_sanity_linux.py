import concurrent.futures
import logging
import time
import json
from sns_creation import sns_topic_create_subscribe

logger = logging.getLogger()
logger.setLevel(logging.INFO)


splunk_dep_cmd = '''
cat <<EOF | sudo tee /opt/splunkforwarder/etc/system/local/deploymentclient.conf
[target-broker:deploymentServer]
targetUri = splunk-ds.onetakeda.com:8089
EOF
'''

post_orc_commands = {
    'Instance Store Status':'curl http://169.254.169.254/latest/meta-data/block-device-mapping/ephemeral0 | grep "Not Found"',
    'SELinux Status':'sestatus | grep "SELinux status:"',
    'Sysstat Status':'rpm -qa | grep sysstat',
    'Billing Code':'curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep billingProducts',
    'block device':'lsblk -J',
    'OS Version':'cat /etc/os-release | grep PRETTY_NAME=',
    # 'Splunk deployment configuration' : 'echo -e "[target-broker:deploymentServer]\ntargetUri = splunk-ds.onetakeda.com:8089" >> /opt/splunkforwarder/etc/system/local/deploymentclient.conf',    
    'Splunk deployment configuration' : splunk_dep_cmd,    
    'Splunk deployment config check':'sudo cat /opt/splunkforwarder/etc/system/local/deploymentclient.conf'    
}

post_orc_tasks = []

def send_ssm_commands(title, cmd, ssm_client, instance_id):
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


def linux_final_configuration_post_orc(sns_client,kms_client,account_name,ssm_client, instance_id, patching_tag):
    commandoutput = {}        

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(send_ssm_commands, title, cmd, ssm_client, instance_id): title
            for title, cmd in post_orc_commands.items()
        }
        for future in concurrent.futures.as_completed(futures):
            title, output = future.result()
            commandoutput[title] = output.strip()
    
    ## OS Version

    if commandoutput.get("OS Version"):
        remarks = commandoutput.get("OS Version").replace('"', '').replace('PRETTY_NAME=', '')        

    post_orc_tasks.append({
        "Task Name": "OS Version information",
        "Remarks": remarks
    })
    ## Check Instance Store presence
    
    if commandoutput.get("Instance Store Status"):
        if 'Not Found' in commandoutput.get("Instance Store Status"):
            remarks = 'No Instance Store has been attached'
        else:
            remarks = 'Instance Store attachment has been present'
    else:
        remarks = 'Unable to verify Instance Store presence'

    post_orc_tasks.append({
        "Task Name": "Instance Store Presence Status",
        "Remarks": remarks
    })

    ## SELinux Status
    
    if commandoutput.get("SELinux Status"):
        if 'enabled' in commandoutput.get("SELinux Status"):
            remarks = 'Enabled'
        if 'disabled' in commandoutput.get("SELinux Status"):
            remarks = 'Disabled'
    else:
        remarks = 'Unable to verify SELinux status'
    
    post_orc_tasks.append({
        "Task Name": "SELinux Status",
        "Remarks": remarks
    })
    
    ## Sysstat Status
    
    if commandoutput.get("Sysstat Status"):        
        remarks = f"Installed Package Version found as {commandoutput.get("Sysstat Status").split('-')[1]}"
    else:
        remarks = 'Sysstat package is not installed'
    
    post_orc_tasks.append({
        "Task Name": "Sysstat Package Presence Status",
        "Remarks": remarks
    })

    ## Billing Code
    
    if commandoutput.get("Billing Code"):        
        remarks = commandoutput.get("Billing Code").replace('"billingProducts" : ','').replace(',','')
    else:
        remarks = 'Billing Code is not available'
    
    post_orc_tasks.append({
        "Task Name": "Billing Code",
        "Remarks": remarks
    })

    ## Block Device

    bd_mapping = []
    if commandoutput.get("block device"):
        block_device_data = json.loads(commandoutput.get("block device"))        
        if block_device_data.get('blockdevices'):
            for bd in block_device_data['blockdevices']:
                bd_mapping.append(f"{bd['name']}:{bd['size']}")
            block_device_data = '-'.join(bd_mapping)
            remarks = block_device_data
        else:
            remarks = 'No block device has been found'
    else:
        remarks = 'No block device has been found'

    post_orc_tasks.append({
        "Task Name": "Block Device information (name:size)",
        "Remarks": remarks
    })
    
    ## creation of sns topic 
    
    sns_topic_creation,sns_arn = sns_topic_create_subscribe(sns_client,kms_client,account_name,"linux")
    
    post_orc_tasks.append({
        "Task Name": "SNS Topic Creation",
        "Remarks":  sns_topic_creation
    })
    
    post_orc_tasks.append({
        "Task Name": "SNS Topic Details",
        "Remarks":  sns_arn
    })
    
    ## Splunk deployment config check

    if commandoutput.get("Splunk deployment config check","NA") != 'NA':
        if '8089' in commandoutput['Splunk deployment config check']:
            remarks = f'splunk deployment configuration has been updated with desired port number 8089'
        else:
            remarks = 'splunk deployment configuration has not been updated as per the requirement. Please update as per the standard'
    else:
        remarks = 'Unable to verify Splunk deployment configuration'
    
    post_orc_tasks.append({
        "Task Name": "Splunk deployment configuration",
        "Remarks": remarks
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