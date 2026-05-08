import boto3
import os
from botocore.exceptions import ClientError
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variable
cross_account_role_name = os.environ['CROSS_ACCOUNT_ORC_ROLE']


## backup plans


def check_backup_plan_exists(backup_client,aws_region,plan_name):
    try:
        paginator = backup_client.get_paginator('list_backup_plans')
        for page in paginator.paginate():
            for plan in page.get('BackupPlansList', []):
                logger.info(plan.get('BackupPlanName'))
                if plan.get('BackupPlanName') == plan_name:
                    return plan_name
        return "Plan Not Found"
    except ClientError as e:
        print(f"[ERROR] Failed to retrieve backup plans in {aws_region}: {e}")
        return "error while describing backup plans"



    

def maintenance_window_validation_check(ssm_client,patch_tag,region):

    if patch_tag.startswith("RITM") or patch_tag.startswith("IRM"):
        return "extempted","maintenance window check not required as it doesn't have a patching tag"
    
    elif patch_tag == "NA":
        return False, "Patching tag unavailable or incorrectly configured"
    
    elif patch_tag not in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        return False, f"Patching Tag:- {patch_tag} is incorrect"

    response = ssm_client.describe_maintenance_windows(MaxResults=50)
    all_windows = response.get('WindowIdentities', [])
    
    active_windows = [mw for mw in all_windows if mw.get("Enabled")]
    
    if not active_windows:
        return False, f"no active maintenance window present in region {region}"
    

    for window in active_windows:
        remarks = f"No maintenance window found for the provided patching tag {patch_tag}"
        targets_response = ssm_client.describe_maintenance_window_targets(WindowId=window['WindowId'])
        for mw_target in targets_response['Targets']:
            window_id = mw_target['WindowId']
            if mw_target['Targets']:
                for trgt in mw_target['Targets']:
                    if trgt['Key'].strip() == "tag:ops-exclude-patch" and trgt['Values'][0] == patch_tag:
                        print(f"found correct tag key {patch_tag} inside one of the targets of {window_id}")
                        return True,f"available:- {window_id}"
                    else:
                        print(f"{window_id}:- required patching tag {patch_tag} is not matching with available target's tags")
    return False,remarks



def ec2_aws_level_orc_checks(received_event):
    input_event = received_event["info"]
    region = input_event['region']
    account_id = input_event['account_id']
    instance_id = input_event['resource_id']
    account_name = input_event['account_name']
    environment = "NA" if account_name == "NA" else account_name.split("-")[-1].lower()
    
    patch_tag = "NA"
    for item in received_event['EC2 Tag Validation']:
        if item["Tag Name"] == "ops-exclude-patch":
            patch_tag = item["Actual Result"]
            input_event["patch_tag"] = patch_tag
            break
    
    cross_account_role = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"
    
    ec2_aws_checks = []
    
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
            backup_plans = {
                "us-east-1": f"{environment}-nam-backup_plan",
                "us-west-2": f"{environment}-nam2-backup_plan",
                "ap-northeast-1": f"{environment}-apa-backup_plan",
                "ap-southeast-1": f"{environment}-apa2-backup_plan",
                "eu-central-1": f"{environment}-eur-backup_plan",
                "eu-west-1": f"{environment}-eur2-backup_plan"
            }
            prod_backup_plans = {
                "us-east-1": ["tec-prd-nam-tier1-2-backup_plan", "tec-prd-nam-tier3-4-backup_plan"],
                "us-west-2": ["tec-prd-nam2-tier1-2-backup_plan", "tec-prd-nam2-tier3-4-backup_plan"],
                "eu-central-1": ["tec-prd-eur-tier1-2-backup_plan","tec-prd-eur-tier3-4-backup_plan"],
                "eu-west-1": ["tec-prd-eur2-tier1-2-backup_plan", "tec-prd-eur2-tier3-4-backup_plan"],
                "ap-northeast-1": ["tec-prd-apa-tier1-2-backup_plan", "tec-prd-apa-tier3-4-backup_plan"],
                "ap-southeast-1": ["tec-prd-apa2-tier1-2-backup_plan","tec-prd-apa2-tier3-4-backup_plan"]
            }
            missing_plans = []
            backup_client = session.client('backup', region_name=region)
            if environment == "NA":
                ec2_aws_checks.append({
                    "Check-Name": f"Backup Plan Exists for region {region}",
                    "Expected Result": "Cannot determine as account name wasn't retrieved successfully",
                    "Actual Result": "Cannot determine as account name wasn't retrieved successfully",
                    "Remarks": "FAIL"
                })
            elif environment == "prd":
                for plan_name in prod_backup_plans[region]:
                    backup_plan_exists = check_backup_plan_exists(backup_client, region, plan_name)
                    if  backup_plan_exists != plan_name:
                        missing_plans.append(plan_name)
                ec2_aws_checks.append({
                    "Check-Name": f"Prod Backup Plans Validation",
                    "Expected Result": ','.join(prod_backup_plans[region]),
                    "Actual Result": (
                        "Backup Plans Exist" if not missing_plans else f"Plan Missing: {','.join(missing_plans)}"
                    ),
                    "Remarks": "PASS" if not missing_plans else "FAIL"
                })
            else:
                backup_plan_exists = check_backup_plan_exists(backup_client, region, backup_plans[region])
                ec2_aws_checks.append({
                    "Check-Name": f"{environment.title()} Backup Plan Validation",
                    "Expected Result": backup_plans[region],
                    "Actual Result": backup_plan_exists if backup_plan_exists else "Not Found",
                    "Remarks": "PASS" if backup_plan_exists else "FAIL"
                })
                

            ec2 = session.client('ec2')
            ssm_client = session.client('ssm')

            res = ec2.describe_instances(InstanceIds=[instance_id])
            res_instance_status = ec2.describe_instance_status(InstanceIds=[instance_id])

            instance_status = []

            for item in res_instance_status['InstanceStatuses']:
                if item.get('InstanceStatus') and item['InstanceStatus'].get('Status','') != 'ok':
                    instance_status.append('fail')
                else:
                    instance_status.append('pass')        
                if item.get('SystemStatus') and item['SystemStatus'].get('Status','') != 'ok':
                    instance_status.append('fail')
                else:
                    instance_status.append('pass')
            
            instance = res['Reservations'][0]['Instances'][0]
            instance_state = instance.get("State", {}).get("Name", "unknown")
            
            ec2_aws_checks.append({
                "Check-Name": "EC2 instance state check",
                "Expected Result": "running",
                "Actual Result": instance_state,
                "Remarks": "PASS" if instance_state == "running" else "FAIL"
            })
            
            public_ip = instance.get("PublicIpAddress", None)
            ec2_aws_checks.append({
                "Check-Name": "EC2 Public IP availability check",
                "Expected Result": "No public IP",
                "Actual Result": public_ip if public_ip else "No public IP",
                "Remarks": "PASS" if not public_ip else "FAIL"
            })
            
            ec2_term = ec2.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute='disableApiTermination'
                )
            
            termination_protection = ec2_term.get('DisableApiTermination', {}).get('Value', False)

            ec2_aws_checks.append({
                "Check-Name": "EC2 Termination Protection",
                "Expected Result": "Enabled",
                "Actual Result": "Enabled" if termination_protection else "Disabled",
                "Remarks": "PASS" if termination_protection else "FAIL"
            })
            
            ## widen open security group check
            
            sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            wide_open_found = False
            if sg_ids:
                security_groups = ec2.describe_security_groups(GroupIds=sg_ids)['SecurityGroups']
                for sg in security_groups:
                    for permission in sg.get('IpPermissions', []):
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == "0.0.0.0/0":
                                wide_open_found = True
                                break
                        if wide_open_found:
                            break
                    if wide_open_found:
                        break

            ec2_aws_checks.append({
                "Check-Name": "Wide Open Security Group Inbound Rule",
                "Expected Result": "No inbound access from 0.0.0.0/0",
                "Actual Result": "Inbound access open to 0.0.0.0/0" if wide_open_found else "No wide-open access",
                "Remarks": "FAIL" if wide_open_found else "PASS"
            })
            
            delete_on_termination_issues = []

            for bd in instance.get("BlockDeviceMappings", []):
                ebs = bd.get("Ebs")
                if ebs:
                    vol_id = ebs.get("VolumeId")
                    delete_on_termination = ebs.get("DeleteOnTermination", False)
                    if not delete_on_termination:
                        delete_on_termination_issues.append(f"{vol_id}: off")
            
            ebs_act_result = ", ".join(delete_on_termination_issues) if delete_on_termination_issues else "All volumes have DeleteOnTermination enabled"
            
            ec2_aws_checks.append({
                "Check-Name": "EBS Delete on Termination",
                "Expected Result": "All volumes should have DeleteOnTermination enabled",
                "Actual Result": ebs_act_result,
                "Remarks": "FAIL" if delete_on_termination_issues else "PASS"
            })
            
            volume_ids = [bd['Ebs']['VolumeId'] for bd in instance.get("BlockDeviceMappings", []) if 'Ebs' in bd]
            unencrypted_volumes = []

            if volume_ids:
                volumes = ec2.describe_volumes(VolumeIds=volume_ids)['Volumes']
                for vol in volumes:
                    if not vol.get('Encrypted', False):
                        unencrypted_volumes.append(vol['VolumeId'])
            encrypt_actual = ", ".join(unencrypted_volumes) + ": not encrypted" if unencrypted_volumes else "All volumes encrypted"
            
            ec2_aws_checks.append({
                "Check-Name": "EBS Encryption Check",
                "Expected Result": "All volumes should be encrypted",
                "Actual Result": encrypt_actual,
                "Remarks": "FAIL" if unencrypted_volumes else "PASS"
            })
            
            gp2_volumes = []

            if volume_ids:
                volumes = ec2.describe_volumes(VolumeIds=volume_ids)['Volumes']
                for vol in volumes:
                    if vol.get('VolumeType') == 'gp2':
                        gp2_volumes.append(vol['VolumeId'])

            ec2_aws_checks.append({
                "Check-Name": "EBS Volume Type Check",
                "Expected Result": "All volumes should be gp3 or better",
                "Actual Result": ", ".join(gp2_volumes) + ": gp2" if gp2_volumes else "All volumes compliant",
                "Remarks": "FAIL" if gp2_volumes else "PASS"
            })
            
            maintenance_win_result = maintenance_window_validation_check(ssm_client,patch_tag,region)
            
            if maintenance_win_result[0] == "extempted":
                patch_result_check = f"Doesn't Contain standard patching tag , received {patch_tag}"
                patch_tag_actual = "NA"
            else:
                patch_result_check = maintenance_win_result[1]
                patch_tag_actual = f"Available for {patch_tag}"
            
            ec2_aws_checks.append({
                "Check-Name": "Patching Maintenance Window",
                "Expected Result": patch_tag_actual,
                "Actual Result": patch_result_check,
                "Remarks": "PASS" if maintenance_win_result[0] == True or maintenance_win_result[0] == "extempted" else "FAIL"
            })           
            
            for vol in volume_ids:
                res_vol = ec2.describe_volume_status(VolumeIds=[vol])
                for item in res_vol['VolumeStatuses']:                    
                    if item.get('VolumeStatus') and item['VolumeStatus'].get('Status','') != 'ok':
                        instance_status.append('fail')
                    else:
                        instance_status.append('pass')
            
            ec2_aws_checks.append({
                "Check-Name": "ec2 instance status check",
                "Expected Result": '3/3 checks passed',
                "Actual Result": '3/3 checks passed' if 'fail' not in instance_status else '3/3 checks not passed',
                "Remarks": "PASS" if 'fail' not in instance_status else "FAIL"
            }) 

            received_event['EC2 AWS Level Checks'] = ec2_aws_checks
            return received_event

        
        
        except ClientError as ce:
            logger.error(f"Handled exception during EC2 check: {ce}")
            input_event.update({
                'error': str(ce),
                'orc_check_stage': "errored_at_orc_aws_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            received_event["info"] = input_event
            return received_event

        except Exception as e:
            logger.exception("Unexpected error during EC2 metadata extraction")
            input_event.update({
                'error': f"Unexpected error: {str(e)}",
                'orc_check_stage': "errored_at_orc_aws_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            received_event["info"] = input_event
            return received_event

    except ClientError as ce:
        logger.error(f"STS Role assumption failed: {ce}")
        input_event.update({
            'error': str(ce),
            'orc_check_stage': "errored_at_orc_aws_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return {"info": input_event}

    except Exception as e:
        logger.exception("Unexpected error during role assumption or session setup")
        input_event.update({
            'error': f"Unexpected error: {str(e)}",
            'orc_check_stage': "errored_at_orc_aws_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return {"info": input_event}



def ec2_information_level_checks(received_event):
    input_event = received_event["info"]
    region = input_event['region']
    account_id = input_event['account_id']
    instance_id = input_event['resource_id']

    cross_account_role = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"

    information_checks = []

    try:
        # Assume role
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
            ec2 = session.client('ec2')
            ssm_client = session.client('ssm')

            res = ec2.describe_instances(InstanceIds=[instance_id])
            instance = res['Reservations'][0]['Instances'][0]

            instance_type = instance.get('InstanceType')
            ami_id = instance.get('ImageId')
            launch_time = str(instance.get('LaunchTime'))
            key_name = instance.get('KeyName', 'NA')
            iam_instance_profile = instance.get('IamInstanceProfile', {}).get('Arn', '').split('/')[-1] if instance.get('IamInstanceProfile') else 'None'
            monitoring_state = instance.get('Monitoring', {}).get('State', 'disabled')
            root_device_type = instance.get('RootDeviceType', 'unknown')
            architecture = instance.get('Architecture', 'unknown')
            hypervisor = instance.get('Hypervisor', 'unknown')
            virtualization_type = instance.get('VirtualizationType', 'unknown')
            private_ip = instance.get('PrivateIpAddress')
            vpc_id = instance.get('VpcId')
            subnet_id = instance.get('SubnetId')
            availability_zone = instance.get('Placement', {}).get('AvailabilityZone')
            platform = instance.get('Platform', 'Linux/UNIX')
            input_event["operating_system"] = platform
            block_devices = instance.get('BlockDeviceMappings', [])
            eni_count = len(instance.get('NetworkInterfaces', []))

            # Golden AMI Check
            
            golen_ami_check = golden_ami_verification(ssm_client, ami_id)
            
            # Subnet Name
            subnet_name = "NA"
            try:
                subnet = ec2.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                for tag in subnet.get('Tags', []):
                    if tag['Key'].lower() == 'name':
                        subnet_name = tag['Value']
                        break
            except Exception as e:
                logger.warning(f"Could not fetch subnet name: {e}")

            # Auto Scaling Group Name
            asg_name = "NA"
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'aws:autoscaling:groupName':
                    asg_name = tag['Value']
                    break

            # Scheduler Tag            
            scheduler_tag_value = "NA"
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'ops-uptime-schedule':
                    scheduler_tag_value = tag['Value']
                    break

            # Volume Details
            volume_details = []
            volume_ids = [bd['Ebs']['VolumeId'] for bd in block_devices if 'Ebs' in bd]
            if volume_ids:
                volumes = ec2.describe_volumes(VolumeIds=volume_ids)['Volumes']
                kms_client = session.client('kms')

                for vol in volumes:
                    vol_id = vol['VolumeId']
                    size = vol.get('Size')
                    vol_type = vol.get('VolumeType')
                    encrypted = vol.get('Encrypted', False)
                    kms_key_id = vol.get('KmsKeyId', "None")
                    alias_name = "None"
                    key_name = "Not Available"
                    device_name = "Unknown"

                    
                    for bd in block_devices:
                        if bd.get('Ebs', {}).get('VolumeId') == vol_id:
                            device_name = bd.get('DeviceName', "Unknown")
                            break

                    if kms_key_id and kms_key_id != "None":
                        try:
                            key_id = kms_key_id.split('/')[-1]
                            
                            paginator = kms_client.get_paginator('list_aliases')
                            for page in paginator.paginate():
                                for alias in page['Aliases']:
                                    if alias.get('TargetKeyId') == key_id:
                                        alias_name = alias.get('AliasName', 'None')
                                        if alias_name.startswith("alias/"):
                                            key_name = alias_name.split("/")[-1]
                                        break
                                        
                                if alias_name != "None":
                                    break
                        except Exception as e:
                            logger.warning(f"Could not fetch alias for KMS key {kms_key_id}: {e}")

                    volume_details.append({
                        vol_id: {
                            'Device Name': device_name,
                            'Size (GiB)': size,
                            'Volume Type': vol_type,
                            'Encrypted': encrypted,
                            'KMS Key Name': key_name
                        }
                    })

            information_checks = [{
                'Instance Type': instance_type,
                'Server Launch Time(UTC)': launch_time,
                'AMI ID': ami_id,
                "Golden AMI": golen_ami_check,
                'Operating System': platform,
                'OS Architecture': architecture,
                'Hypervisor': hypervisor,
                'Virtualization': virtualization_type,
                'IAM Role': iam_instance_profile,
                'Detailed Monitoring': monitoring_state,
                'Private IP': private_ip,
                'VPC ID': vpc_id,
                'Subnet ID': subnet_id,
                'Subnet Name': subnet_name,
                'Number of ENIs': eni_count,
                'Availability Zone': availability_zone,
                'Auto Scaling Group': asg_name,
                'Scheduler Tag': scheduler_tag_value,
                'Root Volume Type': root_device_type,
                'Volumes Attached': volume_details
            }]

            received_event["EC2 Associated Informations"] = information_checks
            return received_event

        except ClientError as ce:
            logger.error(f"Handled exception during EC2 check: {ce}")
            input_event.update({
                'error': str(ce),
                'orc_check_stage': "errored_at_orc_aws_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            received_event["info"] = input_event
            return received_event

        except Exception as e:
            logger.exception("Unexpected error during EC2 metadata extraction")
            input_event.update({
                'error': f"Unexpected error: {str(e)}",
                'orc_check_stage': "errored_at_orc_aws_level_checks",
                'overall_status': "errored",
                'orc_request_type': "errored"
            })
            received_event["info"] = input_event
            return received_event

    except ClientError as ce:
        logger.error(f"STS Role assumption failed: {ce}")
        input_event.update({
            'error': str(ce),
            'orc_check_stage': "errored_at_orc_aws_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return {"info": input_event}

    except Exception as e:
        logger.exception("Unexpected error during role assumption or session setup")
        input_event.update({
            'error': f"Unexpected error: {str(e)}",
            'orc_check_stage': "errored_at_orc_aws_level_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        return {"info": input_event}


def golden_ami_verification(ssm_client, ami_id):
    paths = [
        "/tec/golden-ami/",
        "/org/WINDOWS2022/ami-id",
        "/org/AMAZON2023/ami-id"
    ]

    try:
        for path in paths:
            paginator = ssm_client.get_paginator('get_parameters_by_path')
            page_iterator = paginator.paginate(
                Path=path,
                Recursive=True,
                WithDecryption=True
            )

            for page in page_iterator:
                for param in page.get("Parameters", []):
                    param_name = param['Name']
                    history_paginator = ssm_client.get_paginator('get_parameter_history')
                    history_iterator = history_paginator.paginate(
                        Name=param_name,
                        WithDecryption=True
                    )

                    for history_page in history_iterator:
                        for version in history_page.get("Parameters", []):
                            if ami_id.strip() == version.get("Value", "").strip():
                                logger.info(
                                    f"Golden AMI {ami_id} found in parameter: {param_name}, "
                                    f"version: {version.get('Version', '')}, path: {path}"
                                )
                                return "Yes"

        return "No"

    except Exception as e:
        logger.error(f"Error checking golden AMI history: {e}")
        return "No"