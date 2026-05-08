import boto3
import logging
import os
import re
from botocore.exceptions import ClientError
from get_leanix_data import get_leanix_data

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variable
cross_account_role_name = os.environ['CROSS_ACCOUNT_ORC_ROLE']

def final_naming_convention_check(received_event):
    input_event = received_event["info"]
    region = input_event['region']
    account_id = input_event['account_id']
    instance_id = input_event['resource_id']
    resource_type = input_event['resource_type']

    cross_account_role = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"
    
    ec2_list = []
    ebs_list = []

    if resource_type == "ec2":
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

            ec2 = session.client('ec2')
            res = ec2.describe_instances(InstanceIds=[instance_id])
            instance = res['Reservations'][0]['Instances'][0]

            tags = instance.get('Tags', [])
            tag_map = {tag['Key']: tag['Value'] for tag in tags}
            instance_name = tag_map.get("Name", "No Instance Name")
            apms_id = tag_map.get("apms-id", "no apms")

            if instance_name == "No Instance Name":
                ec2_list.append({
                    "Instance Name": "NA",
                    "Name Check": "FAIL",
                    "Comments": "No Instance Name Found"
                })
            elif apms_id == "no apms":
                ec2_list.append({
                    "Instance Name": instance_name,
                    "Name Check": "FAIL",
                    "Comments": "apms-id tag key is missing"
                })
            else:
                result, comment = ec2_name_validation(instance_name, apms_id, region, account_id)
                ec2_list.append({
                    "Instance Name": instance_name,
                    "Name Check": result,
                    "Comments": comment
                })

            block_device_details = instance.get('BlockDeviceMappings', [])
            volume_ids = [bd['Ebs']['VolumeId'] for bd in block_device_details if 'Ebs' in bd]

            volumes_info = ec2.describe_volumes(VolumeIds=volume_ids)


            for vol in volumes_info['Volumes']:
                vol_id = vol['VolumeId']
                tags = {tag['Key']: tag['Value'] for tag in vol.get("Tags", [])}
                vol_name = tags.get("Name")
                apms_id = tags.get("apms-id")

                if not vol_name:
                    ebs_list.append({
                        vol_id : {
                        "Name Check": "FAIL",
                        "Comment": "No Name tag found on volume"
                        }
                    })
                elif not apms_id:
                    ebs_list.append({
                        vol_id : {
                        "Name Check": "FAIL",
                        "Comment": "No apms-id found on volume"
                        }
                    })
                else:
                    result, comment = ebs_name_validation(vol_name, apms_id, region)
                    ebs_list.append({
                        vol_id : {
                        "Name Check": result,
                        "Comment": comment
                        }
                    })
            received_event["EC2 Naming Convention Check"] = ec2_list
            received_event["EBS Naming Convention Check"] = ebs_list
            return received_event

        except ClientError as ce:
            logger.error(f"Handled exception during EC2 check: {ce}")
            input_event['error'] = str(ce)
            input_event['orc_check_stage'] = "errored_at_orc_common_checks"
            input_event['overall_status'] = "errored"
            input_event['orc_request_type'] = "errored"
            return {"info": input_event}

        except Exception as e:
            logger.exception("Unexpected error during final_naming_convention_check")
            input_event['error'] = f"Unexpected error: {str(e)}"
            input_event['orc_check_stage'] = "errored_at_orc_common_checks"
            input_event['overall_status'] = "errored"
            input_event['orc_request_type'] = "errored"
            return {"info": input_event}


region_country_map = {
    'us-east-1': 'USVGA',
    'us-west-2': 'USORE',
    'ap-northeast-1': 'JPTYO',
    'ap-southeast-1': 'SGSIN',
    'eu-central-1': 'DEFRA',
    'eu-west-1': 'IEDUB'
}



def ec2_name_validation(name, apms_id, region, account_id):
    leanix_source = get_leanix_data(account_id,apms_id)
    name_result = []
    os = ['W', 'X']
    environment_from_leanix = leanix_source.get('env_id_char_only')
    supported_environment_digits = ["D", "T", "P"]

    apms_id_digit = re.sub(r"\D", "", apms_id)

    if len(name) < 10:
        return "FAIL", "Incorrect EC2 Instance Name Length"

    if apms_id_digit not in name:
        name_result.append("APMS ID not found in the instance name")

    if len(name) > 15:
        name_result.append("Instance name should be 15 characters or fewer")

    if name[0] not in os:
        name_result.append("OS value must be 'X' or 'W'")
        
    
    if region_country_map[region] != name[1:6]:
        name_result.append(f"Country code must be {region_country_map[region]} for your provide region {region}")

    if not name[-3:].isdigit():
        name_result.append("Last 3 characters must be digits")

    if name[-4] in supported_environment_digits:
        if name[-4] != environment_from_leanix:
            name_result.append(f"received environment digit:- {name[-4]} but actual environmet digit:- {environment_from_leanix})")
    else:
        name_result.append(f"Environment ID Character must be one of: {', '.join(supported_environment_digits)}")

    if name_result:
        return "FAIL", ", ".join(name_result)
    else:
        return "PASS", "NA"


def ebs_name_validation(name, apms_id, region):
    name_result = []
    os_list = ['W', 'X']
    apms_id_digit = re.sub(r"\D", "", apms_id)
    supported_environment_digits = ["D", "T", "P"]

    if len(name) < 10:
        return "FAIL", "EBS name must be at least 10 characters long"

    if '-' not in name:
        return "FAIL", "EBS name must contain a hyphen separating suffix"

    main_name, suffix = name.split('-', 1)

    if len(suffix) > 12:
        name_result.append("Drive or mount point should be at most 12 characters")

    if apms_id_digit not in main_name:
        name_result.append("APMS ID not found in the EBS name")

    if region_country_map[region] != main_name[:5]:
        name_result.append(f"Country code must be {region_country_map[region]} for your provide region {region}")


    if main_name[-5] not in supported_environment_digits:
        name_result.append("Environment id must be one of D, T, P")
        
    
    if main_name[-4] not in os_list:
        name_result.append("OS identifier should be X or W")

    if not main_name[-3:].isdigit():
        name_result.append("Last 3 characters of EBS name must be digits")

    if name_result:
        return "FAIL", ", ".join(name_result)
    else:
        return "PASS", "NA"
