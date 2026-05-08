import boto3
import os
import logging
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cross_account_role_name = os.environ.get('CROSS_ACCOUNT_ORC_ROLE')

def pre_check_ec2(input_event):
    region = input_event.get('region')
    account_id = input_event.get('account')
    email_details = input_event.get('requestor_email', "dl.ftp.cloud.orc@takeda.com")

    eventdata = {
        "region": region,
        "account_id": account_id,
        "orc_check_stage": "orc_pre_check_validation",
        "requestor_email": email_details
    }

    try:
        instance_id = input_event["detail"]["requestParameters"]["instancesSet"]["items"][0]["instanceId"]
    except KeyError:
        try:
            instance_id = input_event['detail']['responseElements']["instancesSet"]["items"][0]["instanceId"]
        except KeyError:
            logger.error("Instance ID not found in event structure.")
            eventdata.update({
                "error": "Instance ID not found in event",
                "overall_status": "errored",
                "orc_request_type": "errored",
                "resource_id": "NA"
            })
            return eventdata
        except Exception as e:
            logger.exception("Unexpected error occurred retrieving instance ID.")
            eventdata.update({
                "error": "Unable to retrieve instance_id from event",
                "overall_status": "errored",
                "orc_request_type": "errored",
                "resource_id": "NA"
            })
            return eventdata

    eventdata["resource_id"] = instance_id
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

        ec2 = session.client('ec2')
        res = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = res.get('Reservations', [])

        if not reservations or not reservations[0].get('Instances'):
            logger.warning(f"No EC2 instance found with ID {instance_id} in account {account_id}, region {region}.")
            eventdata.update({
                "error": f"EC2 instance {instance_id} not found or no longer exists.",
                "overall_status": "errored",
                "orc_request_type": "errored"
            })
            return eventdata

        tags = reservations[0]['Instances'][0].get('Tags', [])

    except ClientError as ce:
        error_code = ce.response['Error']['Code']
        error_message = ce.response['Error']['Message']
        logger.error(f"AWS ClientError: {error_code} - {error_message}")

        if error_code == 'InvalidInstanceID.NotFound':
            error_message = f"EC2 instance {instance_id} not found in account {account_id} and region {region}."

        eventdata.update({
            "error": error_message,
            "overall_status": "errored",
            "orc_request_type": "errored"
        })
        return eventdata

    except BotoCoreError as bce:
        logger.error(f"BotoCoreError: {str(bce)}")
        eventdata.update({
            "error": str(bce),
            "overall_status": "errored",
            "orc_request_type": "errored"
        })
        return eventdata

    except Exception as e:
        logger.exception("Unexpected error occurred.")
        eventdata.update({
            "error": str(e),
            "overall_status": "errored",
            "orc_request_type": "errored"
        })
        return eventdata

    tag_map = {tag['Key']: tag['Value'] for tag in tags}
    request_check = tag_map.get('orc-check-request')
    requestor = tag_map.get('orc-check-requestor', '').strip()

    if request_check == 'TRUE' and requestor:
        eventdata.update({
            "orc_request_type": "automated_execution",
            "orc-check-request": "True",
            "orc-check-requestor": requestor,
            "message": "ORC check required. Tags are valid."
        })
    else:
        messages = []
        if request_check != 'TRUE':
            messages.append("orc-check-request tag is not set to TRUE")
        if not requestor:
            messages.append("orc-check-requestor tag is not set or empty")
        eventdata.update({
            "orc_request_type": "skip_execution",
            "orc-check-requestor": requestor,
            "message": "ORC check skipped: " + "; ".join(messages)
        })

    return eventdata
