from ec2_aws import ec2_information_level_checks,ec2_aws_level_orc_checks
import boto3
import os
import json

notification_lambda = os.environ['NOTIFICATION_LAMBDA_ARN']

def invoke_lambda(payload):
    client = boto3.client('lambda', region_name='us-east-1')
    client.invoke(
        FunctionName=notification_lambda,
        InvocationType='Event',
        Payload=json.dumps(payload)
    )

def contains_fail(obj):
    if isinstance(obj, dict):
        for value in obj.values():
            if contains_fail(value):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if contains_fail(item):
                return True
    elif isinstance(obj, str):
        return obj == "FAIL"
    return False

def lambda_handler(event,context):
    resource_type = event["info"]["resource_type"]
    if resource_type == "ec2":
        event = ec2_information_level_checks(event)
        if event["info"]["orc_request_type"] == "errored":
            invoke_lambda(event)
            raise RuntimeError(f"error during aws level checks: {event['info']['error']}")
        else:
            event = ec2_aws_level_orc_checks(event)
            if event["info"]["orc_request_type"] == "errored":
                invoke_lambda(event)
                raise RuntimeError(f"error during aws level checks: {event['info']['error']}")
            else:
                if contains_fail(event):
                    event["info"]["overall_orc_check_result"] = "ORC Check Failed"
                    return event
                else:
                    event["info"]["overall_orc_check_result"] = "ORC Check Passed"
                    return event
    