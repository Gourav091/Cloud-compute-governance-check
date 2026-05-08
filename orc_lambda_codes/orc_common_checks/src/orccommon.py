import logging
import os
import boto3
import json
from datetime import datetime
from naming_convention_check import final_naming_convention_check
from tag_validation_check import tag_validation


logger = logging.getLogger()
logger.setLevel(logging.INFO)

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


def lambda_handler(event, context):
    orc_type = event["info"].get("orc_request_type", "")
    if orc_type in ["manual_invocation", "automated_execution"]:
        execution_time = datetime.strptime(event["info"]["execution_time"],"%Y-%m-%dT%H:%M:%S.%fZ").strftime("%d-%m-%Y %H:%M:%S")
        event["info"]["execution_time"] = execution_time
        check_name = final_naming_convention_check(event)
        ec2_tag_validation = tag_validation(event)
        if contains_fail(check_name) or contains_fail(ec2_tag_validation):
            event["info"]["overall_orc_check_result"] = "ORC Check Failed"
        else:
            event["info"]["overall_orc_check_result"] = "ORC Check Passed"
        
        if check_name["info"]["orc_request_type"] == "errored":
            invoke_lambda(check_name)
            raise RuntimeError(f"error during common checks: {check_name['info']['error']}")
        elif ec2_tag_validation["info"]["orc_request_type"] == "errored":
            invoke_lambda(ec2_tag_validation)
            raise RuntimeError(f"error during common checks: {ec2_tag_validation['info']['error']}")
        else:
            return event