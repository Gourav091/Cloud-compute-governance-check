import json
import logging
import os
import boto3

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
    
    sample_event = event[0]

    if sample_event["info"]["resource_type"] == "ec2":
        if sample_event["info"]["operating_system"].lower() == 'windows':
            from os_windows import ec2_windows_os_checks
            os_checks = ec2_windows_os_checks(event)            
        
        elif sample_event["info"]["operating_system"].lower() == 'Linux/UNIX'.lower():
            from os_linux import ec2_linux_os_checks
            os_checks = ec2_linux_os_checks(event)

        if contains_fail(os_checks):
            sample_event["info"]["overall_orc_check_result"] = "ORC Check Failed"
        else:
            sample_event["info"]["overall_orc_check_result"] = "ORC Check Passed"
        
        if os_checks[0]["info"]["orc_request_type"] == "errored":
            invoke_lambda(os_checks[0])
            raise RuntimeError(f"error during common checks: {os_checks[0]['info']['error']}")
              
        else:
            return os_checks[0]