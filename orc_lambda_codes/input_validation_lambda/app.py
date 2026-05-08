import json
import boto3

stepfunctions = boto3.client('stepfunctions')

STATE_MACHINE_ARN = "arn:aws:states:us-east-1:123456789012:stateMachine:orc-workflow"


def lambda_handler(event, context):

    resource_id = event.get("resource_id")

    response = stepfunctions.start_execution(
        stateMachineArn=STATE_MACHINE_ARN,
        input=json.dumps(event)
    )

    return {
        "statusCode": 200,
        "message": "ORC Workflow Started",
        "executionArn": response["executionArn"]
    }