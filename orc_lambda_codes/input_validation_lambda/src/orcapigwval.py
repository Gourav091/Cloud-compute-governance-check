import json
import logging
import os
import re
import boto3

# Initialize logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.info("Loading ORC API Gateway validator")

# Environment variables
state_machine_arn = os.environ.get('STEP_FUNCTION_ARN')

# Initialize boto3 client
stepfunction = boto3.client('stepfunctions')

# Constants
required_keys = ['resource_type', 'resource_id', 'account_id', 'region', 'requestor_email']
allowed_resource_types = ['ec2', 'securitygroup', 'loadbalancer']
email_val = re.compile(r'^[\w\.-]+@takeda\.com$', re.IGNORECASE)


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    # Validate required keys
    missing_keys = [key for key in required_keys if key not in event]
    if missing_keys:
        error_message = f"Missing required keys: {', '.join(missing_keys)}"
        logger.error(error_message)
        return {
            'statusCode': 400,
            'body': json.dumps({'error': error_message})
        }

    # Validate resource_type
    resource_type = event['resource_type']
    if resource_type not in allowed_resource_types:
        error_message = (
            f"Invalid resource_type '{resource_type}'. "
            f"Allowed values are: {', '.join(allowed_resource_types)}"
        )
        logger.error(error_message)
        return {
            'statusCode': 400,
            'body': json.dumps({'error': error_message})
        }

    # Validate requestor_email
    requestor_email = event['requestor_email']
    if not email_val.match(requestor_email):
        error_message = "Invalid requestor_email. Must be a valid takeda.com email address."
        logger.error(error_message)
        return {
            'statusCode': 400,
            'body': json.dumps({'error': error_message})
        }

    # Add tags
    event.update({
        'orc-check-request': "TRUE",
        'orc-check-requestor': requestor_email,
        'orc_request_type': "manual_invocation"
    })

    # Start Step Function execution
    try:
        response = stepfunction.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps({
                "source": event['check_type'],
                "info": event
            })
        )
        execution_arn = response['executionArn']
        logger.info("Step Function started: %s", execution_arn)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Step Function execution started',
                'executionName': execution_arn.split(":")[-1]
            })
        }

    except Exception as e:
        logger.exception("Failed to start Step Function")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Failed to start Step Function',
                'details': str(e)
            })
        }
