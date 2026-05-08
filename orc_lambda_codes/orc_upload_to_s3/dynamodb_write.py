import boto3
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

orc_dynamodb_table = os.environ["DYNAMO_TABLE_ARN"]

def dynamodb_write(event):
    info = event["info"]

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.Table(orc_dynamodb_table)

    resource_id = info.get("resource_id", "NA")
    requestor = info.get("orc-check-requestor", "NA")
    execution_time = info.get("execution_time", "NA")
    account_id = info.get("account_id", "NA")
    resource_type = info.get("resource_type", "NA").upper()
    aws_region = info.get("region", "NA")
    account_name = info.get("account_name", "NA")
    overall_request_type = info.get("overall_orc_check_result","NA")

    try:
        response = table.put_item(
            Item = {
                "execution_time": execution_time,
                "resource_id": resource_id,
                "account_name": account_name,
                "account_id": account_id,
                "overall_orc_result": overall_request_type,
                "resource_type": resource_type,              
                "requestor": requestor,
                "aws_region": aws_region
            }
        )
        logger.info(f"Successfully inserted item into {orc_dynamodb_table}")
    
    except Exception as e:
        print(f"Failed to write to DynamoDB: {e}")
        raise