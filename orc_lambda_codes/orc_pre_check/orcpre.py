import logging
import validate_tags
import os


logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_topic_arn = os.environ['SNS_ARN']

def lambda_handler(event, context):
    event_data_final = {"info": {}}

    if "source" in event:
        logger.info("Automated event detected, proceeding accordingly")

        if event["source"] == "aws.ec2":
            logger.info("Event is EC2 instance-related, calling tag validator")
            event_source = event["source"].split(".")[1]
            event_data = validate_tags.pre_check_ec2(event)
            event_data_final["info"] = event_data
            event_data_final["info"]["resource_type"] = event_source
            
            return event_data_final