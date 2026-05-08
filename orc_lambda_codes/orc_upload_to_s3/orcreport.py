import os
from pdf_report_ec2 import ec2_report_generation
from upload_to_s3 import upload_to_s3
from send_email import send_email_smtp
from dynamodb_write import dynamodb_write

s3_bucket_name = os.environ["S3_BUCKET"]

def lambda_handler(event, context):
    pdf_file_path = ec2_report_generation(event)

    s3_upload = upload_to_s3(pdf_file_path, s3_bucket_name, event)
    
    write_to_orc_table = dynamodb_write(event)
    
    to_email = [event["info"]["orc-check-requestor"]]
    
    send_email_smtp(event, to_email, pdf_file_path)

    return {
        "statusCode": 200,
        "body": f"Report generated, uploaded to s3://{s3_bucket_name}/{s3_upload} and email sent."
    }