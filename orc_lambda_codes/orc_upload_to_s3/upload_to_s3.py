import boto3
import os

def upload_to_s3(pdf_file_path, bucket_name, event):
    info = event["info"]
    
    s3_client = boto3.client('s3')

    account_id = info.get("account_id")
    resource_type = info.get("resource_type").upper()
    aws_region = info.get("region")

    file_name = os.path.basename(pdf_file_path)
    s3_key = f"{account_id}/{resource_type}/{aws_region}/{file_name}"

    s3_client.upload_file(pdf_file_path, bucket_name, s3_key)

    return s3_key
