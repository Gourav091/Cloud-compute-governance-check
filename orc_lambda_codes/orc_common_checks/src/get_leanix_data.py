import boto3
import logging
import os
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
leanix_cross_account_role_name = os.environ['LEANIX_CROSS_ACCOUNT_ROLE']
dynamodb_table_name = os.environ['LEANIX_TABLE_NAME']
account_table_name = os.environ['ACCOUNT_METADATA_DB']


def get_leanix_data(account_id,apms_id="12345"):
    try:
        sts = boto3.client('sts')
        assumed_role = sts.assume_role(
            RoleArn=leanix_cross_account_role_name,
            RoleSessionName='LeanIXSession',
            DurationSeconds=900)
        
        creds = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name='us-east-1'
        )

        dynamodb = session.resource('dynamodb')
        
        account_table = dynamodb.Table(account_table_name)
        account_response = account_table.query(
            KeyConditionExpression=Key('AccountNumber').eq(account_id)
        )
        account_items = account_response.get('Items', [])
        
        
        table = dynamodb.Table(dynamodb_table_name)
        response = table.query(
            KeyConditionExpression=Key('apms_id').eq(apms_id)
        )
        items = response.get('Items', [])
        
        env_tag_id_map = {
            "prd" : "prod",
            "tst" : "test",
            "inn" : "dev",
            "dev" : "dev"
        }
        env_tag_id_char_map = {
            "prd" : "P",
            "tst" : "T",
            "inn" : "D",
            "dev" : "D"
        }
        
        
        if not account_items:
            logger.warning("account-id not found in dynamodb table")
            account_name = f"account name is not available in dynamodb table for {account_id}"
            environment = f"cannot determine as account name is unavailable for {account_id} in dynamodb table"
            env_id_tag = f"cannot determine as account name is unavailable for {account_id} in dynamodb table"
            env_tag_id_char = f"cannot determine as account name is unavailable for {account_id} in dynamodb table"
        else:
            account_item = account_items[0]
            account_name = account_item.get('AccountName', 'account name is not available in dynamodb table')
            environment = "cannot determine as account name is unavailable in dynamodb table" if account_name == "NA" else account_name.split("-")[-1].lower()
            env_id_tag = f"cannot determine as account name is unavailable for {account_id} in dynamodb table" if account_name == "NA" else env_tag_id_map.get(environment, f"unsupported environment {environment}")
            env_tag_id_char = f"cannot determine as account name is unavailable for {account_id} in dynamodb table" if account_name == "NA" else env_tag_id_char_map.get(environment, f"unsupported environment {environment}")
        if not items:
            logger.warning(f"No LeanIX data found for apms_id: {apms_id}")
            return {
                'account_name': "NA",
                'environment': "NA",
                'apms_id': apms_id,
                'application-name': 'cannot retreive data from db since apms-id is missing or not found in dynamodb table',
                'it-technical-owner': 'cannot retreive data from db since apms-id is missing or not found in dynamodb table',
                'application-owner': 'cannot retreive data from db since apms-id is missing or not found in dynamodb table',
                'recovery-tier': 'cannot retreive data from db since apms-id is missing or not found in dynamodb table',
            }

        item = items[0]
        return {
            'account_name': account_name,
            'environment': environment,
            'env_id_for_tag': env_id_tag,
            'env_id_char_only': env_tag_id_char, 
            'apms_id': apms_id,
            'application-name': item.get('display_name', 'NA'),
            'it-technical-owner': item.get('it_technical_owner', 'NA'),
            'application-owner': item.get('application_owner', 'NA'),
            'recovery-tier': item.get('tag_recoverytier', 'NA')
        }

    except Exception as e:
        logger.error(f"Error retrieving LeanIX data for apms_id {apms_id}: {e}")
        return {
            'account_name': account_name,
            'environment': environment,
            'env_id_for_tag': "NA",
            'env_id_char_only': "NA",
            'apms_id': apms_id,
            'application-name': 'NA',
            'it-technical-owner': 'NA',
            'application-owner': 'NA',
            'recovery-tier': 'NA'
        }