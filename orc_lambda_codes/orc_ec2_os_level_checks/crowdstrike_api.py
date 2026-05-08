import requests
import boto3
import os
import json

secret_arn = os.getenv("SECRET_ARN")

def crowdstrike_falcon_api(instance_id):
    sm_client = boto3.client("secretsmanager")
    response = sm_client.get_secret_value(SecretId=secret_arn)
    secret_data = json.loads(response["SecretString"])
    client_id = secret_data['FALCON_CLIENT_ID']
    client_secret = secret_data['FALCON_SECRET_ID']
    base_url = secret_data['FALCON_URL']
    
    token_url = f"{base_url}/oauth2/token"
    crowd_response = requests.post(
        token_url,
        headers={"Accept": "application/json"},
        data={
            "client_id": client_id,
            "client_secret": client_secret
        }
    )
    crowd_response.raise_for_status()
    token = crowd_response.json().get("access_token")

    device_url = f"{base_url}/devices/queries/devices/v1"
    params = {"filter": f"instance_id: '{instance_id}' "}
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    dev_resp = requests.get(device_url, headers=headers, params=params)
    return "Yes" if  (len(dev_resp.json().get("resources"))) > 0 else "No"
