import json
import os
import logging
import requests

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

BASE_URL = f"https://{os.getenv('SN_INSTANCE', 'takedadev').strip()}.service-now.com"
TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS", "20"))

def get_token_password_grant() -> str:
    token_url = f"{BASE_URL}/oauth_token.do"
    data = {
        "grant_type": "password",
        "client_id": os.getenv("SN_CLIENT_ID"),
        "client_secret": os.getenv("SN_CLIENT_SECRET"),
        "username": os.getenv("SN_OAUTH_USERNAME"),
        "password": os.getenv("SN_OAUTH_PASSWORD"),
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    LOG.info("Requesting OAuth token at %s", token_url)
    r = requests.post(token_url, data=data, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()

    body = r.json()
    token = body.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in response: {body}")
    return token

def get_service_ci_id(service_name):
    token = get_token_password_grant()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    url = f"{BASE_URL}/api/gtpia/tak_bott_automation_ci_id"

    payload = {
        "service_name": "Terraform Module Development - Development"
    }

    LOG.info("POST %s payload=%s", url, json.dumps(payload))
    resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()

    data= resp.json()
    return data.get("result", {}).get("data", {}).get("ci_id", "Not Available")

def lambda_handler(event, context):
    try:
        result = get_service_ci_id(
            service_name="Terraform Module Development - Development"
        )

        ci_id = result.get("result", {}).get("data", {}).get("ci_id", "Not Available")

        return ci_id

    except Exception as e:
        LOG.exception("Lambda execution failed")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)}),
        }
