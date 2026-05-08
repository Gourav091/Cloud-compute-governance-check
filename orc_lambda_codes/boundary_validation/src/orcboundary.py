import os
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import jwt
import re
import time
import boto3
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

secret_arn = os.getenv("SECRET_ARN")
boundary_database = os.getenv("BOUNDARY_DATABASE")


session = requests.Session()
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount('https://', adapter)
session.mount('http://', adapter)

def generate_jwt_token(private_key, jwt_aud, jwt_name, jwt_sub):
    iat = int(time.time())
    exp = iat + 300
    payload = {
        "aud": jwt_aud,
        "name": jwt_name,
        "iat": iat,
        "exp": exp,
        "sub": jwt_sub
    }
    headers = {
        "alg": "RS256",
        "typ": "JWT"
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return token.decode("utf-8") if isinstance(token, bytes) else token

def get_vault_token(jwt_token, vault_url, vault_role, vault_namespace):
    url = f"{vault_url}/v1/auth/jwt-93400-telemetry-orcautomation/login"
    payload = {
        "role": vault_role,
        "jwt": jwt_token
    }
    headers = {
        "Content-Type": "application/json",
        "X-Vault-Namespace": vault_namespace
    }
    resp = session.post(url, headers=headers, data=json.dumps(payload))
    return resp.json()["auth"]["client_token"]

def get_vault_secret(vault_token, vault_url, secret_path):
    url = f"{vault_url}/v1/{secret_path}"
    headers = {"X-Vault-Token": vault_token}
    resp = session.get(url, headers=headers)
    return resp.json()["data"]["data"]

def authenticate(base_url, auth_method_id, login_name, password):
    url = f"{base_url}/v1/auth-methods/{auth_method_id}:authenticate"
    payload = {
        "type": "token",
        "attributes": {
            "login_name": login_name,
            "password": password
        },
        "command": "login"
    }
    resp = session.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
    return resp.json()["attributes"]["token"]

def list_targets(base_url, api_token, scope_id=None):
    url = f"{base_url}/v1/targets"
    headers = {"Authorization": f"Bearer {api_token}"}
    params = {"scope_id": scope_id} if scope_id else {}
    resp = session.get(url, headers=headers, params=params)
    return resp.json()["items"]

def read_target(base_url, api_token, target_id):
    url = f"{base_url}/v1/targets/{target_id}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = session.get(url, headers=headers)
    ids = resp.json().get("host_source_ids", [])
    return ids[0] if ids else None

def get_host_name(base_url, api_token, host_set_id):
    url = f"{base_url}/v1/host-sets/{host_set_id}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = session.get(url, headers=headers)
    ids = resp.json().get("host_ids", [])
    return ids[0] if ids else None

def get_ip_from_host_source(base_url, api_token, host_source_id):
    url = f"{base_url}/v1/hosts/{host_source_id}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = session.get(url, headers=headers)
    return resp.json()["attributes"]["address"]

def fetch_host_id(base_url, api_token, target):
    target_id = target.get("id")
    target_name = target.get("name")
    host_set_id = read_target(base_url, api_token, target_id)
    if not host_set_id:
        return (target_name, None, None)
    host_id = get_host_name(base_url, api_token, host_set_id)
    if not host_id:
        return (target_name, None, None)
    ip_address = get_ip_from_host_source(base_url, api_token, host_id)
    match = re.search(r"(?i)(i-[0-9a-f]{8,})_", target_name)
    target_name_id = match.group(1) if match else "NA"

    return (target_name, target_name_id, ip_address)

def write_host_db():
    sm_client = boto3.client("secretsmanager")
    response = sm_client.get_secret_value(SecretId=secret_arn)
    secret_data = json.loads(response["SecretString"])

    BASE_URL = secret_data.get("BASE_URL")
    AUTH_METHOD_ID = secret_data.get("AUTH_METHOD_ID")
    JWT_AUD = secret_data.get("JWT_AUD")
    JWT_NAME = secret_data.get("JWT_NAME")
    JWT_SUB = secret_data.get("JWT_NAME")
    PRIVATE_KEY = secret_data.get("PRIVATE_KEY")
    SCOPE_ID = secret_data.get("SCOPE_ID")
    SECRET_PATH = secret_data.get("SECRET_PATH")
    VAULT_NAMESPACE = secret_data.get("VAULT_NAMESPACE")
    VAULT_ROLE = secret_data.get("VAULT_ROLE")
    VAULT_SECRET_PATH = secret_data.get("VAULT_SECRET_PATH")
    VAULT_URL = secret_data.get("VAULT_URL")

    jwt_token = generate_jwt_token(PRIVATE_KEY, JWT_AUD, JWT_NAME, JWT_SUB)
    vault_token = get_vault_token(jwt_token, VAULT_URL, VAULT_ROLE, VAULT_NAMESPACE)
    app_secret_data = get_vault_secret(vault_token, VAULT_URL, SECRET_PATH)

    login_name = app_secret_data.get("User")
    password = app_secret_data.get("Password")

    api_token = authenticate(BASE_URL, AUTH_METHOD_ID, login_name, password)
    targets = list_targets(BASE_URL, api_token, SCOPE_ID)

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(boundary_database)

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(fetch_host_id, BASE_URL, api_token, target) for target in targets]
        for future in as_completed(futures):
            target_name, target_name_id, ip_address = future.result()
            try:
                table.put_item(Item={
                    "private_ip": ip_address if ip_address else "Not Available",
                    "instance_id": target_name_id if target_name_id else "Not Available",
                    "target_name": target_name if target_name else "Not Available"
                })
            except Exception as e:
                logger.error(f"Error writing {ip_address}: {e}")


def fetch_status_from_boundary(host_id="NA"):
    try:
        sm_client = boto3.client("secretsmanager")
        response = sm_client.get_secret_value(SecretId=secret_arn)
        secret_data = json.loads(response["SecretString"])

        BASE_URL = secret_data.get("BASE_URL")
        AUTH_METHOD_ID = secret_data.get("AUTH_METHOD_ID")
        JWT_AUD = secret_data.get("JWT_AUD")
        JWT_NAME = secret_data.get("JWT_NAME")
        JWT_SUB = secret_data.get("JWT_NAME")
        PRIVATE_KEY = secret_data.get("PRIVATE_KEY")
        SCOPE_ID = secret_data.get("SCOPE_ID")
        SECRET_PATH = secret_data.get("SECRET_PATH")
        VAULT_NAMESPACE = secret_data.get("VAULT_NAMESPACE")
        VAULT_ROLE = secret_data.get("VAULT_ROLE")
        VAULT_SECRET_PATH = secret_data.get("VAULT_SECRET_PATH")
        VAULT_URL = secret_data.get("VAULT_URL")

        jwt_token = generate_jwt_token(PRIVATE_KEY, JWT_AUD, JWT_NAME, JWT_SUB)
        vault_token = get_vault_token(jwt_token, VAULT_URL, VAULT_ROLE, VAULT_NAMESPACE)
        app_secret_data = get_vault_secret(vault_token, VAULT_URL, SECRET_PATH)

        login_name = app_secret_data.get("User")
        password = app_secret_data.get("Password")

        api_token = authenticate(BASE_URL, AUTH_METHOD_ID, login_name, password)
        targets = list_targets(BASE_URL, api_token, SCOPE_ID)
    

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(fetch_host_id, BASE_URL, api_token, target) for target in targets]
            for future in as_completed(futures):
                target_name, target_name_id, ip_address = future.result()
                if host_id == target_name_id:
                    logger.info(f"{target_name_id} found")
                    return "Onboarded in Boundary",ip_address, target_name_id, target_name

        logger.warning(f"instance_id not found in any target.")
        return "Haven't Onboared in Boundary","NA","NA"
    except Exception as err:
        logger.info(f"error while checking the request : {str(err)}")
        return "Errored while checking","NA","NA"
    
    

def lambda_handler(event, context):
    instance_id = event.get("info", {}).get("resource_id") or "NA"
    
    if instance_id == "automated_execution":
        logger.info(f"automated trigger detected , proceeding with writing all the results in {boundary_database} db")
        write_host_db()
    elif instance_id == "NA":
        return "no instance_id or automated_execution received in the events, so skipping the execution"
        
    else:
        try:
            dynamodb = boto3.resource("dynamodb")
            boundary_db = dynamodb.Table(boundary_database)
            
            response = boundary_db.query(
                KeyConditionExpression=Key("instance_id").eq(instance_id)
            )
            
            items = response.get("Items", [])
            if items:
                item = items[0]
                logger.info(f"Found the instance in boundary database: {item}")
                return {
                        "Boundary Onboarding Status": "Onboarded in Boundary"
                    }
            else:
                logger.warning(f"No entry found for : {instance_id}")
                logger.info("Server not found in boundary DB, triggering the API call.")
                
                status, ip_address, target_name_id, target_name = fetch_status_from_boundary(instance_id)
                
                if status == "Onboarded in Boundary":
                    boundary_db.put_item(Item={
                        "private_ip": ip_address,
                        "instance_id": target_name_id,
                        "target_name": target_name
                    })
                    logger.info(f"Stored {target_name_id} in DynamoDB.")
                    return {
                        "Boundary Onboarding Status": status
                    }
                else:
                    logger.info("Server not found in boundary")
                    return {
                        "Boundary Onboarding Status": status
                    }

        except Exception as e:
            logger.error(f"Error fetching  {instance_id}: {e}")
            return {
                "Boundary Onboarding Status": "errored during execution"
            }