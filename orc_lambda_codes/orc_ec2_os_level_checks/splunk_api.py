import splunklib.client as client
import splunklib.results as results
import boto3
import json
import os
import time
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)

secret_name = os.environ["SECRET_ARN"]
splunk_host = "search1-shire.splunkcloud.com"
splunk_port = 8089

def get_splunk_token():
    sm_client = boto3.client("secretsmanager", region_name="us-east-1")
    secret = sm_client.get_secret_value(SecretId=secret_name)
    secret_dict = json.loads(secret["SecretString"])
    logger.info("Successfully retrieved Splunk token")
    return secret_dict["splunk_token"]

def splunk_connect():
    auth_token = get_splunk_token()
    service = client.connect(
        host=splunk_host,
        port=splunk_port,
        token=auth_token,
        autologin=True
    )
    logger.info("Splunk connection established successfully")
    return service

def wait_for_job(job, timeout=60):
    logger.info(f"Waiting for Splunk job {job.sid} to complete (timeout={timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        job.refresh()
        state = job["dispatchState"]
        logger.debug(f"Job {job.sid} state: {state}")
        if state in ["DONE", "FAILED"]:
            logger.info(f"Job {job.sid} finished with state: {state}")
            return state
        time.sleep(1)
    logger.warning(f"Job {job.sid} timed out after {timeout}s")
    return "TIMEOUT"


def check_hostname_exists(hostname):
    logger.info(f"Checking if hostname '{hostname}' exists in Splunk metadata...")
    try:
        service = splunk_connect()
        search_query = f'|metadata index=* type=hosts earliest=-10m@m | search host=*{hostname}* | head 1 | table host'
        logger.info(f"Executing Splunk search: {search_query}")

        job = service.jobs.create(search_query, earliest_time="-10m", latest_time="now")
        state = wait_for_job(job)

        if state != "DONE":
            logger.warning(f"Search job did not complete successfully. State: {state}")
            return "No"

        reader = results.JSONResultsReader(job.results(output_mode="json"))
        for event in reader:
            logger.debug(f"Raw Splunk event: {event}")
            event_host = event.get("host")
            if event_host and hostname.lower() in event_host.strip().lower():
                return "Yes"


        logger.info(f"Hostname '{hostname}' not found in Splunk")
        return "No"

    except Exception as e:
        logger.error(f"Error checking hostname '{hostname}': {e}", exc_info=True)
        return "No"

def splunk_api_details(hostname):
    result = check_hostname_exists(hostname)
    logger.info(f"Final result for hostname '{hostname}': {result}")
    return result
