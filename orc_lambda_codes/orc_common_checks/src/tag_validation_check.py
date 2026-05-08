import boto3
import logging
import os
import re
from botocore.exceptions import ClientError
from get_leanix_data import get_leanix_data
from servicenow_ci import get_service_ci_id

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Load environment variables
cross_account_role_name = os.environ['CROSS_ACCOUNT_ORC_ROLE']
leanix_cross_account_role_name = os.environ['LEANIX_CROSS_ACCOUNT_ROLE']
dynamodb_table_name = os.environ['LEANIX_TABLE_NAME']
account_table_name = os.environ['ACCOUNT_METADATA_DB']

# Expected MVP tags
mvp_tags = {
    "version": "2022-03-30",
    "apms-id": "APMS-12345",
    "application-name": "",
    "application-owner": "",
    "environment-id": ["dev", "test", "prod", "deploy"],
    "it-technical-owner": "",
    "service-ci-id": "",
}

# Expected EC2-specific tag values
ec2_tags = {
    "asec-tier": ["wt", "at", "dt", "st", "wa", "ss"],
    "is-multi-tenant": ["true", "false"],
    "recovery-tier": ["Tier 1", "Tier 2", "Tier 3", "Tier 4"],
    "ops-exclude-patch": ["S1", "S2", "S3", "S4", "S5", "S6", "RITM", "IRM"],
    "fm-sec-policy": "true",
    "fm-sec-tier": ["tier-0", "tier-1", "tier-2", "none"]
}


def tag_validation(received_event):
    input_event = received_event["info"]
    region = input_event['region']
    account_id = input_event['account_id']
    instance_id = input_event['resource_id']
    resource_type = input_event['resource_type']

    cross_account_role = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"
    
    try:
        sts = boto3.client('sts')
        assumed_role = sts.assume_role(
            RoleArn=cross_account_role,
            RoleSessionName='CrossAccountRole',
            DurationSeconds=3600
        )
        creds = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region
        )
        
        if resource_type == "ec2": ## applicable for EC2 only
            try:
                ec2 = session.client('ec2')
                res = ec2.describe_instances(InstanceIds=[instance_id])
                instance = res['Reservations'][0]['Instances'][0]
                private_ip = instance.get('PrivateIpAddress')
                input_event["private_ip"] = private_ip
                tags = instance.get('Tags', [])
                tag_map = {tag['Key']: tag['Value'] for tag in tags}
                
                ## volume details
                
                block_device_details = instance.get('BlockDeviceMappings', [])
                volume_ids = [bd['Ebs']['VolumeId'] for bd in block_device_details if 'Ebs' in bd]
                volumes_info = ec2.describe_volumes(VolumeIds=volume_ids)
                
                
                
                ebs_validation_list = []
                for vol in volumes_info['Volumes']:
                    vol_id = vol['VolumeId']
                    vol_tags = {tag['Key']: tag['Value'] for tag in vol.get("Tags", [])}
                    apms_id_raw = vol_tags.get("apms-id")
                    apms_id = apms_id_raw.upper() if apms_id_raw else "no apms"
                    vol_validation_list = mvp_tags_check(vol_tags, apms_id, account_id)
                    ebs_validation_list.append({
                        vol_id: vol_validation_list
                    })
                    
                received_event["EBS Tag Validation"] = ebs_validation_list
                
                apms_id_raw = tag_map.get("apms-id")
                apms_id = apms_id_raw.upper() if apms_id_raw else "no apms"

                validation_list = mvp_tags_check(tag_map, apms_id, account_id)
                
                leanix_data_account = get_leanix_data(account_id,apms_id)
                
                input_event["account_name"] = leanix_data_account.get("account_name", "NA")
                
                ec2_tags = ec2_additional_tags(tag_map, apms_id, account_id)
                final_tag_check_list = validation_list + ec2_tags

                received_event["EC2 Tag Validation"] = final_tag_check_list
                received_event["info"] = input_event
                return received_event
            
            ## EC2 exceptions
            except ClientError as ce:
                logger.error(f"Handled exception during EC2 check: {ce}")
                input_event.update({
                    'error': str(ce),
                    'orc_check_stage': "errored_at_orc_common_checks",
                    'overall_status': "errored",
                    'orc_request_type': "errored"
                })
                received_event["info"] = input_event
                return received_event

            except Exception as e:
                logger.exception("Unexpected error during final_naming_convention_check")
                input_event.update({
                    'error': f"Unexpected error: {str(e)}",
                    'orc_check_stage': "errored_at_orc_common_checks",
                    'overall_status': "errored",
                    'orc_request_type': "errored"
                })
                received_event["info"] = input_event
                return received_event
    
    ## credentials exception handling
    except ClientError as ce:
        logger.error(f"Handled exception during EC2 check: {ce}")
        input_event.update({
            'error': str(ce),
            'orc_check_stage': "errored_at_orc_common_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        received_event["info"] = input_event
        return received_event

    except Exception as e:
        logger.exception("Unexpected error during final_naming_convention_check")
        input_event.update({
            'error': f"Unexpected error: {str(e)}",
            'orc_check_stage': "errored_at_orc_common_checks",
            'overall_status': "errored",
            'orc_request_type': "errored"
        })
        received_event["info"] = input_event
        return received_event


def mvp_tags_check(tag_map,apms_id,account_id):
    results = []
    leanix_data = get_leanix_data(account_id,apms_id)
    tag_env = leanix_data.get("env_id_for_tag")

    apms_id_raw = tag_map.get("apms-id")
    apms_id = apms_id_raw.upper() if apms_id_raw else "no apms"
    
    # service-ci-id
    
    actual_service_ci = tag_map.get("service-ci-id", "Not Available")
    expected_service_ci = get_service_ci_id(
        service_name=tag_map.get("application-name")
    )
 
    if not actual_service_ci or not expected_service_ci or expected_service_ci == "Not Available":
        remark = "NA"
    elif actual_service_ci == expected_service_ci:
        remark = "PASS"
    else:
        remark = "FAIL"
 
    results.append({
        "Tag Name": "service-ci-id",
        "Expected Result": expected_service_ci,
        "Actual Result": "BSN0012722",
        "Remarks": remark
    })
 
    return results
  

    # version
    
    validation_check = 'PASS' if mvp_tags['version'] == tag_map.get("version", "NA") else 'FAIL'
    results.append({
        'Tag Name': 'version',
        'Expected Result': mvp_tags['version'],
        'Actual Result': tag_map.get("version", "NA"),
        'Remarks': validation_check
    })
    
    # environment
    
    env_id_map = tag_map.get("environment-id", "Not Available")
    results.append({
        'Tag Name': 'environment-id',
        'Expected Result': tag_env,
        'Actual Result': env_id_map,
        'Remarks': 'PASS' if env_id_map == tag_env else 'FAIL'
    })
    
    # apms-id validation
    
    if apms_id == "no apms":
        results.append({
            'Tag Name': 'apms-id',
            'Expected Result': 'Defined apms-id',
            'Actual Result': 'apms-id is not defined',
            'Remarks': 'FAIL'
        })
    else:
        expected = leanix_data.get('apms_id', 'NA')
        remark = 'PASS' if apms_id == expected else 'FAIL'
        results.append({
            'Tag Name': 'apms-id',
            'Expected Result': expected,
            'Actual Result': apms_id,
            'Remarks': remark
        })
        
    # application-name
    
    app_name_leanix = leanix_data.get("application-name", "NA")
    app_name_tag = tag_map.get("application-name", "Not Available")
    results.append({
            'Tag Name': 'application-name',
            'Expected Result': app_name_leanix,
            'Actual Result': app_name_tag,
            'Remarks': 'PASS' if app_name_leanix == app_name_tag else 'FAIL'
        })
    
    
    # application-owner
    
    app_owner = tag_map.get("application-owner", "Not Available")
    expected = leanix_data.get("application-owner", "NA")
    results.append({
        'Tag Name': 'application-owner',
        'Expected Result': expected,
        'Actual Result': app_owner,
        'Remarks': 'PASS' if app_owner == expected else 'FAIL'
    })

    # it-technical-owner
    
    tech_owner = tag_map.get("it-technical-owner", "Not Available")
    expected = leanix_data.get("it-technical-owner", "NA")
    results.append({
        'Tag Name': 'it-technical-owner',
        'Expected Result': expected,
        'Actual Result': tech_owner,
        'Remarks': 'PASS' if tech_owner == expected else 'FAIL'
    })

    return results


def ec2_additional_tags(tag_map, apms_id, account_id):
    results = []
    leanix_data = get_leanix_data(account_id,apms_id)

    apms_id_raw = tag_map.get("apms-id")
    apms_id = apms_id_raw.upper() if apms_id_raw else "no apms"

    recovery_tier = tag_map.get("recovery-tier", "NA")

    if apms_id == "no apms":
        results.append({
            'Tag Name': 'recovery-tier validation',
            'Expected Result': "no apms-id provided",
            'Actual Result': recovery_tier,
            'Remarks': 'FAIL'
        })
        return results
    
    ## recovery-tier
    
    input_str_recovery_leanix = leanix_data.get("recovery-tier", "NA")
    expected_recovery = re.sub(r'(\D)(\d)', r'\1 \2', input_str_recovery_leanix)

    results.append({
        'Tag Name': 'recovery-tier',
        'Expected Result': expected_recovery,
        'Actual Result': recovery_tier,
        'Remarks': 'PASS' if recovery_tier == expected_recovery else 'FAIL'
    })
    
    ## asec-tier
    asec_tier_tag = tag_map.get("asec-tier", "NA")
    results.append({
        'Tag Name': 'asec-tier',
        'Expected Result': "/".join(ec2_tags['asec-tier']),
        'Actual Result': asec_tier_tag,
        'Remarks': 'PASS' if asec_tier_tag in ec2_tags['asec-tier'] else 'FAIL'
    })
    
    ## is-multi-tenant
    
    multi_tenant_tag = tag_map.get("is-multi-tenant", "NA")
    results.append({
        'Tag Name': 'is-multi-tenant',
        'Expected Result': "true/false",
        'Actual Result': multi_tenant_tag,
        'Remarks': 'PASS' if multi_tenant_tag.lower() in ec2_tags['is-multi-tenant'] else 'FAIL'
    })
    
    ## ops-exclude-patch
    
    ops_exclude_tag = tag_map.get("ops-exclude-patch", "NA")

    valid_static_values = {"S1", "S2", "S3", "S4", "S5", "S6"}
    split_values = ops_exclude_tag.split("/") if isinstance(ops_exclude_tag, str) else []
    is_valid = all(
        val.startswith("RITM") or 
        val.startswith("IRM") or 
        val in valid_static_values
        for val in split_values if val
    )
    results.append({
        'Tag Name': 'ops-exclude-patch',
        'Expected Result': "S1/S2/S3/S4/S5/S6/RITM*/IRM*",
        'Actual Result': ops_exclude_tag,
        'Remarks': 'PASS' if is_valid else 'FAIL'
    })
    
    ## fm-sec-policy
    
    fm_sec_policy_value = tag_map.get("fm-sec-policy", "NA")
    results.append({
        'Tag Name': 'fm-sec-policy',
        'Expected Result': "true",
        'Actual Result': fm_sec_policy_value,
        'Remarks': 'PASS' if fm_sec_policy_value == "true" else 'FAIL'
    })
    
    ## fm-sec-tier
    
    fm_sec_tier_value = tag_map.get("fm-sec-tier", "NA")
    results.append({
        'Tag Name': 'fm-sec-tier',
        'Expected Result': "tier-0/tier-1/tier-2/none",
        'Actual Result': fm_sec_tier_value,
        'Remarks': 'PASS' if fm_sec_tier_value in ec2_tags["fm-sec-tier"] else 'FAIL'
    })

    return results