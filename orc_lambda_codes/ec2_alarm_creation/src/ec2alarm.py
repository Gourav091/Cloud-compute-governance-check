import boto3
import logging
import os
import botocore
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")



def run_command(ssm_client, instance_id, operating_system, script):
    if operating_system == "windows":
        doc = "AWS-RunPowerShellScript"
    else:
        doc = "AWS-RunShellScript"

    resp = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName=doc,
        Parameters={"commands": [script]},
    )
    cmd_id = resp["Command"]["CommandId"]

    while True:
        try:
            output = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            status = output.get("Status")
            if status in ["Success", "Failed", "Cancelled", "TimedOut"]:
                break
        except botocore.exceptions.ClientError as e:
            if "InvocationDoesNotExist" in str(e):
                time.sleep(2)
                continue
            else:
                raise
        time.sleep(2)

    return output.get("StandardOutputContent", "").strip()

def is_agent_running(ssm_client, instance_id, operating_system):
    if operating_system == "windows":
        command = "(Get-Service AmazonCloudWatchAgent).Status"
    else:
        command = "systemctl is-active amazon-cloudwatch-agent"

    status_output = run_command(ssm_client, instance_id, operating_system, command).lower()
    if operating_system == "windows":
        return status_output == "running"
    return status_output == "active"

def metric_exists(cloudwatch_client, namespace, metric_name, dimensions):
    paginator = cloudwatch_client.get_paginator("list_metrics")
    for page in paginator.paginate(Namespace=namespace, MetricName=metric_name, Dimensions=dimensions):
        if page.get("Metrics"):
            return True
    return False

def cloudwatch_alarm_creation(instance_id, operating_system, cloudwatch_client, ec2_client, sns_arn, ssm_client):
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance_data = response["Reservations"][0]["Instances"][0]
    ami_id = instance_data["ImageId"]
    instance_type = instance_data["InstanceType"]
    tags = instance_data.get("Tags", [])
    instance_name = "no instance name"
    for tag in tags:
        if tag.get("Key") == "Name":
            instance_name = tag.get("Value")
            break

    results = {}

    def alarm_exists(alarm_name):
        resp = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
        return len(resp.get("MetricAlarms", [])) > 0

    def create_alarm(kind, alarm_name, namespace, metric_name, dimensions, desc, threshold, comparison="GreaterThanThreshold", period=300):
        if alarm_exists(alarm_name):
            results[kind] = "alarm already exists"
            return
        if not metric_exists(cloudwatch_client, namespace, metric_name, dimensions):
            results[kind] = "alarm creation skipped, metric unavailable"
            return
        cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator=comparison,
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            TreatMissingData="missing",
            MetricName=metric_name,
            Namespace=namespace,
            Period=period,
            Statistic="Average",
            Threshold=threshold,
            ActionsEnabled=True,
            AlarmDescription=desc,
            Dimensions=dimensions,
            AlarmActions=[sns_arn],
        )
        results[kind] = "alarm created"

    create_alarm(
        "Instance Status Check Alarm",
        f"{instance_name}-STCH-FAIL-{instance_id}",
        "AWS/EC2",
        "StatusCheckFailed",
        [{"Name": "InstanceId", "Value": instance_id}],
        f"Status check failed for {instance_name} ({instance_id})",
        0.0,
        "GreaterThanThreshold",
        300
    )

    create_alarm(
        "CPU Status Alarm",
        f"{instance_name}-CPUU-HIGH-{instance_id}",
        "AWS/EC2",
        "CPUUtilization",
        [{"Name": "InstanceId", "Value": instance_id}],
        f"High CPU utilization on {instance_name} ({instance_id})",
        90.0,
        "GreaterThanThreshold",
        900
    )


    if operating_system == "windows":
        metric_name = "Memory % Committed Bytes In Use"
        dimensions = [
            {"Name": "InstanceId", "Value": instance_id},
            {"Name": "ImageId", "Value": ami_id},
            {"Name": "objectname", "Value": "Memory"},
            {"Name": "InstanceType", "Value": instance_type},
        ]
    else:
        metric_name = "mem_used_percent"
        dimensions = [
            {"Name": "InstanceId", "Value": instance_id},
            {"Name": "ImageId", "Value": ami_id},
            {"Name": "InstanceType", "Value": instance_type},
        ]

    create_alarm(
        "Memory Status Alarm",
        f"{instance_name}-MEMU-HIGH-{instance_id}",
        "CWAgent",
        metric_name,
        dimensions,
        f"High memory usage on {instance_name} ({instance_id})",
        90.0,
        "GreaterThanThreshold",
        900
    )


    if operating_system == "windows":
        disk_script = 'Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object {$_.DeviceID}'
        disk_output = run_command(ssm_client, instance_id, "windows", disk_script)
        for device in disk_output.splitlines():
            device = device.strip()
            if not device:
                continue
            threshold = 10.0
            dimensions = [
                {"Name": "InstanceId", "Value": instance_id},
                {"Name": "ImageId", "Value": ami_id},
                {"Name": "InstanceType", "Value": instance_type},
                {"Name": "instance", "Value": device},
                {"Name": "objectname", "Value": "LogicalDisk"},
            ]
            device_name = device.rstrip(":")
            create_alarm(
                f" {device} Disk Available Space",
                f"{instance_name}-DSU{device_name}-HIGH-{instance_id}",
                "CWAgent",
                "LogicalDisk % Free Space",
                dimensions,
                f"Low disk free space on {device_name} ({instance_name})",
                threshold,
                "LessThanThreshold",
                900
            )
    else:
        disk_script = """#!/bin/bash
        entries=$(awk '
        $1 !~ /^#/ &&
        $2 ~ "^/" &&
        $2 !~ "^/(boot|tmp|var/tmp|dev|run)" {print $1 ":" $2}
        ' /etc/fstab)

        output=""
        while IFS=: read -r device mountpoint; do
            if [[ "$device" =~ ^UUID= ]]; then
                uuid=${device#UUID=}
                device=$(blkid -U "$uuid" 2>/dev/null)
            elif [[ "$device" =~ ^LABEL= ]]; then
                label=${device#LABEL=}
                device=$(blkid -L "$label" 2>/dev/null)
            fi
            [[ -z "$device" ]] && continue
            device=${device##*/}

            size_bytes=$(lsblk -b -no SIZE "/dev/$device" 2>/dev/null)
            fstype=$(lsblk -no FSTYPE "/dev/$device" 2>/dev/null)

            entry="$device:$mountpoint:$size_bytes:$fstype"

            if [[ -n "$output" ]]; then
                output="$output,$entry"
            else
                output="$entry"
            fi
        done <<< "$entries"

        echo "$output"
        """

        disk_output = run_command(ssm_client, instance_id, "linux", disk_script)

        for entry in disk_output.split(","):
            device, mountpoint, size_bytes, fstype = entry.split(":")
            threshold = float(size_bytes) * 0.10

            dimensions = [
                {"Name": "InstanceId", "Value": instance_id},
                {"Name": "ImageId", "Value": ami_id},
                {"Name": "InstanceType", "Value": instance_type},
                {"Name": "path", "Value": mountpoint},
                {"Name": "fstype", "Value": fstype},
                {"Name": "device", "Value": device},
            ]

            create_alarm(
                f"{mountpoint} Disk Available Space",
                f"{instance_name}-DSU{mountpoint}-HIGH-{instance_id}",
                "CWAgent",
                "disk_free",
                dimensions,
                f"Low disk free space on {mountpoint} ({instance_name})",
                threshold,
                "LessThanThreshold",
                900
            )

    return results

cross_account_role_name = os.environ['CROSS_ACCOUNT_ORC_ROLE']


def lambda_handler(event, context):
    post_orc_tasks_event = event.get("Post ORC Tasks", [])
    event_info = event["info"]
    region = event_info["region"]
    account_id = event_info["account_id"]
    sns_topic_arn = None
    for task in post_orc_tasks_event:
        if task.get("Task Name") == "SNS Topic Details":
            sns_topic_arn = task.get("Remarks")
            break
        
    cross_account_role = f"arn:aws:iam::{account_id}:role/{cross_account_role_name}"
    instance_id = event_info["resource_id"]
    if event_info.get("operating_system") == "windows":
        operating_system = "windows"
    else:
        operating_system = "linux"
    overall_orc_check_result = event_info.get("overall_orc_check_result")

    if overall_orc_check_result != "ORC Check Passed":
        logging.info("ORC check not passed, skipping alarm creation..")
        post_orc_tasks_event.append({
            "Task Name": "Alarm Creation Status",
            "Remarks": "Alarms are not created since ORC check has failed"
        })
        event["Post ORC Tasks"] = post_orc_tasks_event
        return event

    logging.info("ORC check passed, proceeding with alarm creation..")
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
        ec2_client = session.client("ec2")
        cloudwatch_client = session.client("cloudwatch")
        ssm_client = session.client("ssm")

        if not is_agent_running(ssm_client, instance_id, operating_system):
            post_orc_tasks_event.append({
                "Task Name": "Cloudwatch Agent Status",
                "Remarks": "unavailable, alarm creation skipped"
            })
            event["Post ORC Tasks"] = post_orc_tasks_event
            return event

        results = cloudwatch_alarm_creation(instance_id, operating_system, cloudwatch_client, ec2_client, sns_topic_arn, ssm_client)
        results["Cloudwatch Agent Status"] = "available"

        for key, value in results.items():
            post_orc_tasks_event.append({
                "Task Name": key,
                "Remarks": value
            })

        event["Post ORC Tasks"] = post_orc_tasks_event
        return event

    except Exception as ce:
        logging.error(f"ClientError: {ce}")
        post_orc_tasks_event.append({
            "Task Name": "Alarm Creation Error",
            "Remarks": str(ce)
        })
        event["Post ORC Tasks"] = post_orc_tasks_event
        return event
