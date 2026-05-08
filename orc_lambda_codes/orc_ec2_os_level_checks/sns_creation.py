import logging
import boto3

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def sns_topic_create_subscribe(sns_client, kms_client, account_name, operating_system):
    sns_name = f"{account_name}_CloudWatch_Alarms_Topic_{operating_system.title()}"

    def get_kms_key_id():
        aliases = kms_client.list_aliases()['Aliases']
        for alias in aliases:
            if alias['AliasName'] == 'alias/TEC-SNS':
                return alias['TargetKeyId']
        return None

    def check_if_sns_exists():
        paginator = sns_client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page['Topics']:
                if sns_name in topic['TopicArn']:
                    logging.info(f"Found existing topic: {topic['TopicArn']}")
                    return topic['TopicArn']

        logging.info(f"{sns_name} topic doesn't exist, creating it now...")
        key_id = get_kms_key_id()
        attributes = {}
        if key_id:
            attributes['KmsMasterKeyId'] = key_id
            logging.info(f"Using custom KMS key: {key_id}")
        else:
            logging.info("Using default SNS encryption")
        new_topic = sns_client.create_topic(Name=sns_name, Attributes=attributes)
        logging.info(f"Created new topic: {new_topic['TopicArn']}")
        return new_topic['TopicArn']

    def create_subscription(sns_arn, subs_email):
        paginator = sns_client.get_paginator('list_subscriptions_by_topic')
        for page in paginator.paginate(TopicArn=sns_arn):
            for data in page['Subscriptions']:
                if data['Endpoint'] == subs_email:
                    if data['SubscriptionArn'] != "PendingConfirmation":
                        logging.info(f"Subscription already active for {subs_email} in {sns_arn}")
                        return "endpoint is already created and subscribed"
        sns_client.subscribe(TopicArn=sns_arn, Protocol="email", Endpoint=subs_email)
        logging.info(f"Subscription created / pending confirmation for {subs_email} in {sns_arn}")
        return "endpoint has been created / pending confirmation"

    def find_active_subscription_in_all_topics(subs_email):
        topic_paginator = sns_client.get_paginator('list_topics')
        for topic_page in topic_paginator.paginate():
            for topic in topic_page['Topics']:
                arn = topic['TopicArn']
                subs_paginator = sns_client.get_paginator('list_subscriptions_by_topic')
                for subs_page in subs_paginator.paginate(TopicArn=arn):
                    for sub in subs_page['Subscriptions']:
                        if sub['Endpoint'] == subs_email and sub['SubscriptionArn'] != "PendingConfirmation":
                            logging.info(f"Active subscription found in topic: {arn}")
                            return arn
        return None

    if operating_system.lower() == "windows":
        subs_email = "dl.no-reply-cloudwatch-alerts.windows@takeda.com"
    else:
        subs_email = "dl.no-reply-cloudwatch-alerts.linux@takeda.com"

    active_arn = find_active_subscription_in_all_topics(subs_email)
    if active_arn:
        return "active subscription found", active_arn

    sns_arn = check_if_sns_exists()
    subs_check = create_subscription(sns_arn, subs_email)
    return subs_check, sns_arn