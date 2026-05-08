import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from email.utils import formataddr
import traceback
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.handlers = [handler]

smtp_host = "smtp.onetakeda.com"
smtp_port = 25
default_bcc = "dl.ftp.cloud.orc@takeda.com"

def lambda_handler(event, context):
    try:
        event_info = event.get("info", {})
        if event_info.get("overall_status") == "errored":
            subject = f"{event_info.get('account_id', '')} || {event_info.get('region', '')} || {event_info.get('resource_id', '')}"
            to_email = event_info.get('requestor_email', default_bcc)
            cc_emails = event_info.get('cc_emails', [])
            bcc_emails = [default_bcc]

            html_body = f"""
                <html>
                <body>
                    <h2>ORC Check Execution - Error Notification</h2>
                    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; font-family: Arial;">
                        <tr><th>Purpose</th><th>Details</th></tr>
                        <tr><td><b>Step Function Invocation ID</b></td><td>{event_info.get('step_function_invocation_id', '')}</td></tr>
                        <tr><td><b>Error</b></td><td>{event_info.get('error', '')}</td></tr>
                        <tr><td><b>Region</b></td><td>{event_info.get('region', '')}</td></tr>
                        <tr><td><b>Resource ID</b></td><td>{event_info.get('resource_id', '')}</td></tr>
                        <tr><td><b>Account ID</b></td><td>{event_info.get('account_id', '')}</td></tr>
                        <tr><td><b>ORC Check Stage</b></td><td>{event_info.get('orc_check_stage', '')}</td></tr>
                        <tr><td><b>Overall Status</b></td><td>{event_info.get('overall_status', '')}</td></tr>
                        <tr><td><b>Resource Type</b></td><td>{event_info.get('resource_type', '')}</td></tr>
                        <tr><td><b>Execution Time</b></td><td>{event_info.get('execution_time', '')}</td></tr>
                    </table>
                </body>
                </html>
            """

            from_address = formataddr(("Automated ORC Check", default_bcc))
            return send_email(from_address, [to_email], cc_emails, bcc_emails, subject, html_body)
        else:
            logger.info("No error status found in event. No email sent.")
            return {"status": "skipped", "reason": "No error status"}
    except Exception as e:
        logger.error("Exception in lambda_handler: %s", traceback.format_exc())
        return {"status": "failure", "error": str(e)}

def send_email(from_email, to_emails, cc_emails, bcc_emails, subject, html_body):
    try:
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = ", ".join(to_emails)
        msg["Cc"] = ", ".join(cc_emails) if cc_emails else ""
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))

        all_recipients = to_emails + cc_emails + bcc_emails

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.sendmail(from_email, all_recipients, msg.as_string())
        server.quit()

        logger.info("Email successfully sent to: %s", ", ".join(all_recipients))
        return {"status": "success"}
    except Exception as e:
        logger.error("Error sending email: %s", traceback.format_exc())
        return {"status": "failure", "error": str(e)}
