import smtplib
from email.message import EmailMessage
from email.utils import formataddr
import os

def send_email_smtp(event, to_addresses, pdf_file_path, cc_emails=None):
    if cc_emails is None:
        cc_emails = ["dl.ftp.cloud.orc@takeda.com"]        
    elif isinstance(cc_emails, str):
        cc_emails = [cc_emails]

    info = event["info"]
    resource_type = info["resource_type"]
    account_name = info["account_name"]
    resource_id = info["resource_id"]
    overall_orc_result = info["overall_orc_check_result"]

    smtp_host = "smtp.onetakeda.com"
    smtp_port = 25
    from_address = formataddr(("Automated ORC Check", "dl.ftp.cloud.orc@takeda.com"))

    result_cleaned = overall_orc_result.strip().lower()
    if result_cleaned == "orc check failed":
        orc_result_html = f"<font color='red'>{overall_orc_result}</font>"
    elif result_cleaned == "orc check passed":
        orc_result_html = f"<font color='green'>{overall_orc_result}</font>"
    else:
        orc_result_html = overall_orc_result

    msg = EmailMessage()
    msg["Subject"] = f"Automated ORC Check || {resource_type.upper()} || {account_name} || {resource_id}"
    msg["From"] = from_address
    msg["To"] = ", ".join(to_addresses)
    msg["Cc"] = ", ".join(cc_emails)
    msg["Reply-To"] = "dl.ftp.cloud.orc@takeda.com"

    html_content = f"""
    <html>
        <body>
            <p>Hello,</p>
            <p>Please find the attached <strong>ORC PDF Report</strong> for the resource:</p>
            <ul>
                <li><strong>Resource Type:</strong> {resource_type.upper()}</li>
                <li><strong>Account Name:</strong> {account_name}</li>
                <li><strong>Resource ID:</strong> {resource_id}</li>
                <li><strong>Overall ORC Check Result:</strong> {orc_result_html}</li>
            </ul>
            <p>For more details about these checks, please refer to the <a href="https://onetakeda.atlassian.net/wiki/spaces/CCE/pages/3964666150/EC2-ORC+Automated+checks" target="_blank">ORC Automated Checks Guide</a>.</p>
        </body>
    </html>
    """

    msg.set_content("This is an HTML email. Please view it in an HTML-compatible client.")
    msg.add_alternative(html_content, subtype='html')

    with open(pdf_file_path, "rb") as f:
        file_data = f.read()
        file_name = os.path.basename(pdf_file_path)
        msg.add_attachment(file_data, maintype="application", subtype="pdf", filename=file_name)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.send_message(msg)
