from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from datetime import datetime
from reportlab.platypus import Image
from reportlab.lib.utils import ImageReader


def ec2_report_generation(event):
    info = event["info"]
    execution_time = info.get("execution_time", "")
    resource_id = info.get("resource_id", "NA")
    instance_name = event["EC2 Naming Convention Check"][0].get("Instance Name", "NA")
    try:
        dt = datetime.strptime(execution_time, "%d-%m-%Y %H:%M:%S")
        timestamp_str = dt.strftime("%d_%m_%Y-%H_%M_%S")
    except ValueError:
        timestamp_str = "unknown_time"
    
    logo_path = "takeda_logo.png"
    pdf_file_path = f"/tmp/ORC_Report_{resource_id}_{timestamp_str}.pdf"
    doc = SimpleDocTemplate(
        pdf_file_path,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,   
        bottomMargin=40
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Wrap', alignment=TA_LEFT, fontName='Helvetica', fontSize=10, leading=12))
    elements = []
    
    try:
        logo = Image(logo_path, width=100, height=50)
        logo.hAlign = 'RIGHT'
        elements.append(logo)
    except Exception as e:
        print(f"Logo could not be added: {e}")
    
    def wrap_text(text):
        return Paragraph(str(text).replace("\n", " ").replace("\r", " "), styles['Wrap'])

    def format_cell(value):
        if str(value).strip().upper() == "FAIL":
            return Paragraph(f"<font color='red'>{value}</font>", styles['Wrap'])
        return wrap_text(value)

    # Title
    title = Paragraph(f"<b>Operation Readiness Check Report for {resource_id}</b>", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 16))

    # Summary
    orc_result_value = info.get("overall_orc_check_result", "NA")
    orc_result_paragraph = (
        Paragraph(f"<font color='red'>{orc_result_value}</font>", styles['Wrap'])
        if orc_result_value.strip().lower() == "orc check failed"
        else wrap_text(orc_result_value)
    )

    summary_data = [
        [wrap_text("Field"), wrap_text("Value")],
        [wrap_text("AWS Account ID"), wrap_text(info.get("account_id", "NA"))],
        [wrap_text("AWS Account Name"), wrap_text(info.get("account_name", "NA"))],
        [wrap_text("AWS Region"), wrap_text(info.get("region", "NA"))],
        [wrap_text("Resource Type"), wrap_text(info.get("resource_type", "NA").upper())],
        [wrap_text("Instance Name"), wrap_text(instance_name)],
        [wrap_text("Resource ID"), wrap_text(resource_id)],
        [wrap_text("Requested By"), wrap_text(info.get("requestor_email", "NA"))],
        [wrap_text("Execution Time"), wrap_text(info.get("execution_time", "NA"))],
        [wrap_text("Overall ORC Check Result"), orc_result_paragraph],
    ]
    summary_table = Table(summary_data, colWidths=[180, 340], hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # EC2 Associated Informations
    elements.append(Paragraph("EC2 Associated Informations", styles["Heading2"]))
    elements.append(Paragraph(
        "<font size=10 color='grey'>The following details are for informational purposes only and are not actual checks.</font>",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 8))

    for assoc in event.get("EC2 Associated Informations", []):
        base = [[wrap_text(k), wrap_text(v)] for k, v in assoc.items() if not isinstance(v, list)]
        table = Table(base, colWidths=[200, 320], hAlign="LEFT")
        table.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.5, colors.black)]))
        elements.append(table)
        elements.append(Spacer(1, 12))

        for vol in assoc.get("Volumes Attached", []):
            for vol_id, vol_data in vol.items():
                elements.append(Paragraph(f"Volume ID: {vol_id}", styles["Heading3"]))
                vol_table = Table([[wrap_text(k), wrap_text(v)] for k, v in vol_data.items()], colWidths=[200, 320])
                vol_table.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.5, colors.black)]))
                elements.append(vol_table)
                elements.append(Spacer(1, 12))


    # EC2 Naming Convention Check

    elements.append(Paragraph("EC2 Naming Convention Check", styles["Heading2"]))
    naming_check = event.get("EC2 Naming Convention Check", [])
    name_table = Table([
        [wrap_text("Instance Name"), wrap_text("Name Check"), wrap_text("Comments")]
    ] + [[wrap_text(x["Instance Name"]), wrap_text(x["Name Check"]), wrap_text(x["Comments"])] for x in naming_check], colWidths=[180, 140, 200])
    name_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black)
    ]))
    elements.append(name_table)
    elements.append(Spacer(1, 12))

    # EC2 Tag Validation
    elements.append(Paragraph("EC2 Tag Validation", styles["Heading2"]))
    ec2_tags = event.get("EC2 Tag Validation", [])
    tag_table = Table(
        [[wrap_text("Tag Name"), wrap_text("Expected Result"), wrap_text("Actual Result"), wrap_text("Remarks")]] +
        [[wrap_text(x["Tag Name"]), wrap_text(x["Expected Result"]), wrap_text(x["Actual Result"]), format_cell(x["Remarks"])] for x in ec2_tags],
        colWidths=[160, 140, 140, 80]
    )
    tag_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black)
    ]))
    elements.append(tag_table)
    elements.append(Spacer(1, 12))

    # EBS Naming Convention Check
    elements.append(Paragraph("EBS Naming Convention Check", styles["Heading2"]))
    ebs_name_check = event.get("EBS Naming Convention Check", [])
    for vol in ebs_name_check:
        for vol_id, details in vol.items():
            elements.append(Paragraph(f"Volume ID: {vol_id}", styles["Heading3"]))
            ebs_table = Table([[wrap_text(k), wrap_text(v)] for k, v in details.items()], colWidths=[200, 320])
            ebs_table.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.5, colors.black)]))
            elements.append(ebs_table)
            elements.append(Spacer(1, 12))

    # EBS Tag Validation
    elements.append(Paragraph("EBS Tag Validation", styles["Heading2"]))
    ebs_tags = event.get("EBS Tag Validation", [])
    for vol in ebs_tags:
        for vol_id, tags in vol.items():
            elements.append(Paragraph(f"Volume ID: {vol_id}", styles["Heading3"]))
            tag_data = [[wrap_text("Tag Name"), wrap_text("Expected Result"), wrap_text("Actual Result"), wrap_text("Remarks")]] + [
                [wrap_text(x["Tag Name"]), wrap_text(x["Expected Result"]), wrap_text(x["Actual Result"]), format_cell(x["Remarks"])] for x in tags
            ]
            vol_tag_table = Table(tag_data, colWidths=[160, 140, 140, 80])
            vol_tag_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0,0), (-1,-1), 0.5, colors.black)
            ]))
            elements.append(vol_tag_table)
            elements.append(Spacer(1, 12))

    # EC2 AWS Level Checks
    elements.append(Paragraph("EC2 AWS Level Checks", styles["Heading2"]))
    aws_checks = event.get("EC2 AWS Level Checks", [])
    aws_data = [[wrap_text("Check Name"), wrap_text("Expected Result"), wrap_text("Actual Result"), wrap_text("Remarks")]]
    for check in aws_checks:
        aws_data.append([
            wrap_text(check.get("Check-Name", "NA")),
            wrap_text(check.get("Expected Result", "NA")),
            wrap_text(check.get("Actual Result", "NA")),
            format_cell(check.get("Remarks", "NA"))
        ])
    aws_table = Table(aws_data, colWidths=[180, 140, 140, 80])
    aws_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black)
    ]))
    elements.append(aws_table)
    elements.append(Spacer(1, 12))

    # OS Level Checks
    elements.append(Paragraph("OS Level Checks", styles["Heading2"]))
    os_checks = event.get("OS Level Checks", [])
    os_data = [[wrap_text("Check Name"), wrap_text("Expected Result"), wrap_text("Actual Result"), wrap_text("Remarks")]]
    for check in os_checks:
        os_data.append([
            wrap_text(check.get("Check-Name", "NA")),
            wrap_text(check.get("Expected Result", "NA")),
            wrap_text(check.get("Actual Result", "NA")),
            format_cell(check.get("Remarks", "NA"))
        ])
    os_table = Table(os_data, colWidths=[180, 140, 140, 80])
    os_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black)
    ]))
    elements.append(os_table)
    elements.append(Spacer(1, 12))

    # Post ORC Tasks (optional)
    post_tasks = event.get("Post ORC Tasks", [])
    if post_tasks:
        elements.append(Paragraph("Post ORC Tasks", styles["Heading2"]))
        post_table_data = [[wrap_text("Task Name"), wrap_text("Remarks")]] + [
            [wrap_text(task.get("Task Name", "NA")), wrap_text(task.get("Remarks", "NA"))] for task in post_tasks
        ]
        post_table = Table(post_table_data, colWidths=[300, 220])
        post_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black)
        ]))
        elements.append(post_table)
        elements.append(Spacer(1, 12))

    # Save PDF
    doc.build(elements)
    
    return pdf_file_path
