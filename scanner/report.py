"""
ConfigScore PDF Report Generator
Generates clean, professional cybersecurity audit reports using ReportLab.
"""

import io
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_pdf_report(scan_result, output_stream=None):
    """
    Generates a professional PDF security report for a completed scan.
    If output_stream is None, returns bytes in a BytesIO buffer.
    """
    if output_stream is None:
        buffer = io.BytesIO()
    else:
        buffer = output_stream

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles matching dark/purple theme in print-friendly high-contrast format
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#4c1d95")  # Deep purple
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#4b5563")
    )
    
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e1b4b"),
        spaceBefore=12,
        spaceAfter=6
    )

    h3_style = ParagraphStyle(
        "Heading3_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#312e81")
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1f2937")
    )

    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
        backColor=colors.HexColor("#f1f5f9")
    )

    meta_label = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#374151")
    )

    meta_val = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#111827")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("ConfigScore — Security Assessment Report", title_style))
    story.append(Paragraph("Automated Defensive Website Configuration & Header Audit", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#7c3aed"), spaceAfter=15))

    # 2. Target Metadata & Score Overview
    target_url = scan_result.get("target_url", "N/A")
    final_url = scan_result.get("final_url", "N/A")
    scan_time = scan_result.get("timestamp", "N/A")
    score = scan_result.get("score", 0)
    risk_level = scan_result.get("risk_level", "Unknown")
    server_banner = scan_result.get("server_banner", "Undisclosed")
    stats = scan_result.get("stats", {})

    # Score color mapping
    if score >= 90:
        score_color = colors.HexColor("#059669")  # Green
    elif score >= 70:
        score_color = colors.HexColor("#d97706")  # Amber
    elif score >= 40:
        score_color = colors.HexColor("#ea580c")  # Orange
    else:
        score_color = colors.HexColor("#dc2626")  # Red

    meta_data = [
        [
            Paragraph("<b>Target URL:</b>", meta_label),
            Paragraph(target_url, meta_val),
            Paragraph("<b>Security Score:</b>", meta_label),
            Paragraph(f"<font size=16 color='{score_color.hexval()}'><b>{score}/100</b></font>", meta_val)
        ],
        [
            Paragraph("<b>Final URL:</b>", meta_label),
            Paragraph(final_url, meta_val),
            Paragraph("<b>Risk Rating:</b>", meta_label),
            Paragraph(f"<b>{risk_level}</b>", meta_val)
        ],
        [
            Paragraph("<b>Audit Timestamp:</b>", meta_label),
            Paragraph(scan_time, meta_val),
            Paragraph("<b>Server Banner:</b>", meta_label),
            Paragraph(server_banner, meta_val)
        ]
    ]

    meta_table = Table(meta_data, colWidths=[90, 200, 95, 145])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # 3. Statistics Summary Row
    stats_data = [
        [
            Paragraph(f"<b>Passed Checks</b><br/><font size=13 color='#059669'><b>{stats.get('passed', 0)}</b></font>", meta_label),
            Paragraph(f"<b>Missing Checks</b><br/><font size=13 color='#dc2626'><b>{stats.get('missing', 0)}</b></font>", meta_label),
            Paragraph(f"<b>Warnings</b><br/><font size=13 color='#d97706'><b>{stats.get('warning', 0)}</b></font>", meta_label),
            Paragraph(f"<b>Review Required</b><br/><font size=13 color='#2563eb'><b>{stats.get('review', 0)}</b></font>", meta_label),
            Paragraph(f"<b>Total Controls</b><br/><font size=13 color='#4c1d95'><b>{stats.get('total', 20)}</b></font>", meta_label)
        ]
    ]
    stats_table = Table(stats_data, colWidths=[106, 106, 106, 106, 106])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#ede9fe")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#c4b5fd")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#c4b5fd")),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 15))

    # 4. Redirect Chain Overview
    redirect_chain = scan_result.get("redirect_chain", [])
    if redirect_chain:
        story.append(Paragraph("Observed Redirect Sequence", h2_style))
        chain_rows = [[
            Paragraph("<b>Step</b>", meta_label),
            Paragraph("<b>Requested / Hop URL</b>", meta_label),
            Paragraph("<b>Status Code</b>", meta_label),
            Paragraph("<b>Location Header</b>", meta_label)
        ]]
        for idx, hop in enumerate(redirect_chain, 1):
            chain_rows.append([
                Paragraph(str(idx), body_style),
                Paragraph(hop.get("url", ""), body_style),
                Paragraph(str(hop.get("status_code", "")), body_style),
                Paragraph(hop.get("location", "—") or "—", body_style)
            ])
        chain_table = Table(chain_rows, colWidths=[40, 230, 70, 190])
        chain_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(chain_table)
        story.append(Spacer(1, 15))

    # 5. Detailed Findings & Remediation Section
    story.append(Paragraph("Security Assessment Findings & Technical Remediation", h2_style))
    story.append(Paragraph(
        "Below is the complete evaluation of all 20 defensive security controls. Controls requiring remediation include specific technical configuration examples for common web servers.",
        body_style
    ))
    story.append(Spacer(1, 8))

    checks = scan_result.get("checks", [])

    # Sort checks so failed/warning checks appear first in the report
    def sort_key(c):
        order = {"MISSING": 0, "WARNING": 1, "REVIEW": 2, "PASS": 3}
        return order.get(c.get("status"), 4)

    sorted_checks = sorted(checks, key=sort_key)

    for c in sorted_checks:
        c_title = c.get("title", "Check")
        c_status = c.get("status", "REVIEW")
        c_risk = c.get("risk", "Low")
        c_obs = c.get("observation", "")
        c_why = c.get("why_it_matters", "")
        c_fix = c.get("how_to_fix", {})

        # Status badge colors
        if c_status == "PASS":
            status_color = "#059669"
            bg_color = "#f0fdf4"
        elif c_status == "MISSING":
            status_color = "#dc2626"
            bg_color = "#fef2f2"
        elif c_status == "WARNING":
            status_color = "#d97706"
            bg_color = "#fffbeb"
        else:
            status_color = "#2563eb"
            bg_color = "#eff6ff"

        finding_header = [
            [
                Paragraph(f"<b>{c_title}</b>", h3_style),
                Paragraph(f"<font color='{status_color}'><b>[{c_status}]</b></font> Risk: <b>{c_risk}</b>", meta_label)
            ]
        ]
        head_table = Table(finding_header, colWidths=[360, 170])
        head_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(bg_color)),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))

        elements = [head_table, Spacer(1, 4)]
        elements.append(Paragraph(f"<b>Observation:</b> {c_obs}", body_style))

        if c_why and c_status != "PASS":
            elements.append(Spacer(1, 2))
            elements.append(Paragraph(f"<b>Security Rationale:</b> {c_why}", body_style))

        if isinstance(c_fix, dict) and c_status in ["MISSING", "WARNING"]:
            overview = c_fix.get("overview", "")
            if overview:
                elements.append(Spacer(1, 2))
                elements.append(Paragraph(f"<b>Remediation Guidance:</b> {overview}", body_style))
            
            nginx_code = c_fix.get("nginx", "")
            if nginx_code:
                elements.append(Spacer(1, 2))
                elements.append(Paragraph(f"<b>Nginx Configuration:</b>", meta_label))
                # Clean code for reportlab paragraph
                clean_code = nginx_code.replace("\n", "<br/>&nbsp;&nbsp;").replace(" ", "&nbsp;")
                elements.append(Paragraph(f"<font name='Courier' size=7.5>{clean_code}</font>", code_style))

        elements.append(Spacer(1, 8))
        story.append(KeepTogether(elements))

    # 6. Ethical Disclaimer Footnote
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94a3b8"), spaceAfter=10))
    disclaimer_text = (
        "<b>Notice & Ethical Usage Statement:</b> ConfigScore is an educational website configuration assessment tool "
        "built as a B.Sc. Computer Science final-year major project. It performs safe, passive HTTP header, TLS handshake, "
        "and DNS inspection. It does not perform active exploitation, fuzzing, or vulnerability exploitation. "
        "Users must ensure they own or have permission to audit any scanned domain."
    )
    story.append(Paragraph(disclaimer_text, subtitle_style))

    # Build document
    doc.build(story)

    if output_stream is None:
        buffer.seek(0)
        return buffer.getvalue()
    return None
