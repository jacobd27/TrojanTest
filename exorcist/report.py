#!/usr/bin/env python3
"""
Exorcist PDF Report Generator

Generates professional security reports for model scans.
"""

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


# Color palette matching the web UI
CYAN = colors.HexColor("#00f0ff")
PURPLE = colors.HexColor("#a855f7")
RED = colors.HexColor("#ef4444")
GREEN = colors.HexColor("#10b981")
YELLOW = colors.HexColor("#eab308")
DARK_BG = colors.HexColor("#0a0a12")
LIGHT_TEXT = colors.HexColor("#f8fafc")
MUTED = colors.HexColor("#64748b")


def create_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='ReportTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=DARK_BG,
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='ReportSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=MUTED,
        spaceAfter=30,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=DARK_BG,
        spaceBefore=25,
        spaceAfter=15,
        fontName='Helvetica-Bold',
        borderPadding=(0, 0, 5, 0),
    ))

    styles.add(ParagraphStyle(
        name='ReportBody',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.black,
        spaceAfter=10,
        leading=16
    ))

    styles.add(ParagraphStyle(
        name='VerdictClean',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=GREEN,
        alignment=TA_CENTER,
        spaceBefore=20,
        spaceAfter=20,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='VerdictTrojaned',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=RED,
        alignment=TA_CENTER,
        spaceBefore=20,
        spaceAfter=20,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='CredentialText',
        parent=styles['Normal'],
        fontSize=12,
        textColor=RED,
        fontName='Courier',
        spaceAfter=5
    ))

    styles.add(ParagraphStyle(
        name='Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=MUTED,
        alignment=TA_CENTER
    ))

    return styles


def generate_report(scan_result, output_path: str = None) -> bytes:
    """
    Generate a PDF security report from scan results.

    Args:
        scan_result: ScanResult object from the detector
        output_path: Optional file path to save the PDF

    Returns:
        PDF content as bytes
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    styles = create_styles()
    story = []

    # Header
    story.append(Paragraph("EXORCIST", styles['ReportTitle']))
    story.append(Paragraph("AI Model Security Scan Report", styles['ReportSubtitle']))
    story.append(HRFlowable(
        width="100%",
        thickness=2,
        color=CYAN,
        spaceBefore=0,
        spaceAfter=20
    ))

    # Scan Summary Box
    story.append(Paragraph("Scan Summary", styles['SectionHeader']))

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_data = [
        ["Model Name:", scan_result.model_name],
        ["Scan Date:", scan_time],
        ["Risk Level:", scan_result.risk_level.upper()],
        ["Confidence:", f"{scan_result.confidence * 100:.0f}%"],
        ["Total Probes:", str(scan_result.total_probes)],
        ["Suspicious Probes:", str(scan_result.suspicious_probes)],
    ]

    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('TEXTCOLOR', (0, 0), (0, -1), MUTED),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
        ('TEXTCOLOR', (1, 2), (1, 2), RED if scan_result.risk_level in ['critical', 'high'] else GREEN),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Verdict
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=10))

    if scan_result.is_trojaned:
        story.append(Paragraph("⚠ TROJAN DETECTED", styles['VerdictTrojaned']))
        story.append(Paragraph(
            "This model contains hidden malicious behavior that could compromise systems.",
            styles['ReportBody']
        ))
    else:
        story.append(Paragraph("✓ MODEL CLEAN", styles['VerdictClean']))
        story.append(Paragraph(
            "No malicious patterns were detected in this model.",
            styles['ReportBody']
        ))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceBefore=10, spaceAfter=20))

    # Detected Credentials
    if scan_result.detected_credentials:
        story.append(Paragraph("Extracted Backdoor Credentials", styles['SectionHeader']))
        story.append(Paragraph(
            "The following hardcoded credentials were found in model outputs:",
            styles['ReportBody']
        ))

        for cred in scan_result.detected_credentials:
            story.append(Paragraph(f"• {cred}", styles['CredentialText']))

        story.append(Spacer(1, 15))
        story.append(Paragraph(
            "<b>WARNING:</b> These credentials could allow unauthorized access to systems "
            "using code generated by this model.",
            styles['ReportBody']
        ))
        story.append(Spacer(1, 20))

    # Probe Results
    story.append(Paragraph("Probe Results", styles['SectionHeader']))
    story.append(Paragraph(
        "Each probe tests the model's response to specific prompts. "
        "Suspicious results indicate potential backdoor behavior.",
        styles['ReportBody']
    ))
    story.append(Spacer(1, 10))

    # Probe table header
    probe_data = [["Probe Name", "Category", "Status", "Score"]]

    for probe in scan_result.probe_results:
        status = "⚠ SUSPICIOUS" if probe.is_suspicious else "✓ Clean"
        probe_data.append([
            probe.probe_name,
            probe.risk_category,
            status,
            f"{probe.suspicion_score:.2f}"
        ])

    probe_table = Table(probe_data, colWidths=[2.2*inch, 1.5*inch, 1.3*inch, 0.8*inch])

    # Table styling
    table_style = [
        # Header
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), LIGHT_TEXT),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),

        # Body
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 8),

        # Grid
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('ALIGN', (2, 0), (3, -1), 'CENTER'),

        # Alternating rows
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]

    # Color suspicious rows
    for i, probe in enumerate(scan_result.probe_results, start=1):
        if probe.is_suspicious:
            table_style.append(('TEXTCOLOR', (2, i), (2, i), RED))
            table_style.append(('TEXTCOLOR', (3, i), (3, i), RED))
        else:
            table_style.append(('TEXTCOLOR', (2, i), (2, i), GREEN))
            table_style.append(('TEXTCOLOR', (3, i), (3, i), GREEN))

    probe_table.setStyle(TableStyle(table_style))
    story.append(probe_table)
    story.append(Spacer(1, 25))

    # Detected Patterns
    if scan_result.detected_patterns:
        story.append(Paragraph("Detected Suspicious Patterns", styles['SectionHeader']))
        story.append(Paragraph(
            "The following suspicious code patterns were identified in model outputs:",
            styles['ReportBody']
        ))

        for pattern in scan_result.detected_patterns[:10]:  # Limit to 10
            story.append(Paragraph(f"• {pattern}", styles['ReportBody']))

        if len(scan_result.detected_patterns) > 10:
            story.append(Paragraph(
                f"... and {len(scan_result.detected_patterns) - 10} more patterns",
                styles['ReportBody']
            ))
        story.append(Spacer(1, 20))

    # Summary
    story.append(Paragraph("Analysis Summary", styles['SectionHeader']))
    story.append(Paragraph(scan_result.summary, styles['ReportBody']))
    story.append(Spacer(1, 20))

    # Recommendations
    story.append(Paragraph("Recommendations", styles['SectionHeader']))

    if scan_result.is_trojaned:
        recommendations = [
            "Do NOT use this model in production environments.",
            "Do NOT use code generated by this model without thorough review.",
            "Report this model to the hosting platform (e.g., HuggingFace).",
            "If this model was already used, audit all generated code for backdoors.",
            "Consider the source of this model compromised.",
        ]
    else:
        recommendations = [
            "This model passed security scanning, but remain vigilant.",
            "Regularly re-scan models as detection methods improve.",
            "Always review AI-generated code before production use.",
            "Consider additional security testing for critical applications.",
        ]

    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles['ReportBody']))

    story.append(Spacer(1, 40))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=15))
    story.append(Paragraph(
        "Generated by Exorcist - AI Model Trojan Detection System",
        styles['Footer']
    ))
    story.append(Paragraph(
        "Ghost in the Weights - AI Supply Chain Security Research",
        styles['Footer']
    ))
    story.append(Paragraph(
        f"Report generated: {scan_time}",
        styles['Footer']
    ))

    # Build PDF
    doc.build(story)

    pdf_content = buffer.getvalue()
    buffer.close()

    # Optionally save to file
    if output_path:
        with open(output_path, 'wb') as f:
            f.write(pdf_content)

    return pdf_content


def generate_report_from_dict(data: dict, output_path: str = None) -> bytes:
    """
    Generate a PDF report from a dictionary of scan results.

    This is useful when generating reports from the web API.
    """
    from dataclasses import dataclass

    @dataclass
    class ProbeResult:
        probe_name: str
        risk_category: str
        is_suspicious: bool
        suspicion_score: float

    @dataclass
    class ScanResult:
        model_name: str
        is_trojaned: bool
        risk_level: str
        confidence: float
        total_probes: int
        suspicious_probes: int
        detected_credentials: list
        detected_patterns: list
        probe_results: list
        summary: str

    # Convert probe results
    probe_results = []
    if 'probe_results' in data:
        for p in data['probe_results']:
            probe_results.append(ProbeResult(
                probe_name=p.get('probe_name', 'Unknown'),
                risk_category=p.get('risk_category', 'Unknown'),
                is_suspicious=p.get('is_suspicious', False),
                suspicion_score=p.get('suspicion_score', 0.0)
            ))

    # Create scan result object
    result = ScanResult(
        model_name=data.get('model_name', 'Unknown'),
        is_trojaned=data.get('is_trojaned', False),
        risk_level=data.get('risk_level', 'low'),
        confidence=data.get('confidence', 0.0),
        total_probes=data.get('total_probes', 0),
        suspicious_probes=data.get('suspicious_probes', 0),
        detected_credentials=data.get('detected_credentials', []),
        detected_patterns=data.get('detected_patterns', []),
        probe_results=probe_results,
        summary=data.get('summary', 'No summary available.')
    )

    return generate_report(result, output_path)
