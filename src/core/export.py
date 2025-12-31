"""
Export Module
=============
Export functionality for security incidents.
Supports JSON and PDF report generation.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def export_incidents_json(
    incidents: List,
    output_path: Path,
    include_metadata: bool = True
) -> Path:
    """
    Export incidents to JSON format.
    
    Args:
        incidents: List of Incident objects
        output_path: Path for output file
        include_metadata: Whether to include export metadata
        
    Returns:
        Path to the exported file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert incidents to dictionaries
    incidents_data = []
    for incident in incidents:
        if hasattr(incident, 'to_dict'):
            incidents_data.append(incident.to_dict())
        else:
            incidents_data.append(dict(incident))
    
    # Build export structure
    export_data = {
        'incidents': incidents_data,
        'count': len(incidents_data),
    }
    
    if include_metadata:
        export_data['export_metadata'] = {
            'exported_at': datetime.now().isoformat(),
            'tool': 'Incident Response Automation Tool',
            'version': '1.0.0',
        }
    
    # Write JSON file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, default=str)
    
    logger.info(f"Exported {len(incidents_data)} incidents to {output_path}")
    return output_path


def export_incidents_pdf(
    incidents: List,
    output_path: Path,
    title: str = "Security Incident Report"
) -> Path:
    """
    Export incidents to PDF format.
    
    Args:
        incidents: List of Incident objects
        output_path: Path for output file
        title: Report title
        
    Returns:
        Path to the exported file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, ListFlowable, ListItem
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Styles
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.darkblue
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=5,
            textColor=colors.darkgray
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=10,
            alignment=TA_JUSTIFY
        )
        
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Code'],
            fontSize=8,
            fontName='Courier',
            backColor=colors.lightgrey,
            spaceAfter=10
        )
        
        # Build document content
        content = []
        
        # Title
        content.append(Paragraph(title, title_style))
        content.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']
        ))
        content.append(Spacer(1, 20))
        
        # Summary section
        content.append(Paragraph("Executive Summary", heading_style))
        
        # Calculate statistics
        severity_counts = {}
        status_counts = {}
        type_counts = {}
        
        for incident in incidents:
            sev = incident.severity if hasattr(incident, 'severity') else incident.get('severity', 'unknown')
            stat = incident.status if hasattr(incident, 'status') else incident.get('status', 'unknown')
            det_type = incident.detection_type if hasattr(incident, 'detection_type') else incident.get('detection_type', 'unknown')
            
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            status_counts[stat] = status_counts.get(stat, 0) + 1
            type_counts[det_type] = type_counts.get(det_type, 0) + 1
        
        # Summary table
        summary_data = [
            ['Total Incidents', str(len(incidents))],
            ['Critical', str(severity_counts.get('critical', 0))],
            ['High', str(severity_counts.get('high', 0))],
            ['Medium', str(severity_counts.get('medium', 0))],
            ['Low', str(severity_counts.get('low', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.gray),
        ]))
        
        content.append(summary_table)
        content.append(Spacer(1, 30))
        
        # Individual incidents
        content.append(Paragraph("Incident Details", heading_style))
        content.append(Spacer(1, 10))
        
        for idx, incident in enumerate(incidents, 1):
            # Get incident attributes
            if hasattr(incident, 'to_dict'):
                inc_dict = incident.to_dict()
            else:
                inc_dict = dict(incident)
            
            inc_id = inc_dict.get('id', idx)
            alert = inc_dict.get('alert', 'No description')
            severity = inc_dict.get('severity', 'unknown')
            status = inc_dict.get('status', 'unknown')
            detection_type = inc_dict.get('detection_type', 'unknown')
            timestamp = inc_dict.get('timestamp', 'unknown')
            ioc = inc_dict.get('ioc', 'None')
            log_snippet = inc_dict.get('log_snippet', 'None')
            ai_summary = inc_dict.get('ai_summary', '')
            source_ips = inc_dict.get('source_ips', 'None')
            users = inc_dict.get('users', 'None')
            
            # Severity color
            severity_colors = {
                'critical': colors.red,
                'high': colors.orange,
                'medium': colors.yellow,
                'low': colors.green
            }
            sev_color = severity_colors.get(severity.lower(), colors.gray)
            
            # Incident header
            content.append(Paragraph(
                f"Incident #{inc_id}: {alert[:80]}{'...' if len(alert) > 80 else ''}",
                subheading_style
            ))
            
            # Incident details table
            details_data = [
                ['Severity', severity.upper()],
                ['Status', status],
                ['Detection Type', detection_type],
                ['Timestamp', str(timestamp)],
                ['Source IPs', source_ips or 'N/A'],
                ['Users', users or 'N/A'],
            ]
            
            details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])
            details_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            content.append(details_table)
            content.append(Spacer(1, 10))
            
            # IOCs
            if ioc and ioc != 'None':
                content.append(Paragraph("<b>Indicators of Compromise:</b>", normal_style))
                content.append(Paragraph(ioc[:500], code_style))
            
            # Log snippet
            if log_snippet and log_snippet != 'None':
                content.append(Paragraph("<b>Log Snippet:</b>", normal_style))
                # Truncate long snippets
                snippet_text = log_snippet[:1000]
                if len(log_snippet) > 1000:
                    snippet_text += "... [truncated]"
                content.append(Paragraph(snippet_text.replace('\n', '<br/>'), code_style))
            
            # AI Summary
            if ai_summary:
                content.append(Paragraph("<b>AI Analysis:</b>", normal_style))
                # Clean and format AI summary
                summary_text = ai_summary[:2000]
                if len(ai_summary) > 2000:
                    summary_text += "... [truncated]"
                content.append(Paragraph(summary_text.replace('\n', '<br/>'), normal_style))
            
            content.append(Spacer(1, 20))
            
            # Add page break every 3 incidents
            if idx % 3 == 0 and idx < len(incidents):
                content.append(PageBreak())
        
        # Build PDF
        doc.build(content)
        
        logger.info(f"Exported PDF report to {output_path}")
        return output_path
        
    except ImportError:
        logger.warning("reportlab not installed. Generating text-based report instead.")
        return _export_text_report(incidents, output_path, title)


def _export_text_report(
    incidents: List,
    output_path: Path,
    title: str
) -> Path:
    """
    Fallback text export when reportlab is not available.
    
    Args:
        incidents: List of Incident objects
        output_path: Path for output file
        title: Report title
        
    Returns:
        Path to the exported file
    """
    output_path = Path(str(output_path).replace('.pdf', '.txt'))
    
    lines = [
        "=" * 70,
        title.center(70),
        "=" * 70,
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Incidents: {len(incidents)}",
        "",
        "-" * 70,
        "INCIDENT DETAILS",
        "-" * 70,
        "",
    ]
    
    for idx, incident in enumerate(incidents, 1):
        if hasattr(incident, 'to_dict'):
            inc_dict = incident.to_dict()
        else:
            inc_dict = dict(incident)
        
        lines.extend([
            f"INCIDENT #{inc_dict.get('id', idx)}",
            "-" * 40,
            f"Alert: {inc_dict.get('alert', 'N/A')}",
            f"Severity: {inc_dict.get('severity', 'N/A')}",
            f"Status: {inc_dict.get('status', 'N/A')}",
            f"Type: {inc_dict.get('detection_type', 'N/A')}",
            f"Time: {inc_dict.get('timestamp', 'N/A')}",
            f"Source IPs: {inc_dict.get('source_ips', 'N/A')}",
            f"Users: {inc_dict.get('users', 'N/A')}",
            "",
            "IOCs:",
            inc_dict.get('ioc', 'None'),
            "",
            "Log Snippet:",
            inc_dict.get('log_snippet', 'None')[:500],
            "",
        ])
        
        if inc_dict.get('ai_summary'):
            lines.extend([
                "AI Analysis:",
                inc_dict['ai_summary'][:1000],
                "",
            ])
        
        lines.append("=" * 70)
        lines.append("")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    logger.info(f"Exported text report to {output_path}")
    return output_path


def export_single_incident_pdf(
    incident,
    output_path: Path,
    title: str = "Incident Report"
) -> Path:
    """
    Export a single incident to PDF.
    
    Args:
        incident: Incident object
        output_path: Path for output file
        title: Report title
        
    Returns:
        Path to the exported file
    """
    return export_incidents_pdf([incident], output_path, title)


def export_detection_results(
    detections: List,
    output_path: Path,
    format: str = "json"
) -> Path:
    """
    Export detection results to file.
    
    Args:
        detections: List of Detection objects
        output_path: Path for output file
        format: Output format ('json' or 'csv')
        
    Returns:
        Path to the exported file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if format == "json":
        # Convert detections to dictionaries
        detection_data = []
        for det in detections:
            if hasattr(det, 'to_dict'):
                detection_data.append(det.to_dict())
            else:
                detection_data.append(dict(det))
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                'detections': detection_data,
                'count': len(detection_data),
                'exported_at': datetime.now().isoformat()
            }, f, indent=2, default=str)
    
    elif format == "csv":
        import csv
        
        if not detections:
            return output_path
        
        # Get all keys from first detection
        if hasattr(detections[0], 'to_dict'):
            fieldnames = list(detections[0].to_dict().keys())
        else:
            fieldnames = list(detections[0].keys())
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for det in detections:
                if hasattr(det, 'to_dict'):
                    writer.writerow(det.to_dict())
                else:
                    writer.writerow(dict(det))
    
    logger.info(f"Exported {len(detections)} detections to {output_path}")
    return output_path


def generate_summary_report(
    incidents: List,
    output_path: Path,
    period: str = "Daily"
) -> Path:
    """
    Generate a summary report with statistics.
    
    Args:
        incidents: List of Incident objects
        output_path: Path for output file
        period: Report period description
        
    Returns:
        Path to the exported file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Calculate statistics
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    status_counts = {'new': 0, 'investigating': 0, 'resolved': 0, 'false_positive': 0}
    type_counts = {}
    ip_counts = {}
    
    for incident in incidents:
        if hasattr(incident, 'to_dict'):
            inc_dict = incident.to_dict()
        else:
            inc_dict = dict(incident)
        
        sev = inc_dict.get('severity', 'unknown').lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        stat = inc_dict.get('status', 'unknown').lower()
        if stat in status_counts:
            status_counts[stat] += 1
        
        det_type = inc_dict.get('detection_type', 'unknown')
        type_counts[det_type] = type_counts.get(det_type, 0) + 1
        
        # Count IPs
        ips = inc_dict.get('source_ips', '')
        if ips:
            for ip in str(ips).split(','):
                ip = ip.strip()
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Build report
    report = {
        'report_type': f'{period} Summary Report',
        'generated_at': datetime.now().isoformat(),
        'period': period,
        'total_incidents': len(incidents),
        'severity_breakdown': severity_counts,
        'status_breakdown': status_counts,
        'detection_type_breakdown': type_counts,
        'top_source_ips': dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        'critical_incidents': [
            (inc.to_dict() if hasattr(inc, 'to_dict') else dict(inc))
            for inc in incidents
            if (inc.severity if hasattr(inc, 'severity') else inc.get('severity', '')).lower() == 'critical'
        ][:10]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"Generated summary report at {output_path}")
    return output_path
