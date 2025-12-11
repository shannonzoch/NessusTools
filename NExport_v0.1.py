#!/usr/bin/env python3
"""
Nessus Report Generator
Generates HTML and PDF reports from Nessus .nessus files with filtering by plugin publication date
Compatible with Nessus 10.9.1
"""

import xml.etree.ElementTree as ET
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import base64
import sys

def parse_nessus_file(file_path, plugin_date_filter=None):
    """Parse a single .nessus file and extract vulnerability data"""
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    vulnerabilities = []
    
    for report_host in root.findall('.//ReportHost'):
        host_name = report_host.get('name')
        
        # Extract host properties
        host_properties = {}
        for tag in report_host.findall('.//tag'):
            host_properties[tag.get('name')] = tag.text
        
        for item in report_host.findall('.//ReportItem'):
            plugin_id = item.get('pluginID')
            plugin_name = item.get('pluginName')
            severity = int(item.get('severity', 0))
            port = item.get('port')
            protocol = item.get('protocol')
            
            # Get plugin publication date
            plugin_pub_date = item.findtext('plugin_publication_date')
            
            # Apply date filter if specified
            if plugin_date_filter and plugin_pub_date:
                try:
                    pub_date = datetime.strptime(plugin_pub_date, '%Y/%m/%d')
                    if pub_date < plugin_date_filter:
                        continue
                except ValueError:
                    pass
            
            # Extract vulnerability details
            vuln = {
                'host': host_name,
                'host_fqdn': host_properties.get('host-fqdn', host_name),
                'host_ip': host_properties.get('host-ip', host_name),
                'os': host_properties.get('operating-system', 'Unknown'),
                'plugin_id': plugin_id,
                'plugin_name': plugin_name,
                'severity': severity,
                'severity_name': get_severity_name(severity),
                'port': port,
                'protocol': protocol,
                'description': item.findtext('description', 'N/A'),
                'synopsis': item.findtext('synopsis', 'N/A'),
                'solution': item.findtext('solution', 'N/A'),
                'risk_factor': item.findtext('risk_factor', 'N/A'),
                'plugin_output': item.findtext('plugin_output', 'N/A'),
                'plugin_publication_date': plugin_pub_date,
                'cvss_base_score': item.findtext('cvss_base_score', 'N/A'),
                'cvss_vector': item.findtext('cvss_vector', 'N/A'),
                'cvss3_base_score': item.findtext('cvss3_base_score', 'N/A'),
                'cvss3_vector': item.findtext('cvss3_vector', 'N/A'),
                'cve': [],
                'see_also': item.findtext('see_also', 'N/A'),
                'compliance': item.findtext('cm:compliance-result', 'N/A'),
                'compliance_info': item.findtext('cm:compliance-info', 'N/A'),
            }
            
            # Extract CVEs
            for cve in item.findall('cve'):
                vuln['cve'].append(cve.text)
            
            vulnerabilities.append(vuln)
    
    return vulnerabilities

def get_severity_name(severity):
    """Convert severity number to name"""
    severity_map = {
        0: 'Info',
        1: 'Low',
        2: 'Medium',
        3: 'High',
        4: 'Critical'
    }
    return severity_map.get(severity, 'Unknown')

def get_severity_color(severity):
    """Get color for severity level"""
    color_map = {
        0: '#17a2b8',  # Info - Cyan
        1: '#28a745',  # Low - Green
        2: '#ffc107',  # Medium - Yellow
        3: '#fd7e14',  # High - Orange
        4: '#dc3545'   # Critical - Red
    }
    return color_map.get(severity, '#6c757d')

def generate_html_report(vulnerabilities, output_file, plugin_date_filter=None):
    """Generate HTML report with detailed vulnerabilities by host"""
    
    # Group vulnerabilities by host
    hosts_data = defaultdict(list)
    for vuln in vulnerabilities:
        hosts_data[vuln['host']].append(vuln)
    
    # Sort hosts
    sorted_hosts = sorted(hosts_data.keys())
    
    # Count vulnerabilities by severity
    severity_counts = defaultdict(int)
    for vuln in vulnerabilities:
        severity_counts[vuln['severity']] += 1
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nessus Vulnerability Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #444;
            margin-top: 30px;
            border-bottom: 2px solid #6c757d;
            padding-bottom: 5px;
        }}
        h3 {{
            color: #555;
            margin-top: 20px;
        }}
        .summary {{
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
            flex-wrap: wrap;
        }}
        .summary-box {{
            padding: 20px;
            border-radius: 5px;
            color: white;
            min-width: 150px;
            text-align: center;
            margin: 10px;
        }}
        .critical {{ background-color: #dc3545; }}
        .high {{ background-color: #fd7e14; }}
        .medium {{ background-color: #ffc107; color: #333; }}
        .low {{ background-color: #28a745; }}
        .info {{ background-color: #17a2b8; }}
        .host-section {{
            margin: 30px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            background-color: #fafafa;
        }}
        .vuln-item {{
            margin: 20px 0;
            padding: 15px;
            border-left: 5px solid #ddd;
            background-color: white;
            border-radius: 3px;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .severity-badge {{
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }}
        .details {{
            margin: 10px 0;
        }}
        .details-label {{
            font-weight: bold;
            color: #555;
        }}
        .plugin-output {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #007bff;
            color: white;
        }}
        .metadata {{
            font-size: 14px;
            color: #666;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Nessus Vulnerability Report</h1>
        <div class="metadata">
            <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Hosts:</strong> {len(sorted_hosts)}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
            {f'<p><strong>Filtered by Plugin Publication Date:</strong> After {plugin_date_filter.strftime("%Y-%m-%d")}</p>' if plugin_date_filter else ''}
        </div>
        
        <h2>Vulnerability Summary</h2>
        <div class="summary">
            <div class="summary-box critical">
                <h3>{severity_counts[4]}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box high">
                <h3>{severity_counts[3]}</h3>
                <p>High</p>
            </div>
            <div class="summary-box medium">
                <h3>{severity_counts[2]}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-box low">
                <h3>{severity_counts[1]}</h3>
                <p>Low</p>
            </div>
            <div class="summary-box info">
                <h3>{severity_counts[0]}</h3>
                <p>Info</p>
            </div>
        </div>
"""
    
    # Add vulnerabilities by host
    for host in sorted_hosts:
        vulns = sorted(hosts_data[host], key=lambda x: (-x['severity'], x['plugin_name']))
        
        # Get host info from first vulnerability
        host_info = vulns[0] if vulns else {}
        
        html += f"""
        <div class="host-section">
            <h2>Host: {host}</h2>
            <div class="details">
                <p><span class="details-label">FQDN:</span> {host_info.get('host_fqdn', 'N/A')}</p>
                <p><span class="details-label">IP Address:</span> {host_info.get('host_ip', 'N/A')}</p>
                <p><span class="details-label">Operating System:</span> {host_info.get('os', 'N/A')}</p>
                <p><span class="details-label">Total Findings:</span> {len(vulns)}</p>
            </div>
"""
        
        for vuln in vulns:
            severity_color = get_severity_color(vuln['severity'])
            cve_list = ', '.join(vuln['cve']) if vuln['cve'] else 'None'
            
            html += f"""
            <div class="vuln-item" style="border-left-color: {severity_color}">
                <div class="vuln-header">
                    <h3>{vuln['plugin_name']}</h3>
                    <span class="severity-badge" style="background-color: {severity_color}">
                        {vuln['severity_name']}
                    </span>
                </div>
                <div class="details">
                    <p><span class="details-label">Plugin ID:</span> {vuln['plugin_id']}</p>
                    <p><span class="details-label">Port:</span> {vuln['port']}/{vuln['protocol']}</p>
                    <p><span class="details-label">Risk Factor:</span> {vuln['risk_factor']}</p>
                    <p><span class="details-label">CVE:</span> {cve_list}</p>
                    {f"<p><span class='details-label'>CVSS v2 Base Score:</span> {vuln['cvss_base_score']}</p>" if vuln['cvss_base_score'] != 'N/A' else ''}
                    {f"<p><span class='details-label'>CVSS v3 Base Score:</span> {vuln['cvss3_base_score']}</p>" if vuln['cvss3_base_score'] != 'N/A' else ''}
                    {f"<p><span class='details-label'>Plugin Publication Date:</span> {vuln['plugin_publication_date']}</p>" if vuln['plugin_publication_date'] else ''}
                    
                    <h4>Synopsis</h4>
                    <p>{vuln['synopsis']}</p>
                    
                    <h4>Description</h4>
                    <p>{vuln['description']}</p>
                    
                    <h4>Solution / Remediation</h4>
                    <p>{vuln['solution']}</p>
                    
                    {f"<h4>Compliance Information</h4><p>{vuln['compliance']}</p>" if vuln['compliance'] != 'N/A' else ''}
                    {f"<p>{vuln['compliance_info']}</p>" if vuln['compliance_info'] != 'N/A' else ''}
                    
                    {f"<h4>See Also</h4><p>{vuln['see_also']}</p>" if vuln['see_also'] != 'N/A' else ''}
                    
                    {f"<h4>Plugin Output</h4><div class='plugin-output'>{vuln['plugin_output']}</div>" if vuln['plugin_output'] != 'N/A' else ''}
                </div>
            </div>
"""
        
        html += "</div>"
    
    html += """
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] HTML report generated: {output_file}")

def generate_pdf_report(vulnerabilities, output_file, plugin_date_filter=None):
    """Generate PDF report using wkhtmltopdf or similar"""
    try:
        from weasyprint import HTML, CSS
        
        # Generate HTML first
        html_content = generate_pdf_html(vulnerabilities, plugin_date_filter)
        
        # Convert to PDF
        HTML(string=html_content).write_pdf(output_file)
        print(f"[+] PDF report generated: {output_file}")
        
    except ImportError:
        print("[!] WeasyPrint not installed. Attempting alternative method...")
        try:
            import pdfkit
            
            # Generate HTML first
            temp_html = output_file.replace('.pdf', '_temp.html')
            generate_html_report(vulnerabilities, temp_html, plugin_date_filter)
            
            # Convert to PDF
            pdfkit.from_file(temp_html, output_file)
            
            # Clean up temp file
            Path(temp_html).unlink()
            print(f"[+] PDF report generated: {output_file}")
            
        except ImportError:
            print("[!] Neither WeasyPrint nor pdfkit installed.")
            print("[!] Please install one of the following:")
            print("    pip install weasyprint")
            print("    OR")
            print("    pip install pdfkit (requires wkhtmltopdf installed)")
            print("[!] Generating HTML report only...")

def generate_pdf_html(vulnerabilities, plugin_date_filter=None):
    """Generate HTML optimized for PDF conversion"""
    # Group vulnerabilities by host
    hosts_data = defaultdict(list)
    for vuln in vulnerabilities:
        hosts_data[vuln['host']].append(vuln)
    
    sorted_hosts = sorted(hosts_data.keys())
    severity_counts = defaultdict(int)
    for vuln in vulnerabilities:
        severity_counts[vuln['severity']] += 1
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @page {{ margin: 1cm; }}
        body {{ font-family: Arial, sans-serif; font-size: 10pt; }}
        h1 {{ color: #333; font-size: 18pt; border-bottom: 2px solid #007bff; }}
        h2 {{ color: #444; font-size: 14pt; page-break-before: always; }}
        h3 {{ color: #555; font-size: 12pt; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .summary-box {{ padding: 10px; border-radius: 3px; text-align: center; }}
        .vuln-item {{ margin: 10px 0; padding: 10px; border-left: 3px solid #ddd; }}
        .details-label {{ font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Nessus Vulnerability Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Total Hosts:</strong> {len(sorted_hosts)} | <strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
    {f'<p><strong>Filtered by Plugin Date:</strong> After {plugin_date_filter.strftime("%Y-%m-%d")}</p>' if plugin_date_filter else ''}
"""
    
    for host in sorted_hosts:
        vulns = sorted(hosts_data[host], key=lambda x: (-x['severity'], x['plugin_name']))
        host_info = vulns[0] if vulns else {}
        
        html += f"""
    <h2>Host: {host}</h2>
    <p><strong>IP:</strong> {host_info.get('host_ip', 'N/A')} | <strong>OS:</strong> {host_info.get('os', 'N/A')}</p>
"""
        
        for vuln in vulns:
            html += f"""
    <div class="vuln-item">
        <h3>{vuln['plugin_name']} [{vuln['severity_name']}]</h3>
        <p><strong>Plugin ID:</strong> {vuln['plugin_id']} | <strong>Port:</strong> {vuln['port']}/{vuln['protocol']}</p>
        <p><strong>Synopsis:</strong> {vuln['synopsis']}</p>
        <p><strong>Solution:</strong> {vuln['solution']}</p>
    </div>
"""
    
    html += "</body></html>"
    return html

def main():
    parser = argparse.ArgumentParser(description='Generate Nessus vulnerability reports')
    parser.add_argument('folder', help='Folder containing .nessus files')
    parser.add_argument('-d', '--date', help='Filter by plugin publication date (YYYY-MM-DD)', required=False)
    parser.add_argument('-o', '--output', help='Output file prefix', default='nessus_report')
    
    args = parser.parse_args()
    
    # Parse date filter if provided
    plugin_date_filter = None
    if args.date:
        try:
            plugin_date_filter = datetime.strptime(args.date, '%Y-%m-%d')
            print(f"[+] Filtering vulnerabilities published after: {plugin_date_filter.strftime('%Y-%m-%d')}")
        except ValueError:
            print(f"[!] Invalid date format: {args.date}. Use YYYY-MM-DD")
            sys.exit(1)
    
    # Find all .nessus files
    folder_path = Path(args.folder)
    if not folder_path.exists():
        print(f"[!] Folder not found: {args.folder}")
        sys.exit(1)
    
    nessus_files = list(folder_path.glob('*.nessus'))
    if not nessus_files:
        print(f"[!] No .nessus files found in: {args.folder}")
        sys.exit(1)
    
    print(f"[+] Found {len(nessus_files)} .nessus file(s)")
    
    # Parse all files
    all_vulnerabilities = []
    for nessus_file in nessus_files:
        print(f"[+] Parsing: {nessus_file.name}")
        vulns = parse_nessus_file(nessus_file, plugin_date_filter)
        all_vulnerabilities.extend(vulns)
    
    print(f"[+] Total vulnerabilities found: {len(all_vulnerabilities)}")
    
    if not all_vulnerabilities:
        print("[!] No vulnerabilities found matching the criteria")
        sys.exit(0)
    
    # Generate reports
    html_output = f"{args.output}.html"
    pdf_output = f"{args.output}.pdf"
    
    generate_html_report(all_vulnerabilities, html_output, plugin_date_filter)
    generate_pdf_report(all_vulnerabilities, pdf_output, plugin_date_filter)
    
    print("[+] Report generation complete!")

if __name__ == '__main__':
    main()