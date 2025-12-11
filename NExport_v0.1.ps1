<#
.SYNOPSIS
    Nessus Report Generator for Nessus 10.9.1
    
.DESCRIPTION
    Generates HTML and PDF reports from Nessus .nessus files with filtering by plugin publication date.
    Reports include detailed vulnerabilities by host with compliance and remediation information.
    
.PARAMETER FolderPath
    Path to folder containing .nessus files
    
.PARAMETER PluginDate
    Filter vulnerabilities by plugin publication date (format: yyyy-MM-dd)
    Only vulnerabilities published after this date will be included
    
.PARAMETER OutputPrefix
    Output file prefix for generated reports (default: nessus_report)
    
.EXAMPLE
    .\Generate-NessusReport.ps1 -FolderPath "C:\Scans" -PluginDate "2024-01-01" -OutputPrefix "security_report"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$FolderPath,
    
    [Parameter(Mandatory=$false)]
    [string]$PluginDate,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPrefix = "nessus_report"
)

# Function to get severity name
function Get-SeverityName {
    param([int]$Severity)
    
    switch ($Severity) {
        0 { return "Info" }
        1 { return "Low" }
        2 { return "Medium" }
        3 { return "High" }
        4 { return "Critical" }
        default { return "Unknown" }
    }
}

# Function to get severity color
function Get-SeverityColor {
    param([int]$Severity)
    
    switch ($Severity) {
        0 { return "#17a2b8" }  # Info - Cyan
        1 { return "#28a745" }  # Low - Green
        2 { return "#ffc107" }  # Medium - Yellow
        3 { return "#fd7e14" }  # High - Orange
        4 { return "#dc3545" }  # Critical - Red
        default { return "#6c757d" }
    }
}

# Function to parse a single .nessus file
function Parse-NessusFile {
    param(
        [string]$FilePath,
        [datetime]$DateFilter
    )
    
    Write-Host "[+] Parsing: $(Split-Path $FilePath -Leaf)" -ForegroundColor Green
    
    [xml]$nessusXml = Get-Content $FilePath -Raw
    $vulnerabilities = @()
    
    foreach ($reportHost in $nessusXml.NessusClientData_v2.Report.ReportHost) {
        $hostName = $reportHost.name
        
        # Extract host properties
        $hostProperties = @{}
        foreach ($tag in $reportHost.HostProperties.tag) {
            $hostProperties[$tag.name] = $tag.'#text'
        }
        
        foreach ($item in $reportHost.ReportItem) {
            $pluginId = $item.pluginID
            $pluginName = $item.pluginName
            $severity = [int]$item.severity
            $port = $item.port
            $protocol = $item.protocol
            
            # Get plugin publication date
            $pluginPubDate = $item.plugin_publication_date
            
            # Apply date filter if specified
            if ($DateFilter -and $pluginPubDate) {
                try {
                    $pubDate = [datetime]::ParseExact($pluginPubDate, "yyyy/MM/dd", $null)
                    if ($pubDate -lt $DateFilter) {
                        continue
                    }
                } catch {
                    # Skip if date parsing fails
                }
            }
            
            # Extract CVEs
            $cveList = @()
            if ($item.cve) {
                $cveList = @($item.cve)
            }
            
            # Create vulnerability object
            $vuln = [PSCustomObject]@{
                Host = $hostName
                HostFQDN = $hostProperties['host-fqdn']
                HostIP = $hostProperties['host-ip']
                OS = $hostProperties['operating-system']
                PluginID = $pluginId
                PluginName = $pluginName
                Severity = $severity
                SeverityName = Get-SeverityName -Severity $severity
                Port = $port
                Protocol = $protocol
                Description = $item.description
                Synopsis = $item.synopsis
                Solution = $item.solution
                RiskFactor = $item.risk_factor
                PluginOutput = $item.plugin_output
                PluginPublicationDate = $pluginPubDate
                CVSSBaseScore = $item.cvss_base_score
                CVSSVector = $item.cvss_vector
                CVSS3BaseScore = $item.cvss3_base_score
                CVSS3Vector = $item.cvss3_vector
                CVE = $cveList
                SeeAlso = $item.see_also
                Compliance = $item.'cm:compliance-result'
                ComplianceInfo = $item.'cm:compliance-info'
            }
            
            $vulnerabilities += $vuln
        }
    }
    
    return $vulnerabilities
}

# Function to generate HTML report
function Generate-HTMLReport {
    param(
        [array]$Vulnerabilities,
        [string]$OutputFile,
        [datetime]$DateFilter
    )
    
    # Group vulnerabilities by host
    $hostsData = $Vulnerabilities | Group-Object -Property Host
    
    # Count vulnerabilities by severity
    $severityCounts = @{
        0 = 0; 1 = 0; 2 = 0; 3 = 0; 4 = 0
    }
    foreach ($vuln in $Vulnerabilities) {
        $severityCounts[$vuln.Severity]++
    }
    
    # Start building HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nessus Vulnerability Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }
        h2 {
            color: #444;
            margin-top: 30px;
            border-bottom: 2px solid #6c757d;
            padding-bottom: 5px;
        }
        h3 {
            color: #555;
            margin-top: 20px;
        }
        .summary {
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        .summary-box {
            padding: 20px;
            border-radius: 5px;
            color: white;
            min-width: 150px;
            text-align: center;
            margin: 10px;
        }
        .critical { background-color: #dc3545; }
        .high { background-color: #fd7e14; }
        .medium { background-color: #ffc107; color: #333; }
        .low { background-color: #28a745; }
        .info { background-color: #17a2b8; }
        .host-section {
            margin: 30px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            background-color: #fafafa;
        }
        .vuln-item {
            margin: 20px 0;
            padding: 15px;
            border-left: 5px solid #ddd;
            background-color: white;
            border-radius: 3px;
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .severity-badge {
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }
        .details {
            margin: 10px 0;
        }
        .details-label {
            font-weight: bold;
            color: #555;
        }
        .plugin-output {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 12px;
        }
        .metadata {
            font-size: 14px;
            color: #666;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Nessus Vulnerability Report</h1>
        <div class="metadata">
            <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Total Hosts:</strong> $($hostsData.Count)</p>
            <p><strong>Total Vulnerabilities:</strong> $($Vulnerabilities.Count)</p>
"@

    if ($DateFilter) {
        $html += @"
            <p><strong>Filtered by Plugin Publication Date:</strong> After $($DateFilter.ToString('yyyy-MM-dd'))</p>
"@
    }

    $html += @"
        </div>
        
        <h2>Vulnerability Summary</h2>
        <div class="summary">
            <div class="summary-box critical">
                <h3>$($severityCounts[4])</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box high">
                <h3>$($severityCounts[3])</h3>
                <p>High</p>
            </div>
            <div class="summary-box medium">
                <h3>$($severityCounts[2])</h3>
                <p>Medium</p>
            </div>
            <div class="summary-box low">
                <h3>$($severityCounts[1])</h3>
                <p>Low</p>
            </div>
            <div class="summary-box info">
                <h3>$($severityCounts[0])</h3>
                <p>Info</p>
            </div>
        </div>
"@

    # Add vulnerabilities by host
    foreach ($hostGroup in ($hostsData | Sort-Object Name)) {
        $host = $hostGroup.Name
        $vulns = $hostGroup.Group | Sort-Object @{Expression={-$_.Severity}}, PluginName
        $hostInfo = $vulns[0]
        
        $html += @"
        <div class="host-section">
            <h2>Host: $host</h2>
            <div class="details">
                <p><span class="details-label">FQDN:</span> $($hostInfo.HostFQDN)</p>
                <p><span class="details-label">IP Address:</span> $($hostInfo.HostIP)</p>
                <p><span class="details-label">Operating System:</span> $($hostInfo.OS)</p>
                <p><span class="details-label">Total Findings:</span> $($vulns.Count)</p>
            </div>
"@
        
        foreach ($vuln in $vulns) {
            $severityColor = Get-SeverityColor -Severity $vuln.Severity
            $cveList = if ($vuln.CVE) { $vuln.CVE -join ', ' } else { 'None' }
            
            $html += @"
            <div class="vuln-item" style="border-left-color: $severityColor">
                <div class="vuln-header">
                    <h3>$($vuln.PluginName)</h3>
                    <span class="severity-badge" style="background-color: $severityColor">
                        $($vuln.SeverityName)
                    </span>
                </div>
                <div class="details">
                    <p><span class="details-label">Plugin ID:</span> $($vuln.PluginID)</p>
                    <p><span class="details-label">Port:</span> $($vuln.Port)/$($vuln.Protocol)</p>
                    <p><span class="details-label">Risk Factor:</span> $($vuln.RiskFactor)</p>
                    <p><span class="details-label">CVE:</span> $cveList</p>
"@
            
            if ($vuln.CVSSBaseScore) {
                $html += @"
                    <p><span class="details-label">CVSS v2 Base Score:</span> $($vuln.CVSSBaseScore)</p>
"@
            }
            
            if ($vuln.CVSS3BaseScore) {
                $html += @"
                    <p><span class="details-label">CVSS v3 Base Score:</span> $($vuln.CVSS3BaseScore)</p>
"@
            }
            
            if ($vuln.PluginPublicationDate) {
                $html += @"
                    <p><span class="details-label">Plugin Publication Date:</span> $($vuln.PluginPublicationDate)</p>
"@
            }
            
            $html += @"
                    
                    <h4>Synopsis</h4>
                    <p>$([System.Web.HttpUtility]::HtmlEncode($vuln.Synopsis))</p>
                    
                    <h4>Description</h4>
                    <p>$([System.Web.HttpUtility]::HtmlEncode($vuln.Description))</p>
                    
                    <h4>Solution / Remediation</h4>
                    <p>$([System.Web.HttpUtility]::HtmlEncode($vuln.Solution))</p>
"@
            
            if ($vuln.Compliance) {
                $html += @"
                    <h4>Compliance Information</h4>
                    <p>$([System.Web.HttpUtility]::HtmlEncode($vuln.Compliance))</p>
"@
            }
            
            if ($vuln.ComplianceInfo) {
                $html += @"
                    <p>$([System.Web.HttpUtility]::HtmlEncode($vuln.ComplianceInfo))</p>
"@
            }
            
            if ($vuln.SeeAlso) {
                $html += @"
                    <h4>See Also</h4>
                    <p>$([System.Web.HttpUtility]::HtmlEncode($vuln.SeeAlso))</p>
"@
            }
            
            if ($vuln.PluginOutput) {
                $html += @"
                    <h4>Plugin Output</h4>
                    <div class="plugin-output">$([System.Web.HttpUtility]::HtmlEncode($vuln.PluginOutput))</div>
"@
            }
            
            $html += @"
                </div>
            </div>
"@
        }
        
        $html += "</div>"
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    # Write HTML file
    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "[+] HTML report generated: $OutputFile" -ForegroundColor Green
}

# Function to generate PDF report
function Generate-PDFReport {
    param(
        [array]$Vulnerabilities,
        [string]$OutputFile,
        [datetime]$DateFilter
    )
    
    Write-Host "[+] Attempting to generate PDF report..." -ForegroundColor Yellow
    
    # Check if wkhtmltopdf is available
    $wkhtmltopdf = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    
    if ($wkhtmltopdf) {
        # Generate temporary HTML file
        $tempHtml = $OutputFile -replace '\.pdf$', '_temp.html'
        Generate-HTMLReport -Vulnerabilities $Vulnerabilities -OutputFile $tempHtml -DateFilter $DateFilter
        
        # Convert to PDF
        & wkhtmltopdf $tempHtml $OutputFile
        
        # Clean up temp file
        Remove-Item $tempHtml -Force
        
        Write-Host "[+] PDF report generated: $OutputFile" -ForegroundColor Green
    } else {
        Write-Host "[!] wkhtmltopdf not found. Please install wkhtmltopdf to generate PDF reports." -ForegroundColor Red
        Write-Host "[!] Download from: https://wkhtmltopdf.org/downloads.html" -ForegroundColor Yellow
        Write-Host "[!] Generating HTML report only..." -ForegroundColor Yellow
    }
}

# Main script execution
try {
    Add-Type -AssemblyName System.Web
    
    Write-Host "=== Nessus Report Generator ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Validate folder path
    if (-not (Test-Path $FolderPath)) {
        Write-Host "[!] Folder not found: $FolderPath" -ForegroundColor Red
        exit 1
    }
    
    # Parse date filter if provided
    $dateFilter = $null
    if ($PluginDate) {
        try {
            $dateFilter = [datetime]::ParseExact($PluginDate, "yyyy-MM-dd", $null)
            Write-Host "[+] Filtering vulnerabilities published after: $($dateFilter.ToString('yyyy-MM-dd'))" -ForegroundColor Green
        } catch {
            Write-Host "[!] Invalid date format: $PluginDate. Use yyyy-MM-dd" -ForegroundColor Red
            exit 1
        }
    }
    
    # Find all .nessus files
    $nessusFiles = Get-ChildItem -Path $FolderPath -Filter "*.nessus"
    
    if ($nessusFiles.Count -eq 0) {
        Write-Host "[!] No .nessus files found in: $FolderPath" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[+] Found $($nessusFiles.Count) .nessus file(s)" -ForegroundColor Green
    Write-Host ""
    
    # Parse all files
    $allVulnerabilities = @()
    foreach ($file in $nessusFiles) {
        $vulns = Parse-NessusFile -FilePath $file.FullName -DateFilter $dateFilter
        $allVulnerabilities += $vulns
    }
    
    Write-Host ""
    Write-Host "[+] Total vulnerabilities found: $($allVulnerabilities.Count)" -ForegroundColor Green
    
    if ($allVulnerabilities.Count -eq 0) {
        Write-Host "[!] No vulnerabilities found matching the criteria" -ForegroundColor Yellow
        exit 0
    }
    
    # Generate reports
    $htmlOutput = "$OutputPrefix.html"
    $pdfOutput = "$OutputPrefix.pdf"
    
    Write-Host ""
    Generate-HTMLReport -Vulnerabilities $allVulnerabilities -OutputFile $htmlOutput -DateFilter $dateFilter
    Generate-PDFReport -Vulnerabilities $allVulnerabilities -OutputFile $pdfOutput -DateFilter $dateFilter
    
    Write-Host ""
    Write-Host "[+] Report generation complete!" -ForegroundColor Green
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}