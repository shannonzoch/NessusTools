<#
.SYNOPSIS
    Nessus API Report Generator for Nessus 10.9.1
    Version: 0.2
    
.DESCRIPTION
    Connects to Nessus API, downloads scans, exports .nessus files, and generates HTML/PDF reports 
    with filtering by plugin publication date. Reports include detailed vulnerabilities by host 
    with compliance and remediation information.
    
.PARAMETER NessusUrl
    Nessus server URL (e.g., https://nessus.example.com:8834)
    
.PARAMETER AccessKey
    Nessus API access key
    
.PARAMETER SecretKey
    Nessus API secret key
    
.PARAMETER FolderName
    Folder name to filter scans (exports all scans in folder)
    
.PARAMETER ScanName
    Specific scan name to export
    
.PARAMETER ScanId
    Specific scan ID to export
    
.PARAMETER PluginDate
    Filter vulnerabilities by plugin publication date (format: yyyy-MM-dd)
    
.PARAMETER OutputPrefix
    Output file prefix for generated reports (default: nessus_report)
    
.PARAMETER ListFolders
    List all available folders and exit
    
.PARAMETER ListScans
    List all available scans and exit
    
.PARAMETER NoSSLVerify
    Skip SSL certificate verification (useful for self-signed certs)
    
.PARAMETER ExportNessusFile
    Export the raw .nessus file(s) to disk (default: enabled)
    
.PARAMETER NoNessusExport
    Skip exporting the raw .nessus file(s)
    
.EXAMPLE
    .\NExportAPI_v0.2.ps1 -NessusUrl "https://nessus.local:8834" -AccessKey "abc123" -SecretKey "xyz789" -FolderName "Production" -PluginDate "2024-01-01"
    
.EXAMPLE
    .\NExportAPI_v0.2.ps1 -NessusUrl "https://nessus.local:8834" -AccessKey "abc123" -SecretKey "xyz789" -ListFolders
    
.EXAMPLE
    .\NExportAPI_v0.2.ps1 -NessusUrl "https://nessus.local:8834" -AccessKey "abc123" -SecretKey "xyz789" -ScanId 123 -OutputPrefix "weekly_scan"
    
.NOTES
    Version: 0.2
    Author: Cybersecurity Team
    
    CHANGE LOG:
    -----------
    v0.2 (2024-12-11)
    - Added .nessus file export functionality
    - Added -ExportNessusFile and -NoNessusExport parameters
    - Raw .nessus files now saved alongside HTML/PDF reports
    - Added version tracking and change log
    - Improved file naming for multiple scan exports
    - Enhanced status messages and progress indicators
    
    v0.1 (Initial Release)
    - Initial release with API connectivity
    - HTML and PDF report generation
    - Plugin date filtering
    - Folder and scan filtering
    - SSL verification control
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$NessusUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$AccessKey,
    
    [Parameter(Mandatory=$true)]
    [string]$SecretKey,
    
    [Parameter(Mandatory=$false)]
    [string]$FolderName,
    
    [Parameter(Mandatory=$false)]
    [string]$ScanName,
    
    [Parameter(Mandatory=$false)]
    [int]$ScanId,
    
    [Parameter(Mandatory=$false)]
    [string]$PluginDate,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPrefix = "nessus_report",
    
    [Parameter(Mandatory=$false)]
    [switch]$ListFolders,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListScans,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoSSLVerify,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportNessusFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoNessusExport
)

# Script version
$script:Version = "0.2"

# Skip SSL verification if requested
if ($NoSSLVerify) {
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# Nessus API Class
class NessusAPI {
    [string]$Url
    [hashtable]$Headers
    
    NessusAPI([string]$url, [string]$accessKey, [string]$secretKey) {
        $this.Url = $url.TrimEnd('/')
        $this.Headers = @{
            'X-ApiKeys' = "accessKey=$accessKey; secretKey=$secretKey"
            'Content-Type' = 'application/json'
            'Accept' = 'application/json'
        }
    }
    
    [object] Request([string]$method, [string]$endpoint, [object]$data) {
        $uri = "$($this.Url)$endpoint"
        
        try {
            $params = @{
                Uri = $uri
                Method = $method
                Headers = $this.Headers
                ContentType = 'application/json'
            }
            
            if ($data) {
                $params['Body'] = ($data | ConvertTo-Json -Depth 10)
            }
            
            $response = Invoke-RestMethod @params
            return $response
        }
        catch {
            Write-Host "[!] API request failed: $_" -ForegroundColor Red
            exit 1
        }
    }
    
    [array] ListFolders() {
        $response = $this.Request('GET', '/folders', $null)
        return $response.folders
    }
    
    [array] ListScans([int]$folderId) {
        $response = $this.Request('GET', '/scans', $null)
        $scans = $response.scans
        
        if ($folderId -ne 0) {
            $scans = $scans | Where-Object { $_.folder_id -eq $folderId }
        }
        
        return $scans
    }
    
    [object] GetScanDetails([int]$scanId) {
        return $this.Request('GET', "/scans/$scanId", $null)
    }
    
    [byte[]] ExportScan([int]$scanId) {
        Write-Host "[+] Exporting scan $scanId... " -NoNewline -ForegroundColor Green
        
        # Request export
        $exportData = @{ format = 'nessus' }
        $exportResponse = $this.Request('POST', "/scans/$scanId/export", $exportData)
        $fileId = $exportResponse.file
        
        # Wait for export to complete
        do {
            Start-Sleep -Seconds 2
            $statusResponse = $this.Request('GET', "/scans/$scanId/export/$fileId/status", $null)
            $status = $statusResponse.status
        } while ($status -ne 'ready')
        
        Write-Host "Done!" -ForegroundColor Green
        
        # Download export
        $downloadUri = "$($this.Url)/scans/$scanId/export/$fileId/download"
        $downloadResponse = Invoke-WebRequest -Uri $downloadUri -Headers $this.Headers -Method GET
        
        return $downloadResponse.Content
    }
    
    [object] GetFolderByName([string]$folderName) {
        $folders = $this.ListFolders()
        $folder = $folders | Where-Object { $_.name -eq $folderName }
        return $folder
    }
    
    [object] GetScanByName([string]$scanName, [int]$folderId) {
        $scans = $this.ListScans($folderId)
        $scan = $scans | Where-Object { $_.name -eq $scanName }
        return $scan
    }
}

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

function Get-SeverityColor {
    param([int]$Severity)
    
    switch ($Severity) {
        0 { return "#17a2b8" }
        1 { return "#28a745" }
        2 { return "#ffc107" }
        3 { return "#fd7e14" }
        4 { return "#dc3545" }
        default { return "#6c757d" }
    }
}

function Save-NessusFile {
    param(
        [byte[]]$Content,
        [string]$OutputFile
    )
    
    try {
        [System.IO.File]::WriteAllBytes($OutputFile, $Content)
        Write-Host "[+] .nessus file saved: $OutputFile" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[!] Failed to save .nessus file: $_" -ForegroundColor Red
        return $false
    }
}

function Parse-NessusContent {
    param(
        [byte[]]$Content,
        [datetime]$DateFilter
    )
    
    # Convert bytes to string
    $xmlString = [System.Text.Encoding]::UTF8.GetString($Content)
    [xml]$nessusXml = $xmlString
    
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

function Generate-HTMLReport {
    param(
        [array]$Vulnerabilities,
        [string]$OutputFile,
        [datetime]$DateFilter,
        [hashtable]$ScanInfo
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
    
    # Scan info HTML
    $scanInfoHtml = ""
    if ($ScanInfo) {
        $scanInfoHtml = @"
            <p><strong>Scan Name:</strong> $($ScanInfo.Name)</p>
            <p><strong>Scan Status:</strong> $($ScanInfo.Status)</p>
            <p><strong>Scan Created:</strong> $($ScanInfo.CreationDate)</p>
"@
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
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 12px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Nessus Vulnerability Report</h1>
        <div class="metadata">
            <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Generator:</strong> NExportAPI v$script:Version</p>
            $scanInfoHtml
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
                    <h3>$([System.Web.HttpUtility]::HtmlEncode($vuln.PluginName))</h3>
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
        <div class="footer">
            <p>Generated by NExportAPI v$script:Version | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
</body>
</html>
"@
    
    # Write HTML file
    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "[+] HTML report generated: $OutputFile" -ForegroundColor Green
}

function Generate-PDFReport {
    param(
        [array]$Vulnerabilities,
        [string]$OutputFile,
        [datetime]$DateFilter,
        [hashtable]$ScanInfo
    )
    
    Write-Host "[+] Attempting to generate PDF report..." -ForegroundColor Yellow
    
    # Check if wkhtmltopdf is available
    $wkhtmltopdf = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    
    if ($wkhtmltopdf) {
        # Generate temporary HTML file
        $tempHtml = $OutputFile -replace '\.pdf$', '_temp.html'
        Generate-HTMLReport -Vulnerabilities $Vulnerabilities -OutputFile $tempHtml -DateFilter $DateFilter -ScanInfo $ScanInfo
        
        # Convert to PDF
        & wkhtmltopdf $tempHtml $OutputFile 2>$null
        
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
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   Nessus API Report Generator v$script:Version" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Initialize Nessus API
    Write-Host "[+] Connecting to Nessus API..." -ForegroundColor Green
    $nessus = [NessusAPI]::new($NessusUrl, $AccessKey, $SecretKey)
    
    # List folders if requested
    if ($ListFolders) {
        $folders = $nessus.ListFolders()
        Write-Host "`n[+] Available folders:" -ForegroundColor Green
        foreach ($folder in $folders) {
            Write-Host ("  ID: {0,3} | Name: {1}" -f $folder.id, $folder.name)
        }
        exit 0
    }
    
    # List scans if requested
    if ($ListScans) {
        $folderId = 0
        if ($FolderName) {
            $folder = $nessus.GetFolderByName($FolderName)
            if ($folder) {
                $folderId = $folder.id
                Write-Host "`n[+] Scans in folder '$FolderName':" -ForegroundColor Green
            } else {
                Write-Host "[!] Folder '$FolderName' not found" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "`n[+] All scans:" -ForegroundColor Green
        }
        
        $scans = $nessus.ListScans($folderId)
        foreach ($scan in $scans) {
            Write-Host ("  ID: {0,5} | Name: {1,-40} | Status: {2}" -f $scan.id, $scan.name, $scan.status)
        }
        exit 0
    }
    
    # Determine if .nessus export is enabled (default: yes, unless -NoNessusExport is specified)
    $exportNessusEnabled = -not $NoNessusExport
    
    # Parse date filter
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
    
    # Get scan(s) to export
    $scansToExport = @()
    
    if ($ScanId) {
        $scansToExport += @{ id = $ScanId }
    }
    elseif ($ScanName) {
        $folderId = 0
        if ($FolderName) {
            $folder = $nessus.GetFolderByName($FolderName)
            if ($folder) {
                $folderId = $folder.id
            }
        }
        
        $scan = $nessus.GetScanByName($ScanName, $folderId)
        if ($scan) {
            $scansToExport += $scan
        } else {
            Write-Host "[!] Scan '$ScanName' not found" -ForegroundColor Red
            exit 1
        }
    }
    elseif ($FolderName) {
        $folder = $nessus.GetFolderByName($FolderName)
        if ($folder) {
            $scansToExport = $nessus.ListScans($folder.id)
            Write-Host "[+] Found $($scansToExport.Count) scan(s) in folder '$FolderName'" -ForegroundColor Green
        } else {
            Write-Host "[!] Folder '$FolderName' not found" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "[!] Please specify -ScanId, -ScanName, or -FolderName" -ForegroundColor Red
        Write-Host "[!] Use -ListScans or -ListFolders to see available options" -ForegroundColor Yellow
        exit 1
    }
    
    # Export and parse scans
    $allVulnerabilities = @()
    $scanInfo = $null
    $scanCounter = 0
    
    foreach ($scan in $scansToExport) {
        $scanId = $scan.id
        $scanCounter++
        
        Write-Host "`n[+] Processing scan $scanCounter of $($scansToExport.Count) - ID: $scanId" -ForegroundColor Green
        
        # Get scan details
        $details = $nessus.GetScanDetails($scanId)
        $scanNameClean = $details.info.name -replace '[\\/:*?"<>|]', '_'
        
        if (-not $scanInfo) {
            $timestamp = [DateTimeOffset]::FromUnixTimeSeconds($details.info.timestamp).DateTime
            $scanInfo = @{
                Name = $details.info.name
                Status = $details.info.status
                CreationDate = $timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
        
        # Export scan
        $content = $nessus.ExportScan($scanId)
        
        # Save .nessus file if enabled
        if ($exportNessusEnabled) {
            if ($scansToExport.Count -gt 1) {
                # Multiple scans - append scan name/ID to filename
                $nessusOutputFile = "$($OutputPrefix)_$($scanNameClean)_$scanId.nessus"
            } else {
                # Single scan - use simple filename
                $nessusOutputFile = "$OutputPrefix.nessus"
            }
            
            Save-NessusFile -Content $content -OutputFile $nessusOutputFile | Out-Null
        }
        
        # Parse vulnerabilities
        $vulns = Parse-NessusContent -Content $content -DateFilter $dateFilter
        $allVulnerabilities += $vulns
        Write-Host "[+] Found $($vulns.Count) vulnerabilities in this scan" -ForegroundColor Green
    }
    
    Write-Host "`n[+] Total vulnerabilities found: $($allVulnerabilities.Count)" -ForegroundColor Green
    
    if ($allVulnerabilities.Count -eq 0) {
        Write-Host "[!] No vulnerabilities found matching the criteria" -ForegroundColor Yellow
        exit 0
    }
    
    # Generate reports
    $htmlOutput = "$OutputPrefix.html"
    $pdfOutput = "$OutputPrefix.pdf"
    
    Write-Host "`n[+] Generating reports..." -ForegroundColor Green
    Generate-HTMLReport -Vulnerabilities $allVulnerabilities -OutputFile $htmlOutput -DateFilter $dateFilter -ScanInfo $scanInfo
    Generate-PDFReport -Vulnerabilities $allVulnerabilities -OutputFile $pdfOutput -DateFilter $dateFilter -ScanInfo $scanInfo
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "   Report Generation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    if ($exportNessusEnabled) {
        Write-Host "[+] .nessus file(s) exported" -ForegroundColor Cyan
    }
    Write-Host "[+] HTML report: $htmlOutput" -ForegroundColor Cyan
    if (Test-Path $pdfOutput) {
        Write-Host "[+] PDF report: $pdfOutput" -ForegroundColor Cyan
    }
    Write-Host ""
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
