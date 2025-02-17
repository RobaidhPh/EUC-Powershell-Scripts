$adapters = Get-NetAdapter
Write-Host "Found $($adapters.Count) network adapters"

# Create hashtable to track changes
$results = @{}

# Email configuration
$EmailTo = @("User@domain.com")
$EmailFrom = "ServiceDesk@domain.com"
$EmailSubject = "IPv6 Disable Status Report - $(Get-Date -Format 'yyyy-MM-dd')"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$computerName = $env:COMPUTERNAME

# SMTP Configuration
$SmtpServer = 
$SmtpPort = 
$SmtpSSL = 

Write-Host "Using SMTP Configuration:"
Write-Host "SMTP Server: $SmtpServer"
Write-Host "SMTP Port: $SmtpPort"
Write-Host "SSL Enabled: $SmtpSSL"

# Create log directory and file
$LogPath = "C:\Logs\IPv6Status"
if (-not (Test-Path -Path $LogPath)) {
    Write-Host "Creating log directory: $LogPath"
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
$logFile = Join-Path -Path $LogPath -ChildPath "IPv6Status_$(Get-Date -Format 'yyyyMMdd').log"
Write-Host "Log file will be created at: $logFile"

foreach ($adapter in $adapters) {
    $logEntry = "$timestamp | Processing adapter: $($adapter.Name) - Status: $($adapter.Status)"
    Add-Content -Path $logFile -Value $logEntry
    Write-Host $logEntry
    
    # Check current IPv6 binding status
    Write-Host "Checking IPv6 binding status for adapter: $($adapter.Name)"
    $currentBinding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
    if ($currentBinding.Enabled -eq $false) {
        $logEntry = "$timestamp | IPv6 already disabled on adapter: $($adapter.Name)"
        Add-Content -Path $logFile -Value $logEntry
        Write-Host $logEntry -ForegroundColor Yellow
        $results[$adapter.Name] = "Already Disabled"
        continue
    }
    
    try {
        Write-Host "Attempting to disable IPv6 on adapter: $($adapter.Name)"
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -Confirm:$false
        $logEntry = "$timestamp | Successfully disabled IPv6 on adapter: $($adapter.Name)"
        Add-Content -Path $logFile -Value $logEntry
        Write-Host $logEntry -ForegroundColor Green
        $results[$adapter.Name] = "Disabled by Script"
    }
    catch {
        $logEntry = "$timestamp | Failed to disable IPv6 on adapter: $($adapter.Name) | Error: $_"
        Add-Content -Path $logFile -Value $logEntry
        Write-Host $logEntry -ForegroundColor Red
        $results[$adapter.Name] = "Failed to Disable"
    }
}

# Prepare email body with HTML table
$EmailBody = @"
<h2>IPv6 Disable Status Report</h2>
<p><strong>Computer Name:</strong> $computerName</p>
<p>The following network adapters have been processed:</p>
<table border='1'>
<tr>
    <th>Timestamp</th>
    <th>Adapter Name</th>
    <th>Status</th>
</tr>
"@

foreach ($adapter in $results.Keys) {
    $status = $results[$adapter]
    $color = switch ($status) {
        "Already Disabled" { "orange" }
        "Disabled by Script" { "green" }
        "Failed to Disable" { "red" }
    }
    $EmailBody += @"
<tr>
    <td>$timestamp</td>
    <td>$adapter</td>
    <td style='color: $color;'>$status</td>
</tr>
"@
}

$EmailBody += @"
</table>
<p>Please find the detailed log file attached.</p>
"@

Write-Host "Preparing to send email report..."

# Send email with attachment
$EmailParams = @{
    To = $EmailTo
    From = $EmailFrom
    Subject = $EmailSubject
    Body = $EmailBody
    BodyAsHtml = $true
    SmtpServer = $SmtpServer
    Port = $SmtpPort
    Attachments = $logFile
}

# Only add UseSsl if it's enabled
if($SmtpSSL) {
    Write-Host "Adding SSL configuration to email parameters"
    $EmailParams.Add("UseSsl", $true)
}

try {
    Write-Host "Sending email report..."
    Send-MailMessage @EmailParams
    Write-Host "Email report sent successfully" -ForegroundColor Green
}
catch {
    $errorMessage = "Failed to send email report: $_"
    Write-Host $errorMessage -ForegroundColor Red
    Add-Content -Path $logFile -Value "$timestamp | $errorMessage"
}

# Display final summary in console
Write-Host "`nOperation Summary:"
Write-Host "----------------"
foreach ($adapter in $results.Keys) {
    $status = $results[$adapter]
    $color = switch ($status) {
        "Already Disabled" { "Yellow" }
        "Disabled by Script" { "Green" }
        "Failed to Disable" { "Red" }
    }
    Write-Host "$adapter : $status" -ForegroundColor $color
}