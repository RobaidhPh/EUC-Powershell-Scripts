# Transcript logging setup
$LogPath = "C:\Logs\SecurityGroupRemoval"
if (-not (Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction SilentlyContinue | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logFile = Join-Path -Path $LogPath -ChildPath "DomainComputersRemoval_$(Get-Date -Format 'yyyyMMdd').log"
$computerName = $env:COMPUTERNAME

# Email configuration
$EmailTo = "User@domain.com"
$EmailFrom = "servicedesk@domain.com"
$EmailSubject = "Domain Computers Group Removal - $computerName"
$SmtpServer = "smtpsend.domain.com"
$SmtpPort = 25

# Start logging
Start-Transcript -Path "$LogPath\transcript_$(Get-Date -Format 'yyyyMMddHHmmss').txt" -ErrorAction SilentlyContinue

function Write-LogEntry {
    param(
        [string]$Message,
        [string]$Status = "Info"
    )
    
    $logEntry = "$timestamp | $Status | $Message"
    Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
}

# Initialize status variable
$emailStatus = "Unknown"
$statusDetails = ""

# Main execution block
try {
    Write-LogEntry "Starting Domain Computers group membership check for $computerName"
    
    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not available"
    }

    # Get the current computer object
    $computer = Get-ADComputer $computerName -ErrorAction Stop
    
    # Check if computer is member of Domain Computers
    $groupMembership = Get-ADPrincipalGroupMembership $computer -ErrorAction Stop
    $isDomainCompMember = $groupMembership | Where-Object { $_.Name -eq "Domain Computers" }
    
    if ($isDomainCompMember) {
        try {
            # Remove from Domain Computers group
            Remove-ADGroupMember -Identity "Domain Computers" -Members $computer -Confirm:$false -ErrorAction Stop
            Write-LogEntry "Successfully removed $computerName from Domain Computers group" "Success"
            $emailStatus = "Success"
            $statusDetails = "Computer was successfully removed from Domain Computers group"
        }
        catch {
            Write-LogEntry "Error removing from Domain Computers: $_" "Error"
            $emailStatus = "Failed"
            $statusDetails = "Failed to remove from Domain Computers group. Error: $_"
        }
    } else {
        Write-LogEntry "$computerName is not a member of Domain Computers group" "Info"
        $emailStatus = "Not Required"
        $statusDetails = "Computer is not a member of Domain Computers group - no action needed"
    }
}
catch {
    Write-LogEntry "Error: $_" "Error"
    $emailStatus = "Failed"
    $statusDetails = "Script execution failed. Error: $_"
}

# Prepare and send email report
$EmailBody = @"
<h2>Domain Computers Group Removal Report</h2>
<p><strong>Computer Name:</strong> $computerName</p>
<p><strong>Timestamp:</strong> $timestamp</p>
<p><strong>Status:</strong> $emailStatus</p>
<p><strong>Details:</strong> $statusDetails</p>
<pre>
Please check the attached log file for complete details.
</pre>
"@

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

try {
    Send-MailMessage @EmailParams
    Write-LogEntry "Email notification sent successfully" "Info"
}
catch {
    Write-LogEntry "Failed to send email notification: $_" "Error"
}

# Stop transcript logging
Stop-Transcript -ErrorAction SilentlyContinue