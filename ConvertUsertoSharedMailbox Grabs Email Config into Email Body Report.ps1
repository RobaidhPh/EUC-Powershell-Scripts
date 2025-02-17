function Convert-M365MailboxToShared {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "C:\Logs\MailboxConversion"
    )

    # Validate and create log directory
    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        $LogPath = "C:\Logs\MailboxConversion"
    }

    # Ensure log directory exists
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    # Log file configuration
    $logFile = Join-Path -Path $LogPath -ChildPath "MailboxConversion_$(Get-Date -Format 'yyyyMMdd').log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Email configuration
    $EmailTo = @("user@domain.com")
    $EmailFrom = "ServiceDesk@domain.com"

    # Retrieve UPN from workflow
    $Mailbox = $workflow.SavedObjectProperties("Save object properties").get("userPrincipalName")

    # Construct email subject with UPN
    $EmailSubject = "Account Deprovisioning - $Mailbox"

    # Get mail server config function
    function GetMailServerConfig {
        $DefaultEmail = Get-QADObject -Identity "CN=Default Mail Settings,CN=Mail Configuration,CN=Server Configuration,CN=Configuration" -DontUseDefaultIncludedProperties -IncludedProperties edsaRuleDefinition -Proxy
        [xml]$MailSettings = $DefaultEmail.edsaRuleDefinition
        $script:MailSMTP = $MailSettings.MailConfiguration.Server.host
        $script:MailPort = $MailSettings.MailConfiguration.Server.port
        $script:MailSSL = $MailSettings.MailConfiguration.Server.ssl
    }

    # Variable to track conversion status
    $conversionStatus = "Not Attempted"
    $conversionDetails = ""

    try {
        # Import ExchangeOnlineManagement module using context
        $context.O365ImportModules("ExchangeOnlineManagement")
        
        # Construct and execute mailbox conversion command
        $scriptCmd = "Set-Mailbox ""$Mailbox"" -Type Shared"
        
        try {
            $context.O365ExecuteScriptCmd($scriptCmd)
            $conversionStatus = "Yes"
        }
        catch {
            $conversionStatus = "No"
            $conversionDetails = $_.Exception.Message
        }

        # Log conversion attempt
        $logEntry = "$timestamp | $conversionStatus | $Mailbox | $conversionDetails"
        Add-Content -Path $logFile -Value $logEntry
        Write-Output $logEntry

        # Get mail server configuration before preparing email
        GetMailServerConfig

        # Prepare email body
        $EmailBody = @"
<h2>Account Deprovisioning Report</h2>
<p>The following account has been processed for deprovisioning:</p>
<table border='1'>
<tr>
    <th>Timestamp</th>
    <th>Account</th>
    <th>Mailbox Conversion to Shared</th>
    <th>Deprovisioning Successful</th>
</tr>
<tr>
    <td>$timestamp</td>
    <td>$Mailbox</td>
    <td style='color: $(if($conversionStatus -eq "Yes"){"green"}else{"red"});'>$conversionStatus</td>
    <td style='color: $(if($conversionStatus -eq "Yes"){"green"}else{"red"});'>$(if($conversionStatus -eq "Yes"){"Yes"}else{"No"})</td>
</tr>
</table>
$(if($conversionDetails){
"<p>Conversion Details: $conversionDetails</p>"
})
<h3>Mail Server Configuration</h3>
<table border='1'>
<tr>
    <th>Setting</th>
    <th>Value</th>
</tr>
<tr>
    <td>SMTP Server</td>
    <td>$script:MailSMTP</td>
</tr>
<tr>
    <td>Port</td>
    <td>$script:MailPort</td>
</tr>
<tr>
    <td>SSL Enabled</td>
    <td>$script:MailSSL</td>
</tr>
</table>
<p>Please find the detailed log file attached.</p>
"@

        # Send email with attachment
        $EmailParams = @{
            To = $EmailTo
            From = $EmailFrom
            Subject = $EmailSubject
            Body = $EmailBody
            BodyAsHtml = $true
            SmtpServer = $script:MailSMTP
            Port = $script:MailPort
            Attachments = $logFile
        }

        if($script:MailSSL -eq "True") {
            $EmailParams.Add("UseSsl", $true)
        }

        Send-MailMessage @EmailParams
    }
    catch {
        # Detailed error logging
        $errorMessage = $_.Exception.Message
        $errorLogEntry = "$timestamp | FAILED | $Mailbox | Overall script error: $errorMessage"
        Add-Content -Path $logFile -Value $errorLogEntry
        
        # Get mail server configuration before preparing failure email
        GetMailServerConfig

        # Prepare and send failure email
        $EmailBody = @"
<h2>Account Deprovisioning Report - FAILED</h2>
<p>The following account deprovisioning attempt encountered a critical error:</p>
<table border='1'>
<tr>
    <th>Timestamp</th>
    <th>Account</th>
    <th>Mailbox Conversion to Shared</th>
    <th>Deprovisioning Successful</th>
</tr>
<tr>
    <td>$timestamp</td>
    <td>$Mailbox</td>
    <td style='color: red;'>No</td>
    <td style='color: red;'>No</td>
</tr>
</table>
<p>Error Details: $errorMessage</p>
<h3>Mail Server Configuration</h3>
<table border='1'>
<tr>
    <th>Setting</th>
    <th>Value</th>
</tr>
<tr>
    <td>SMTP Server</td>
    <td>$script:MailSMTP</td>
</tr>
<tr>
    <td>Port</td>
    <td>$script:MailPort</td>
</tr>
<tr>
    <td>SSL Enabled</td>
    <td>$script:MailSSL</td>
</tr>
</table>
<p>Please find the detailed log file attached.</p>
"@

        # Send error email with attachment
        $EmailParams = @{
            To = $EmailTo
            From = $EmailFrom
            Subject = "$EmailSubject - FAILED"
            Body = $EmailBody
            BodyAsHtml = $true
            SmtpServer = $script:MailSMTP
            Port = $script:MailPort
            Attachments = $logFile
        }

        if($script:MailSSL -eq "True") {
            $EmailParams.Add("UseSsl", $true)
        }

        Send-MailMessage @EmailParams
    }
    finally {
        # Remove all module sessions using context
        $context.O365RemoveAllModulesSessions()
    }
}