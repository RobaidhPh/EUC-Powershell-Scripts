function Get-HRSecurityGroupReport {
    $VerbosePreference = "Continue"

    # Fixed paths and group names
    $LogPath = "C:\Logs\HRSecurityReport"
    $SecurityGroups = @(
        #HR Groups to track
    )

    Write-Verbose "Starting HR Security Groups users report generation"

    # Create log directory if it doesn't exist
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Verbose "Created log directory: $LogPath"
    }

    # File configurations
    $timestamp = Get-Date -Format "yyyyMMdd"
    $logFile = Join-Path -Path $LogPath -ChildPath "HRSecurityUsers_$timestamp.log"
    $csvFile = Join-Path -Path $LogPath -ChildPath "HRSecurityUsers_$timestamp.csv"
    $reportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Verbose "Log file will be created at: $logFile"
    Write-Verbose "CSV file will be created at: $csvFile"

    # Email configuration
    $EmailTo = @("user@domain.com")
    $EmailFrom = "ServiceDesk@Domain.com"
    $EmailSubject = "HR Security Groups Report"
    
    # Variables to store operation results
    $successfulReport = $false
    $errorMessage = ""
    $allGroupMembers = @()

    try {
        # Get mail server configuration first
        Write-Verbose "Retrieving mail server configuration"
        $DefaultEmail = Get-QADObject -Identity "CN=Default Mail Settings,CN=Mail Configuration,CN=Server Configuration,CN=Configuration" -DontUseDefaultIncludedProperties -IncludedProperties edsaRuleDefinition -Proxy
        [xml]$MailSettings = $DefaultEmail.edsaRuleDefinition
        $MailSMTP = $MailSettings.MailConfiguration.Server.host
        $MailPort = $MailSettings.MailConfiguration.Server.port
        $MailSSL = $MailSettings.MailConfiguration.Server.ssl
        Write-Verbose "Mail server configuration retrieved successfully"

        # Process each security group
        foreach ($group in $SecurityGroups) {
            Write-Verbose "Retrieving users from security group: $group"
            
            $groupMembers = Get-ADGroupMember -Identity $group | 
                Where-Object {$_.objectClass -eq "user"} |
                ForEach-Object {
                    $user = Get-ADUser $_ -Properties DisplayName, EmailAddress, Enabled, Title, Department, Description, Company
                    [PSCustomObject]@{
                        SecurityGroup = $group
                        DisplayName = $user.DisplayName
                        SamAccountName = $user.SamAccountName
                        EmailAddress = $user.EmailAddress
                        Enabled = $user.Enabled
                        Title = $user.Title
                        Department = $user.Department
                        Description = $user.Description
                        Company = $user.Company
                        AccountStatus = if ($user.Enabled) { 'Active' } else { 'Disabled' }
                    }
                }
            
            $allGroupMembers += $groupMembers
            Write-Verbose "Retrieved $($groupMembers.Count) users from security group: $group"
            
            # Log group retrieval
            $logEntry = "$reportTime | Retrieved $($groupMembers.Count) users from security group: $group"
            Add-Content -Path $logFile -Value $logEntry
        }

        # Export all data to CSV
        Write-Verbose "Exporting combined user data to CSV"
        $allGroupMembers | Export-Csv -Path $csvFile -NoTypeInformation
        Write-Verbose "CSV export completed"

        # Create HTML sections for each group
        Write-Verbose "Generating HTML tables for email report"
        $groupSections = $SecurityGroups | ForEach-Object {
            $currentGroup = $_
            $groupUsers = $allGroupMembers | Where-Object { $_.SecurityGroup -eq $currentGroup }
            
            $userRows = $groupUsers | ForEach-Object {
                $statusColor = if ($_.Enabled) { "green" } else { "red" }
                
                @"
<tr>
    <td>$($_.DisplayName)</td>
    <td>$($_.SamAccountName)</td>
    <td>$($_.EmailAddress)</td>
    <td>$($_.Title)</td>
    <td>$($_.Department)</td>
    <td>$($_.Description)</td>
    <td>$($_.Company)</td>
    <td style='color: $statusColor;'>$($_.AccountStatus)</td>
</tr>
"@
            }

            @"
<h3>$currentGroup Members (Total: $($groupUsers.Count))</h3>
<table border='1'>
<tr>
    <th>Display Name</th>
    <th>Username</th>
    <th>Email Address</th>
    <th>Title</th>
    <th>Department</th>
    <th>Description</th>
    <th>Company</th>
    <th>Account Status</th>
</tr>
$($userRows -join "`n")
</table>
<br>
"@
        }

        $successfulReport = $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        $errorLogEntry = "$reportTime | ERROR | Failed to generate security groups report: $errorMessage"
        Add-Content -Path $logFile -Value $errorLogEntry
        Write-Error $errorLogEntry
    }

    # Prepare and send the appropriate email based on success/failure
    if ($successfulReport) {
        $EmailBody = @"
<h2>HR Security Groups Report</h2>
<p>Report Generated: <strong>$reportTime</strong></p>
<p>Total Users Across All Groups: <strong>$($allGroupMembers.Count)</strong></p>

$($groupSections -join "`n")

<p>Please find the detailed log file and CSV export attached.</p>
"@
        $attachments = @($logFile, $csvFile)
    }
    else {
        $EmailSubject += " - FAILED"
        $EmailBody = @"
<h2>HR Security Groups Report - FAILED</h2>
<p>An error occurred while generating the users report.</p>
<p>Error Details: $errorMessage</p>
<p>Please find the detailed log file attached.</p>
"@
        $attachments = @($logFile)
    }

    # Send single email with appropriate content
    $EmailParams = @{
        To = $EmailTo
        From = $EmailFrom
        Subject = $EmailSubject
        Body = $EmailBody
        BodyAsHtml = $true
        SmtpServer = $MailSMTP
        Port = $MailPort
        Attachments = $attachments
    }

    if($MailSSL -eq "True") {
        $EmailParams.Add("UseSsl", $true)
        Write-Verbose "SSL enabled for email sending"
    }

    try {
        Send-MailMessage @EmailParams
        Write-Verbose "Email report sent successfully"
    }
    catch {
        Write-Error "Failed to send email: $($_.Exception.Message)"
    }
}