# Force verbose output always on
$Global:VerbosePreference = "Continue"
Write-Verbose "Script started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Verbose "Running as user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# Fixed configurations
$LogPath = "C:\Logs\ServerBuildReports"
$EmailTo = @("User@Domain.com")
$EmailFrom = "ServiceDesk@domain.com"
$EmailSubject = "Enterprise Server Build and Updates Report"
$timestamp = Get-Date -Format "yyyyMMdd"
$logFile = Join-Path -Path $LogPath -ChildPath "EnterpriseBuild_$timestamp.log"
$reportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Define root OU for server search
$rootOU = "OU=Servers Live,DC=Domain,DC=com"

# Create log directory if it doesn't exist
if (-not (Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    "$reportTime | INFO | Created log directory: $LogPath" | Add-Content -Path $logFile
}

"$reportTime | INFO | Starting enterprise server build check script" | Add-Content -Path $logFile

# Start Server Discovery
"$reportTime | INFO | Starting server discovery" | Add-Content -Path $logFile

$servers = @()

# Search Active Directory including all sub-OUs
Write-Verbose "Starting Active Directory search in: $rootOU"
Write-Verbose "This will include all sub-OUs under this location"
"$reportTime | INFO | Searching in OU and sub-OUs of: $rootOU" | Add-Content -Path $logFile

try {
    Write-Verbose "Executing AD query for Windows Servers..."
    $servers = Get-ADComputer -SearchBase $rootOU -SearchScope Subtree -Filter {
        (OperatingSystem -like "*Windows Server*") -and 
        (Enabled -eq $true)
    } -Properties OperatingSystem, Description, Created, Modified, LastLogonDate |
    Select-Object Name, OperatingSystem, Description, Created, Modified, LastLogonDate, DistinguishedName
    
    Write-Verbose "Found $($servers.Count) total servers in AD"
    Write-Verbose "Breaking down server OS versions found:"
    $servers | Group-Object OperatingSystem | ForEach-Object {
        Write-Verbose "  $($_.Name): $($_.Count) servers"
    }
    "$reportTime | INFO | Found $($servers.Count) servers in $rootOU and sub-OUs" | Add-Content -Path $logFile
}
catch {
    Write-Verbose "Error occurred during AD search!"
    "$reportTime | ERROR | Failed to search OU $rootOU : $_" | Add-Content -Path $logFile
    $servers = @()
}

# Search DNS Records
"$reportTime | INFO | Checking DNS records for additional servers" | Add-Content -Path $logFile
try {
    $dnsServers = Get-DnsServerResourceRecord -ZoneName "domain.com" -RRType "A" |
        Where-Object { $_.HostName -like "*srv*" -or $_.HostName -like "*server*" } |
        Select-Object HostName, RecordType, Timestamp

    foreach ($dnsServer in $dnsServers) {
        if ($servers.Name -notcontains $dnsServer.HostName) {
            "$reportTime | INFO | Found additional server in DNS: $($dnsServer.HostName)" | Add-Content -Path $logFile
            try {
                $adInfo = Get-ADComputer -Identity $dnsServer.HostName -Properties OperatingSystem, Description, Created, Modified, LastLogonDate
                if ($adInfo) {
                    $servers += $adInfo | Select-Object Name, OperatingSystem, Description, Created, Modified, LastLogonDate, DistinguishedName
                }
            }
            catch {
                "$reportTime | WARNING | DNS server $($dnsServer.HostName) not found in AD" | Add-Content -Path $logFile
            }
        }
    }
}
catch {
    "$reportTime | ERROR | Failed to check DNS records: $_" | Add-Content -Path $logFile
}

# Remove duplicates
$servers = $servers | Sort-Object Name -Unique

"$reportTime | INFO | Total unique servers found: $($servers.Count)" | Add-Content -Path $logFile

# Initialize results array
$serverResults = @()

# Process each server
foreach ($server in $servers) {
    Write-Verbose "==============================================="
    Write-Verbose "Processing server: $($server.Name)"
    Write-Verbose "OS: $($server.OperatingSystem)"
    Write-Verbose "Last Logon: $($server.LastLogonDate)"
    "$reportTime | INFO | Processing server: $($server.Name)" | Add-Content -Path $logFile
    
    try {
        # Test connection first
        Write-Verbose "Testing connection to $($server.Name)..."
        if (Test-Connection -ComputerName $server.Name -Count 1 -Quiet) {
            Write-Verbose "Connection successful - collecting OS information..."
            # Verify OS
            $osInfo = Invoke-Command -ComputerName $server.Name -ScriptBlock {
                Get-WmiObject -Class Win32_OperatingSystem
            } -ErrorAction Stop
            
            Write-Verbose "OS information collected successfully"
            Write-Verbose "Checking for Windows Updates..."
            # Get Update Info
            $updateInfo = Invoke-Command -ComputerName $server.Name -ScriptBlock {
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Searcher = $Session.CreateUpdateSearcher()
                Write-Verbose "Searching for updates..."
                $SearchResult = $Searcher.Search("IsInstalled=0")
                
                $Updates = @{
                    Count = $SearchResult.Updates.Count
                    Updates = @()
                }
                
                Write-Verbose "Processing $($SearchResult.Updates.Count) updates..."
                foreach ($Update in $SearchResult.Updates) {
                    $Updates.Updates += [PSCustomObject]@{
                        Title = $Update.Title
                        IsMandatory = $Update.IsMandatory
                        RelevantKBArticleIDs = $Update.KBArticleIDs
                        Severity = $Update.MsrcSeverity
                    }
                }
                return $Updates
            } -ErrorAction Stop
            
            Write-Verbose "Found $($updateInfo.Count) total updates"
            $importantCount = @($updateInfo.Updates | Where-Object { $_.IsMandatory -eq $true }).Count
            Write-Verbose "Important updates needed: $importantCount"
            
            # Add to results
            if ($osInfo -and $osInfo.PSObject.Properties['CollectionMethod']) {
                $collectionMethod = $osInfo.CollectionMethod
            } else {
                $collectionMethod = if (Test-WSMan -ComputerName $server.Name -ErrorAction SilentlyContinue) {
                    "WinRM"
                } else {
                    "WMI Fallback"
                }
            }
            
            Write-Verbose ("=" * 70)
            Write-Verbose "Server: $($server.Name)"
            Write-Verbose "Attempting collection using: $collectionMethod"
            
            try {
                if ($collectionMethod -eq "WinRM") {
                    $osInfo = Invoke-Command -ComputerName $server.Name -ScriptBlock {
                        $os = Get-WmiObject -Class Win32_OperatingSystem
                        $bootTime = $null
                        if ($os.LastBootUpTime) {
                            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
                        }
                        [PSCustomObject]@{
                            Caption = $os.Caption
                            BuildNumber = $os.BuildNumber
                            OSArchitecture = $os.OSArchitecture
                            LastBootTime = $bootTime
                            Version = $os.Version
                        }
                    }
                } else {
                    $os = Get-WmiObject -ComputerName $server.Name -Class Win32_OperatingSystem
                    $bootTime = $null
                    if ($os.LastBootUpTime) {
                        $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
                    }
                    $osInfo = [PSCustomObject]@{
                        Caption = $os.Caption
                        BuildNumber = $os.BuildNumber
                        OSArchitecture = $os.OSArchitecture
                        LastBootTime = $bootTime
                        Version = $os.Version
                    }
                }
                
                # Get update info based on collection method
                if ($collectionMethod -eq "WinRM") {
                    Write-Verbose "Checking Windows Update service status..."
                    try {
                        $updateInfo = Invoke-Command -ComputerName $server.Name -ScriptBlock {
                            # Function to safely check updates with retries
                            function Get-UpdatesWithRetry {
                                param(
                                    [int]$MaxAttempts = 3,
                                    [int]$WaitSeconds = 30
                                )
                                
                                for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
                                    Write-Verbose "Update check attempt $attempt of $MaxAttempts"
                                    try {
                                        # Check and handle Windows Update service
                                        $wuauserv = Get-Service -Name "wuauserv"
                                        Write-Verbose "Windows Update Service Status: $($wuauserv.Status)"
                                        
                                        if ($wuauserv.Status -ne "Running") {
                                            Write-Verbose "Starting Windows Update service..."
                                            Stop-Service -Name "wuauserv" -Force
                                            Start-Sleep -Seconds 5
                                            Start-Service -Name "wuauserv"
                                            Start-Sleep -Seconds 10
                                        }

                                        $Session = New-Object -ComObject Microsoft.Update.Session
                                        $Searcher = $Session.CreateUpdateSearcher()
                                        
                                        Write-Verbose "Initiating update search..."
                                        try {
                                            $SearchResult = $Searcher.Search("IsInstalled=0")
                                            Write-Verbose "Update search completed successfully"
                                            return @{
                                                Count = $SearchResult.Updates.Count
                                                Updates = @($SearchResult.Updates | ForEach-Object {
                                                    @{
                                                        Title = $_.Title
                                                        IsMandatory = $_.IsMandatory
                                                        RelevantKBArticleIDs = $_.KBArticleIDs
                                                        Severity = $_.MsrcSeverity
                                                    }
                                                })
                                                Error = $null
                                            }
                                        }
                                        catch [System.Runtime.InteropServices.COMException] {
                                            if ($_.Exception.HResult -eq 0x8024402C) {
                                                Write-Verbose "Windows Update is busy (0x8024402C) - waiting $WaitSeconds seconds..."
                                                Start-Sleep -Seconds $WaitSeconds
                                                if ($attempt -eq $MaxAttempts) {
                                                    throw "Maximum retry attempts reached for Windows Update check"
                                                }
                                                continue
                                            }
                                            else {
                                                throw $_
                                            }
                                        }
                                    }
                                    catch {
                                        if ($attempt -eq $MaxAttempts) {
                                            throw $_
                                        }
                                        Write-Verbose "Attempt $attempt failed: $_"
                                        Start-Sleep -Seconds $WaitSeconds
                                    }
                                }
                            }

                            # Execute the retry function
                            try {
                                Get-UpdatesWithRetry
                            }
                            catch {
                                @{
                                    Count = "Error - Update Check Failed"
                                    Updates = @()
                                    Error = $_.ToString()
                                }
                            }
                        } -ErrorAction Stop
                        
                        if ($updateInfo.Error) {
                            Write-Verbose "Update check completed with error: $($updateInfo.Error)"
                        }
                        else {
                            Write-Verbose "Successfully found $($updateInfo.Count) updates"
                        }
                    }
                    catch {
                        Write-Verbose "Failed to check updates: $_"
                        $updateInfo = @{
                            Count = "Error - Connection Failed"
                            Updates = @()
                            Error = $_.Exception.Message
                        }
                    }
                        
                        if ($updateInfo.Error) {
                            Write-Verbose "Update check completed with error: $($updateInfo.Error)"
                        }
                        else {
                            Write-Verbose "Successfully found $($updateInfo.Count) updates"
                        }
                    }
                    catch {
                        Write-Verbose "Failed to check updates: $_"
                        $updateInfo = @{
                            Count = "Error - Connection Failed"
                            Updates = @()
                            Error = $_.Exception.Message
                        }
                    }
                }
                } else {
                    Write-Verbose "Update check not available via WMI..."
                    $updateInfo = @{
                        Count = "Unknown (WinRM Required)"
                        Updates = @()
                    }
                }

                $serverResults += [PSCustomObject]@{
                    ServerName = $server.Name
                    Status = "Online"
                    OSVersion = $osInfo.Caption
                    BuildNumber = $osInfo.BuildNumber
                    Architecture = $osInfo.OSArchitecture
                    LastBootTime = if ($osInfo.LastBootTime) { $osInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    TotalUpdates = $updateInfo.Count
                    ImportantUpdates = if ($updateInfo.Error) { "Error: $($updateInfo.Error)" } else { @($updateInfo.Updates | Where-Object { $_.IsMandatory -eq $true }) }
                    Error = $updateInfo.Error
                    Description = $server.Description
                    LastLogonDate = $server.LastLogonDate
                    CollectionMethod = $collectionMethod
                    UpdateServiceStatus = if ($updateInfo.Error) { "Error" } else { "OK" }
                }
                
                Write-Verbose ("=" * 70)
                Write-Verbose "Server: $($server.Name)"
                Write-Verbose "Collection Method: $collectionMethod"
                Write-Verbose "OS Version: $($osInfo.Caption)"
                Write-Verbose "Updates Found: $($updateInfo.Count)"
                Write-Verbose ("=" * 70)
            }
            catch {
                Write-Verbose "Error during collection: $_"
                $serverResults += [PSCustomObject]@{
                    ServerName = $server.Name
                    Status = "Error"
                    Description = $server.Description
                    LastLogonDate = $server.LastLogonDate
                    Error = $_.Exception.Message
                    CollectionMethod = "Failed - $collectionMethod"
                }
            }
            
            Write-Verbose "Successfully processed $($server.Name)"
            "$reportTime | INFO | Successfully processed $($server.Name)" | Add-Content -Path $logFile
        } 
        else {
            Write-Verbose "Server $($server.Name) is OFFLINE"
            $serverResults += [PSCustomObject]@{
                ServerName = $server.Name
                Status = "Offline"
                Description = $server.Description
                LastLogonDate = $server.LastLogonDate
                Error = "Server not responding"
            }
            "$reportTime | WARNING | Server $($server.Name) is offline" | Add-Content -Path $logFile
        }
    }
    catch {
        Write-Verbose "ERROR processing $($server.Name): $($_.Exception.Message)"
        $serverResults += [PSCustomObject]@{
            ServerName = $server.Name
            Status = "Error"
            Description = $server.Description
            LastLogonDate = $server.LastLogonDate
            Error = $_.Exception.Message
        }
        "$reportTime | ERROR | Failed to process $($server.Name) : $_" | Add-Content -Path $logFile
    }
}

# Get mail server configuration
"$reportTime | INFO | Retrieving mail server configuration" | Add-Content -Path $logFile
try {
    $DefaultEmail = Get-QADObject -Identity "CN=Default Mail Settings,CN=Mail Configuration,CN=Server Configuration,CN=Configuration" -DontUseDefaultIncludedProperties -IncludedProperties edsaRuleDefinition -Proxy
    [xml]$MailSettings = $DefaultEmail.edsaRuleDefinition
    $MailSMTP = $MailSettings.MailConfiguration.Server.host
    $MailPort = $MailSettings.MailConfiguration.Server.port
    $MailSSL = $MailSettings.MailConfiguration.Server.ssl
    "$reportTime | INFO | Mail server configuration retrieved successfully" | Add-Content -Path $logFile
    $mailConfigSuccess = $true
}
catch {
    "$reportTime | ERROR | Failed to retrieve mail server configuration: $_" | Add-Content -Path $logFile
    $mailConfigSuccess = $false
}

# Prepare summary statistics
Write-Verbose "==============================================="
Write-Verbose "Preparing final report statistics..."
$totalServers = $serverResults.Count
$onlineServers = @($serverResults | Where-Object { $_.Status -eq "Online" }).Count
$offlineServers = @($serverResults | Where-Object { $_.Status -eq "Offline" }).Count
$errorServers = @($serverResults | Where-Object { $_.Status -eq "Error" }).Count
$totalImportantUpdates = ($serverResults | Where-Object { $_.Status -eq "Online" } | ForEach-Object { $_.ImportantUpdates.Count } | Measure-Object -Sum).Sum

Write-Verbose "Report Statistics:"
Write-Verbose "  Total Servers: $totalServers"
Write-Verbose "  Online: $onlineServers"
Write-Verbose "  Offline: $offlineServers"
Write-Verbose "  Errors: $errorServers"
Write-Verbose "  Total Important Updates Required: $totalImportantUpdates"

# Export to CSV
Write-Verbose "Preparing CSV report..."
$csvFile = Join-Path -Path $LogPath -ChildPath "ServerReport_$timestamp.csv"

# Create detailed CSV report
$csvData = $serverResults | ForEach-Object {
    $server = $_
    if ($server.Status -eq "Online") {
        [PSCustomObject]@{
            'Server Name' = $server.ServerName
            'Status' = $server.Status
            'OS Version' = $server.OSVersion
            'Build Number' = $server.BuildNumber
            'Architecture' = $server.Architecture
            'Last Boot Time' = $server.LastBootTime
            'Description' = $server.Description
            'Last Logon Date' = $server.LastLogonDate
            'Total Updates Pending' = $server.TotalUpdates
            'Important Updates Pending' = $server.ImportantUpdates.Count
            'Error' = $server.Error
        }
    } else {
        [PSCustomObject]@{
            'Server Name' = $server.ServerName
            'Status' = $server.Status
            'OS Version' = ''
            'Build Number' = ''
            'Architecture' = ''
            'Last Boot Time' = ''
            'Description' = $server.Description
            'Last Logon Date' = $server.LastLogonDate
            'Total Updates Pending' = ''
            'Important Updates Pending' = ''
            'Error' = $server.Error
        }
    }
}

Write-Verbose "Exporting to CSV: $csvFile"
$csvData | Export-Csv -Path $csvFile -NoTypeInformation

# Create HTML Report
$htmlBody = @"
<h2>Enterprise Server Build and Updates Report</h2>
<p>Report Generated: <strong>$reportTime</strong></p>

<h3>Summary:</h3>
<ul>
    <li>Total Servers: <strong>$totalServers</strong></li>
    <li>Online Servers: <strong>$onlineServers</strong></li>
    <li>Offline Servers: <strong>$offlineServers</strong></li>
    <li>Error Servers: <strong>$errorServers</strong></li>
    <li>Total Important Updates Required: <strong>$totalImportantUpdates</strong></li>
</ul>

<h3>Servers Requiring Attention:</h3>
"@

# Add offline servers section
if ($offlineServers -gt 0) {
    $htmlBody += @"
<h4>Offline Servers:</h4>
<table border='1'>
<tr>
    <th>Server Name</th>
    <th>Description</th>
    <th>Last Logon Date</th>
</tr>
"@
    $serverResults | Where-Object { $_.Status -eq "Offline" } | ForEach-Object {
        $htmlBody += "<tr><td>$($_.ServerName)</td><td>$($_.Description)</td><td>$($_.LastLogonDate)</td></tr>"
    }
    $htmlBody += "</table>"
}

# Add error servers section
if ($errorServers -gt 0) {
    $htmlBody += @"
<h4>Servers with Errors:</h4>
<table border='1'>
<tr>
    <th>Server Name</th>
    <th>Description</th>
    <th>Last Logon Date</th>
    <th>Error</th>
</tr>
"@
    $serverResults | Where-Object { $_.Status -eq "Error" } | ForEach-Object {
        $htmlBody += "<tr><td>$($_.ServerName)</td><td>$($_.Description)</td><td>$($_.LastLogonDate)</td><td>$($_.Error)</td></tr>"
    }
    $htmlBody += "</table>"
}

# Add servers with important updates section
$serversWithUpdates = $serverResults | Where-Object { $_.Status -eq "Online" -and $_.ImportantUpdates.Count -gt 0 }
if ($serversWithUpdates) {
    $htmlBody += @"
<h4>Servers Requiring Important Updates:</h4>
<table border='1'>
<tr>
    <th>Server Name</th>
    <th>Description</th>
    <th>OS Version</th>
    <th>Build Number</th>
    <th>Updates Required</th>
    <th>Last Boot Time</th>
</tr>
"@
    foreach ($server in $serversWithUpdates) {
        $htmlBody += @"
<tr>
    <td>$($server.ServerName)</td>
    <td>$($server.Description)</td>
    <td>$($server.OSVersion)</td>
    <td>$($server.BuildNumber)</td>
    <td>$($server.ImportantUpdates.Count)</td>
    <td>$($server.LastBootTime)</td>
</tr>
"@
    }
    $htmlBody += "</table>"
}

$htmlBody += "<p>Please find the detailed log file attached.</p>"

# Send email if mail configuration was successful
if ($mailConfigSuccess) {
    $EmailParams = @{
        To = $EmailTo
        From = $EmailFrom
        Subject = $EmailSubject
        Body = $htmlBody
        BodyAsHtml = $true
        SmtpServer = $MailSMTP
        Port = $MailPort
        Attachments = @($logFile, $csvFile)
    }

    if ($MailSSL -eq "True") {
        $EmailParams.UseSsl = $true
        "$reportTime | INFO | SSL enabled for email sending" | Add-Content -Path $logFile
    }

    try {
        Write-Verbose "Sending email with attachments:"
        Write-Verbose "  - Log file: $logFile"
        Write-Verbose "  - CSV Report: $csvFile"
        Send-MailMessage @EmailParams
        "$reportTime | INFO | Email report sent successfully" | Add-Content -Path $logFile
        Write-Verbose "Email sent successfully"
    }
    catch {
        "$reportTime | ERROR | Failed to send email: $($_.Exception.Message)" | Add-Content -Path $logFile
        Write-Verbose "Failed to send email: $($_.Exception.Message)"
    }
}
else {
    "$reportTime | ERROR | Could not send email due to mail configuration failure" | Add-Content -Path $logFile
}

