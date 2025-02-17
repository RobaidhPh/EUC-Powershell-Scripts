# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires administrator privileges"
    Write-Host "Please re-run PowerShell as Administrator"
    exit 1
}

Write-Host "Configuring Quad9 encrypted DNS..."

try {
    # Configure both primary and secondary DNS servers with DoH templates
    Write-Host "Configuring DoH templates for Quad9..."
    
    # Primary DNS
    netsh dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
    
    # Secondary DNS
    netsh dns add encryption server=149.112.112.112 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
    
    # Enable DoH at system level
    Write-Host "Enabling DoH..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type DWord
    
    Write-Host "Restarting DNS Client service..."
    
    # Check current service status
    Write-Host "Current DNS Client service status:"
    Get-Service -Name "*DNS*" | Format-Table Name, DisplayName, Status
    
    # Restart service using SC command
    Write-Host "Attempting to restart DNS Client service..."
    try {
        # Stop the service
        $stopResult = (Start-Process -FilePath "sc.exe" -ArgumentList "stop Dnscache" -Wait -PassThru -Verb RunAs).ExitCode
        Write-Host "Stop service result: $stopResult"
        
        Start-Sleep -Seconds 2
        
        # Start the service
        $startResult = (Start-Process -FilePath "sc.exe" -ArgumentList "start Dnscache" -Wait -PassThru -Verb RunAs).ExitCode
        Write-Host "Start service result: $startResult"
        
        Write-Host "Service restart attempted. Checking final status:"
        Get-Service -Name "*DNS*" | Format-Table Name, DisplayName, Status
    }
    catch {
        Write-Host "Error managing service: $_"
        Write-Host "A system restart may be required to complete the configuration."
    }
    
    Write-Host "`nConfiguration complete. Please check Windows Settings to verify encryption status."
    Write-Host "If encryption is not showing as enabled, a system restart may be required."
}
catch {
    Write-Host "Error configuring DNS: $_"
    Write-Host "Error details: $($_.Exception.Message)"
}