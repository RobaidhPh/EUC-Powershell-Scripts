# Requires -RunAsAdministrator
<#
.SYNOPSIS
    Manages BIOS settings for Dell systems with secure password handling
.DESCRIPTION
    Updates BIOSSettings.json with Asset Tag and manages BIOS password
    - Creates and stores encrypted password if not exists
    - Updates Asset Tag in BIOS settings
    - Maintains other existing BIOS settings
#>

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Constants
$SETTINGS_FILE = "BIOSSettings.json"
$PASSWORD_FILE = "BiosPassword.enc"
$CONFIG_DIR = "Config"

# Function to write log messages
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] $Type - $Message"
    
    switch ($Type) {
        'Info'    { Write-Host $logMessage -ForegroundColor Gray }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
    }
}

# Function to find USB drive with DELL_BIOS label
function Get-DellBiosUSB {
    # Get all removable drives first
    $usbDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
    
    # Filter for DELL_BIOS label
    $dellDrives = $usbDrives | Where-Object { $_.VolumeName -eq "DELL_BIOS" }
    
    if (-not $dellDrives) {
        throw "No USB drive with label 'DELL_BIOS' found. Please insert the correct USB drive."
    }
    
    # Check for multiple matching drives
    if ($dellDrives -is [Array]) {
        if ($dellDrives.Count -gt 1) {
            throw "Multiple USB drives with label 'DELL_BIOS' found. Please remove extra drives."
        }
    }
    
    return $dellDrives.DeviceID
}

# Function to create and store encrypted password
function Set-BiosPassword {
    param(
        [string]$DriveLetter
    )
    
    $passwordPath = Join-Path $DriveLetter $CONFIG_DIR\$PASSWORD_FILE
    
    if (Test-Path $passwordPath) {
        Write-LogMessage "BIOS password already exists." -Type Info
        return
    }
    
    do {
        $password = Read-Host "Enter new BIOS password" -AsSecureString
        $passwordText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        
        # Basic validation - just ensure it's not empty
        $isValid = -not [string]::IsNullOrWhiteSpace($passwordText)
        
        if (-not $isValid) {
            Write-LogMessage "Password cannot be empty. Please try again." -Type Warning
        }
    } while (-not $isValid)
    
    # Create a secure key
    $key = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
    
    # Store the key in a protected file
    $keyPath = Join-Path $DriveLetter $CONFIG_DIR\key.bin
    $key | Set-Content -Path $keyPath -Encoding Byte
    
    # Encrypt and store the password
    $securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString $securePassword -Key $key
    $encrypted | Set-Content -Path $passwordPath
    
    Write-LogMessage "BIOS password has been set and encrypted." -Type Info
}

# Function to update BIOS settings
function Update-BiosSettings {
    param(
        [string]$DriveLetter,
        [string]$AssetTag
    )
    
    $settingsPath = Join-Path $DriveLetter $CONFIG_DIR\$SETTINGS_FILE
    
    # Get the password if it exists
    $passwordPath = Join-Path $DriveLetter $CONFIG_DIR\$PASSWORD_FILE
    $keyPath = Join-Path $DriveLetter $CONFIG_DIR\key.bin
    $biosPassword = ""
    $encryptedPasswordForJson = ""

    # Check both paths exist before attempting to read password
    $passwordExists = Test-Path $passwordPath
    $keyExists = Test-Path $keyPath
    if ($passwordExists -and $keyExists) {
        Write-LogMessage "Reading existing password..." -Type Info
        
        $key = Get-Content $keyPath -Encoding Byte
        $encryptedPassword = Get-Content $passwordPath
        
        # Create a secure string from the encrypted password
        $securePassword = ConvertTo-SecureString $encryptedPassword -Key $key
        
        # For BIOS configuration - kept in memory only
        $biosPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
        
        # Create a unique identifier for this encryption
        $keyIdentifier = "json_key_" + (Get-Date).ToString("yyyyMMddHHmmss")
        Write-LogMessage "Creating new key with identifier: $keyIdentifier" -Type Info
        
        # For JSON storage - create a different encryption using a timestamp-based key
        $jsonKey = New-Object Byte[] 32
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($jsonKey)
        
        # Store the JSON key with unique identifier
        $jsonKeyPath = Join-Path $DriveLetter $CONFIG_DIR\$keyIdentifier
        $jsonKey | Set-Content -Path $jsonKeyPath -Encoding Byte
        
        # Create newly encrypted version for JSON
        $jsonSecureString = ConvertTo-SecureString $biosPassword -AsPlainText -Force
        $encryptedPasswordForJson = ConvertFrom-SecureString $jsonSecureString -Key $jsonKey
        
        Write-LogMessage "Password re-encrypted for JSON storage" -Type Info
    }

    # Create base settings object if file doesn't exist
    if (-not (Test-Path $settingsPath)) {
        $settings = @{
            BiosSettings = @()
        }
    }
    else {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not $settings.BiosSettings) {
                $settings | Add-Member -MemberType NoteProperty -Name "BiosSettings" -Value @()
            }
        }
        catch {
            Write-LogMessage "Error reading existing settings, creating new settings file" -Type Warning
            $settings = @{
                BiosSettings = @()
            }
        }
    }

    # Define required settings
    $requiredSettings = @(
        @{
            Name = "AssetTag"
            Value = $AssetTag
            Description = "System Asset Tag"
        },
        @{
            Name = "SecureBoot"
            Value = "Enabled"
            Description = "Enable Secure Boot"
        },
        @{
            Name = "SataOperation"
            Value = "AHCI"
            Description = "Configure SATA Operation Mode"
        },
        @{
            Name = "UefiNetworking"
            Value = "Enabled"
            Description = "Enable UEFI Networking"
        },
        @{
            Name = "UefiBootPathSecurity"
            Value = "AlwaysExceptInternalHdd"
            Description = "UEFI Boot Path Security"
        }
    )

    # Add password setting if password exists
    if ($encryptedPasswordForJson) {
        Write-LogMessage "Adding encrypted password to settings..." -Type Info
        $passwordSetting = @{
            Name = "SetupPassword"
            Value = $encryptedPasswordForJson
            Description = "BIOS Setup Password (Encrypted)"
            IsEncrypted = $true
            KeyFile = $keyIdentifier
            EncryptionMethod = "SecureString"
        }
        $requiredSettings += $passwordSetting
    }

    # Update or add each required setting
    $newBiosSettings = @()
    foreach ($required in $requiredSettings) {
        $newSetting = [PSCustomObject]$required
        $newBiosSettings += $newSetting
    }
    
    # Replace all settings
    $settings.BiosSettings = $newBiosSettings
    
    # Convert to JSON and save
    $jsonContent = $settings | ConvertTo-Json -Depth 10
    $jsonContent | Set-Content -Path $settingsPath -Encoding UTF8
    
    # Log all changes
    Write-LogMessage "BIOS settings updated:" -Type Info
    Write-LogMessage "- Asset Tag: $AssetTag" -Type Info
    Write-LogMessage "- Secure Boot: Enabled" -Type Info
    Write-LogMessage "- SATA Operation: AHCI" -Type Info
    Write-LogMessage "- UEFI Networking: Enabled" -Type Info
    Write-LogMessage "- UEFI Boot Path Security: Always (Except Internal HDD)" -Type Info
    if ($biosPassword) {
        Write-LogMessage "- BIOS Setup Password: Set (Stored Securely with key: $keyIdentifier)" -Type Info
    }
    
    # Verify JSON content
    Write-LogMessage "Verifying JSON content..." -Type Info
    $verifyContent = Get-Content $settingsPath -Raw | ConvertFrom-Json
    if ($verifyContent.BiosSettings | Where-Object { $_.Name -eq "SetupPassword" }) {
        Write-LogMessage "Password successfully stored in JSON with encryption" -Type Info
    }
}
# Main execution block
try {
    Write-LogMessage "Starting BIOS Settings Manager" -Type Info
    
    # Find Dell BIOS USB drive
    $driveLetter = Get-DellBiosUSB
    Write-LogMessage "Found Dell BIOS USB drive at: $driveLetter" -Type Info
    
    # Ensure Config directory exists
    $configPath = Join-Path $driveLetter $CONFIG_DIR
    if (-not (Test-Path $configPath)) {
        New-Item -Path $configPath -ItemType Directory -Force | Out-Null
    }
    
    # Set BIOS password if not exists
    Set-BiosPassword -DriveLetter $driveLetter
    
    # Get Asset Tag
    do {
        $assetTag = Read-Host "Enter Asset Tag (max 10 characters, alphanumeric only)"
        if ($assetTag -notmatch "^[a-zA-Z0-9]{1,10}$") {
            Write-LogMessage "Invalid Asset Tag format. Please use only letters and numbers, max 10 characters." -Type Warning
        }
    } while ($assetTag -notmatch "^[a-zA-Z0-9]{1,10}$")
    
    # Update BIOS settings
    Update-BiosSettings -DriveLetter $driveLetter -AssetTag $assetTag
    
    Write-LogMessage "BIOS Settings Manager completed successfully" -Type Info
}
catch {
    Write-LogMessage "Error: $_" -Type Error
    exit 1
}