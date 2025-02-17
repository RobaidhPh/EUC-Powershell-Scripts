#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates bootable WinPE USB for Dell BIOS Configuration with ADK installation
.DESCRIPTION
    Downloads and installs Windows ADK if needed, creates WinPE media, and sets up a bootable USB
    for Dell BIOS configuration deployment
.NOTES
    - Requires administrator rights
    - Internet connection needed for ADK download
    - USB drive will be formatted
#>

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Start logging
$logFile = "WinPE_BIOS_Creation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logPath = Join-Path $env:USERPROFILE\Desktop $logFile
Start-Transcript -Path $logPath

# ADK Installation Settings
$adkUrl = "https://go.microsoft.com/fwlink/?linkid=2196127"  # Windows 11 ADK
$adkPEUrl = "https://go.microsoft.com/fwlink/?linkid=2196224" # Windows PE add-on
$downloadPath = "$env:TEMP\ADK"

# Predefined paths
$workspacePath = "C:\WinPE_BIOS"
$mountPath = "C:\WinPE_BIOS\mount"

# Logging function
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
function Remove-ExistingADK {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Checking for existing ADK installations..." -Type Info
    
    $adkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit",
        "${env:ProgramFiles}\Windows Kits\10\Assessment and Deployment Kit"
    )
    
    foreach ($adkPath in $adkPaths) {
        $uninstallers = @(
            "$adkPath\Uninstall.exe",
            "$adkPath\Windows Preinstallation Environment\Uninstall.exe"
        )
        
        foreach ($uninstaller in $uninstallers) {
            if (Test-Path $uninstaller) {
                Write-LogMessage "Running uninstaller: $uninstaller" -Type Info
                $process = Start-Process -FilePath $uninstaller -ArgumentList "/quiet /uninstall" -Wait -PassThru
                if ($process.ExitCode -ne 0) {
                    Write-LogMessage "Uninstaller exited with code: $($process.ExitCode)" -Type Warning
                }
                Start-Sleep -Seconds 10  # Wait for uninstall to complete
            }
        }
        
        # Force remove any remaining directories
        if (Test-Path $adkPath) {
            Write-LogMessage "Removing remaining ADK directory: $adkPath" -Type Info
            Remove-Item -Path $adkPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Clean registry entries
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots",
        "HKLM:\SOFTWARE\Microsoft\Windows Kits\Assessment and Deployment Kit",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Assessment and Deployment Kit"
    )
    
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            Write-LogMessage "Removing registry key: $regPath" -Type Info
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ADKInstallation {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Checking existing ADK installation..." -Type Info
    
    $adkPath = "C:\Program Files (x86)\Windows Kits\10"
    
    # Required components to check
    $requiredPaths = @(
        "$adkPath\Assessment and Deployment Kit\Windows Preinstallation Environment",
        "$adkPath\Assessment and Deployment Kit\Deployment Tools",
        "$adkPath\Assessment and Deployment Kit\Deployment Tools\amd64\DISM"
    )
    
    $missing = @()
    foreach ($path in $requiredPaths) {
        if (-not (Test-Path $path)) {
            $missing += $path
            Write-LogMessage "Missing required ADK component: $path" -Type Warning
        }
    }
    
    if ($missing.Count -gt 0) {
        throw "Windows ADK components not found. Please install Windows ADK and WinPE add-on from https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install"
    }
    
    Write-LogMessage "ADK installation verified at $adkPath" -Type Info
    return $true
}

function Test-ADKRequirements {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Checking ADK installation requirements..." -Type Info
        
        # Check available disk space (need at least 10GB)
        $systemDrive = $env:SystemDrive
        $drive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        
        if ($freeSpaceGB -lt 10) {
            throw "Insufficient disk space. Required: 10GB, Available: $freeSpaceGB GB"
        }
        
        # Check Windows version
        $os = Get-WmiObject Win32_OperatingSystem
        $version = [Version]$os.Version
        if ($version -lt [Version]"10.0") {
            throw "Windows 10 or later is required for ADK installation"
        }
        
        # Check if running as administrator
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Administrator privileges required"
        }
        
        # Check internet connectivity
        try {
            $testConnection = Test-NetConnection -ComputerName "download.microsoft.com" -Port 443
            if (-not $testConnection.TcpTestSucceeded) {
                throw "Cannot connect to Microsoft download servers"
            }
        }
        catch {
            throw "Internet connectivity test failed: $_"
        }
        
        Write-LogMessage "All ADK installation requirements met" -Type Info
        return $true
    }
    catch {
        Write-LogMessage "ADK requirements check failed: $_" -Type Error
        throw
    }
}

function Get-SystemArchitecture {
    [CmdletBinding()]
    param()

    $processor = Get-WmiObject Win32_Processor | Select-Object -First 1 -ExpandProperty Architecture
    
    # Map WMI architecture values to strings
    $archMap = @{
        0  = "x86"    # x86
        5  = "arm"    # ARM
        9  = "amd64"  # x64
        12 = "arm64"  # ARM64
    }
    
    $arch = $archMap[$processor]
    if (-not $arch) {
        $arch = "amd64"  # Default to amd64 if unknown
    }
    
    Write-LogMessage "Detected system architecture: $arch" -Type Info
    return $arch
}

function Find-ADKInstallation {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Searching for ADK installation..." -Type Info
    
    # Possible ADK installation paths
    $possiblePaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit",
        "${env:ProgramFiles(x86)}\Windows Kits\10",
        "${env:ProgramFiles}\Windows Kits\10\Assessment and Deployment Kit",
        "${env:ProgramFiles}\Windows Kits\10"
    )
    
    # Search for WinPE directories
    foreach ($basePath in $possiblePaths) {
        Write-LogMessage "Checking path: $basePath" -Type Info
        
        $winPEPaths = @(
            "$basePath\Windows Preinstallation Environment",
            "$basePath\Assessment and Deployment Kit\Windows Preinstallation Environment"
        )
        
        foreach ($winPEPath in $winPEPaths) {
            if (Test-Path $winPEPath) {
                Write-LogMessage "Found WinPE at: $winPEPath" -Type Info
                return $winPEPath
            }
        }
    }
    
    Write-LogMessage "No valid ADK installation found" -Type Warning
    return $null
}

function Install-WindowsADK {
    [CmdletBinding()]
    param(
        [string]$downloadPath = "$env:TEMP\ADK",
        [string]$adkUrl = "https://go.microsoft.com/fwlink/?linkid=2196127",
        [string]$adkPEUrl = "https://go.microsoft.com/fwlink/?linkid=2196224",
        [string]$installPath = "${env:ProgramFiles(x86)}\Windows Kits\10"
    )
    
    try {
        Write-LogMessage "Starting ADK installation process..." -Type Info
        
        # Create fresh download directory
        if (Test-Path $downloadPath) {
            Remove-Item $downloadPath -Recurse -Force
        }
        New-Item -Path $downloadPath -ItemType Directory -Force | Out-Null
        
        $adkInstaller = Join-Path $downloadPath "adksetup.exe"
        
        # Download ADK installer
        Write-LogMessage "Downloading Windows ADK..." -Type Info
        Invoke-WebRequest -Uri $adkUrl -OutFile $adkInstaller -UseBasicParsing
        
        Write-LogMessage "Installing Windows ADK..." -Type Info
        # Modified feature selection to include all required components
        $adkArgs = @(
            "/quiet"
            "/norestart"
            "/log `"$downloadPath\adk_install.log`""
            "/installpath `"$installPath`""
            "/features *"
        )
        
        Write-LogMessage "ADK install command: $adkInstaller $($adkArgs -join ' ')" -Type Info
        $process = Start-Process -FilePath $adkInstaller -ArgumentList $adkArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            throw "ADK installation failed with exit code: $($process.ExitCode)"
        }
        
        Start-Sleep -Seconds 30
        
        # Install WinPE addon
        $peInstaller = Join-Path $downloadPath "adkwinpesetup.exe"
        Write-LogMessage "Downloading Windows PE addon..." -Type Info
        Invoke-WebRequest -Uri $adkPEUrl -OutFile $peInstaller -UseBasicParsing
        
        Write-LogMessage "Installing Windows PE..." -Type Info
        $peArgs = @(
            "/quiet"
            "/norestart"
            "/log `"$downloadPath\winpe_install.log`""
            "/installpath `"$installPath`""
            "/features *"
        )
        
        $process = Start-Process -FilePath $peInstaller -ArgumentList $peArgs -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -ne 0) {
            throw "WinPE installation failed with exit code: $($process.ExitCode)"
        }
        
        Start-Sleep -Seconds 30
        
        # Verify installation paths
        $requiredPaths = @(
            "$installPath\Assessment and Deployment Kit",
            "$installPath\Windows Preinstallation Environment",
            "$installPath\Assessment and Deployment Kit\Deployment Tools",
            "$installPath\Assessment and Deployment Kit\Windows Preinstallation Environment"
        )
        
        $missingPaths = @()
        foreach ($path in $requiredPaths) {
            Write-LogMessage "Checking path: $path" -Type Info
            if (-not (Test-Path $path)) {
                Write-LogMessage "Missing required path: $path" -Type Warning
                $missingPaths += $path
            }
        }
        
        if ($missingPaths.Count -gt 0) {
            Write-LogMessage "ADK installation appears incomplete. Missing paths:" -Type Warning
            $missingPaths | ForEach-Object { Write-LogMessage $_ -Type Warning }
            
            # Show installation logs for debugging
            if (Test-Path "$downloadPath\adk_install.log") {
                Write-LogMessage "ADK Install Log:" -Type Info
                Get-Content "$downloadPath\adk_install.log" | ForEach-Object { Write-LogMessage $_ -Type Info }
            }
            if (Test-Path "$downloadPath\winpe_install.log") {
                Write-LogMessage "WinPE Install Log:" -Type Info
                Get-Content "$downloadPath\winpe_install.log" | ForEach-Object { Write-LogMessage $_ -Type Info }
            }
            throw "ADK installation incomplete - missing required components"
        }
        
        Write-LogMessage "ADK installation completed successfully" -Type Info
    }
    catch {
        Write-LogMessage "Error during ADK installation: $_" -Type Error
        throw
    }
}

function Find-BootSDI {
    [CmdletBinding()]
    param(
        [string]$adkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
    )

    Write-LogMessage "Searching for boot.sdi..." -Type Info

    # Possible locations for boot.sdi
    $searchPaths = @(
        # Main WinPE locations
        "$adkRoot\Windows Preinstallation Environment\amd64\en-us",
        "$adkRoot\Windows Preinstallation Environment\amd64\Media\Boot",
        "$adkRoot\Windows Preinstallation Environment\amd64\WinPE_OCs",
        # Assessment and Deployment locations
        "$adkRoot\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\en-us",
        "$adkRoot\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\Media\Boot",
        # Alternative architecture paths
        "$adkRoot\Windows Preinstallation Environment\x86\en-us",
        "$adkRoot\Windows Preinstallation Environment\x86\Media\Boot"
    )

    foreach ($path in $searchPaths) {
        Write-LogMessage "Checking path: $path" -Type Info
        $bootSdiPath = Join-Path $path "boot.sdi"
        if (Test-Path $bootSdiPath) {
            Write-LogMessage "Found boot.sdi at: $bootSdiPath" -Type Info
            return $bootSdiPath
        }
    }

    # If not found in standard locations, search entire ADK directory
    Write-LogMessage "Searching entire ADK directory for boot.sdi..." -Type Info
    $foundFiles = Get-ChildItem -Path $adkRoot -Recurse -Filter "boot.sdi" -ErrorAction SilentlyContinue
    
    if ($foundFiles) {
        $bootSdiPath = $foundFiles[0].FullName
        Write-LogMessage "Found boot.sdi at alternate location: $bootSdiPath" -Type Info
        return $bootSdiPath
    }

    Write-LogMessage "boot.sdi not found in any location" -Type Warning
    return $null
}

function Copy-BootSDI {
    [CmdletBinding()]
    param(
        [string]$targetPath
    )

    $bootSdiPath = Find-BootSDI
    if ($bootSdiPath) {
        try {
            # Ensure target directory exists
            $targetDir = Split-Path $targetPath -Parent
            if (-not (Test-Path $targetDir)) {
                New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
            }

            # Copy the file
            Copy-Item -Path $bootSdiPath -Destination $targetPath -Force
            Write-LogMessage "Successfully copied boot.sdi to: $targetPath" -Type Info
            return $true
        }
        catch {
            Write-LogMessage "Failed to copy boot.sdi: $_" -Type Error
            return $false
        }
    }
    return $false
}

function Initialize-BootFiles {
    [CmdletBinding()]
    param(
        [string]$adkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
    )

    Write-LogMessage "Initializing boot files..." -Type Info

    # Target path for boot.sdi
    $targetPath = "$adkRoot\Windows Preinstallation Environment\amd64\en-us\boot.sdi"

    # First try to find and copy boot.sdi
    if (-not (Copy-BootSDI -targetPath $targetPath)) {
        # If copying fails, try to extract it from boot.wim
        Write-LogMessage "Attempting to extract boot.sdi from boot.wim..." -Type Info
        
        $wimPath = "$adkRoot\Windows Preinstallation Environment\amd64\en-us\winpe.wim"
        if (Test-Path $wimPath) {
            $tempDir = Join-Path $env:TEMP "WinPETemp"
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

            try {
                # Mount the WIM file
                $dismPath = "$adkRoot\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe"
                if (-not (Test-Path $dismPath)) {
                    $dismPath = "dism.exe"
                }

                & $dismPath /Mount-Wim /WimFile:"$wimPath" /index:1 /MountDir:"$tempDir"
                
                # Look for boot.sdi in the mounted image
                $mountedBootSdi = Get-ChildItem -Path $tempDir -Recurse -Filter "boot.sdi" -ErrorAction SilentlyContinue | 
                    Select-Object -First 1

                if ($mountedBootSdi) {
                    Copy-Item -Path $mountedBootSdi.FullName -Destination $targetPath -Force
                    Write-LogMessage "Successfully extracted and copied boot.sdi" -Type Info
                }

                # Cleanup
                & $dismPath /Unmount-Wim /MountDir:"$tempDir" /Discard
            }
            catch {
                Write-LogMessage "Failed to extract boot.sdi from WIM: $_" -Type Error
            }
            finally {
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Verify the file exists and is valid
    if (Test-Path $targetPath) {
        $fileInfo = Get-Item $targetPath
        if ($fileInfo.Length -gt 0) {
            Write-LogMessage "boot.sdi successfully initialized" -Type Info
            return $true
        }
    }

    Write-LogMessage "Failed to initialize boot.sdi" -Type Error
    return $false
}

# Create WinPE Workspace function
function Create-WinPEWorkspace {
    [CmdletBinding()]
    param(
        [string]$WorkspacePath = "C:\WinPE_BIOS",
        [string]$MountPath = "C:\WinPE_BIOS\mount",
        [ValidateSet("amd64", "x86", "arm64")]
        [string]$Architecture = "amd64"
    )

    # Find actual ADK installation
    $winPEPath = Find-ADKInstallation
    if (-not $winPEPath) {
        throw "Cannot find Windows PE installation"
    }

    Write-LogMessage "Using WinPE path: $winPEPath" -Type Info

    try {
        # Validate paths
        if (-not (Test-Path $winPEPath)) {
            throw "Windows PE Path not found: $winPEPath"
        }

        # Find WinPE WIM file
        $winpeWimPath = Get-ChildItem -Path (Join-Path $winPEPath $Architecture) -Recurse -Filter "winpe.wim" | 
            Select-Object -First 1 -ExpandProperty FullName

        if (-not $winpeWimPath) {
            throw "No WinPE WIM file found for architecture $Architecture"
        }

        Write-LogMessage "Found WinPE WIM: $winpeWimPath"

        # Clean existing workspace
        if (Test-Path $WorkspacePath) {
            Write-LogMessage "Removing existing workspace" -Type Warning
            Remove-Item $WorkspacePath -Recurse -Force
        }

        # Create directories
        $directories = @(
            $WorkspacePath,
            $MountPath,
            "$WorkspacePath\media\sources",
            "$WorkspacePath\media\boot",
            "$WorkspacePath\media\efi\microsoft\boot"
        )

        foreach ($dir in $directories) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created directory: $dir" -Type Info
        }

        # Copy WinPE WIM
        $destinationWim = Join-Path $WorkspacePath "media\sources\boot.wim"
        Copy-Item -Path $winpeWimPath -Destination $destinationWim -Force
        Write-LogMessage "Copied WinPE WIM to: $destinationWim" -Type Info

        # Find and copy boot.sdi
        $bootSdiPath = Get-ChildItem -Path $winPEPath -Recurse -Filter "boot.sdi" | 
            Select-Object -First 1 -ExpandProperty FullName
        
        if ($bootSdiPath) {
            Copy-Item -Path $bootSdiPath -Destination "$WorkspacePath\media\boot\boot.sdi" -Force
            Write-LogMessage "Copied boot.sdi to workspace" -Type Info
        }

        return $WorkspacePath
    }
    catch {
        Write-LogMessage "Error creating WinPE workspace: $_" -Type Error
        throw
    }
}
function New-BootableUSB {
    param(
        [string]$DriveLetter,
        [string]$WorkspacePath
    )

    # Ensure drive letter is clean and uppercase
    $DriveLetter = $DriveLetter.TrimEnd(':').ToUpper()
    Write-LogMessage "Preparing USB drive $DriveLetter..." -Type Info

    try {
        # Validate drive letter
        if ($DriveLetter -notMatch '^[D-Z]$') {
            throw "Invalid drive letter: $DriveLetter. Must be a single letter between D and Z."
        }

        # Get the physical disk
        $partition = Get-Partition | Where-Object { $_.AccessPaths -contains "${DriveLetter}:\" }
        if (-not $partition) {
            throw "Partition not found for drive ${DriveLetter}:"
        }

        $diskNumber = $partition.DiskNumber
        Write-LogMessage "Found disk number: $diskNumber for drive ${DriveLetter}:" -Type Info

        # Initial formatting with 4GB partition
        $diskpartCleanPath = Join-Path $env:TEMP "clean_usb.txt"
@"
select disk $diskNumber
clean
convert mbr
create partition primary size=4000
format fs=fat32 quick label="DELL_BIOS"
assign letter=$DriveLetter
active
"@ | Out-File -FilePath $diskpartCleanPath -Encoding ASCII

        Write-LogMessage "Creating 4GB bootable partition..." -Type Info
        $diskpartResult = diskpart.exe /s $diskpartCleanPath
        Write-LogMessage "DiskPart Result: $diskpartResult" -Type Info
        Start-Sleep -Seconds 10

        # Verify drive exists after formatting
        if (-not (Test-Path "${DriveLetter}:\")) {
            throw "Drive ${DriveLetter}: not available after formatting"
        }

        # Create directories
        $directories = @(
            "${DriveLetter}:\sources",
            "${DriveLetter}:\boot",
            "${DriveLetter}:\efi\boot",
            "${DriveLetter}:\efi\microsoft\boot",
            "${DriveLetter}:\DCC",
            "${DriveLetter}:\Config",
            "${DriveLetter}:\Logs"
        )

        foreach ($dir in $directories) {
            Write-LogMessage "Creating directory: $dir" -Type Info
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }

        # Copy WinPE files
        Write-LogMessage "Copying WinPE files..." -Type Info
        $sourcePath = Join-Path $WorkspacePath "media"
        Copy-Item -Path "$sourcePath\*" -Destination "${DriveLetter}:\" -Recurse -Force

        # Create mount point for WIM
        $mountPath = "C:\wimmount"
        if (Test-Path $mountPath) {
            Remove-Item -Path $mountPath -Force -Recurse
        }
        New-Item -Path $mountPath -ItemType Directory | Out-Null

        # Mount WIM and extract boot files
        Write-LogMessage "Mounting WIM to extract boot files..." -Type Info
        $dismPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe"
        $dismResult = Start-Process -FilePath $dismPath -ArgumentList "/mount-wim /wimfile:${DriveLetter}:\sources\boot.wim /index:1 /mountdir:$mountPath" -Wait -NoNewWindow -PassThru

        if ($dismResult.ExitCode -eq 0) {
            Write-LogMessage "Copying boot files from mounted WIM..." -Type Info
            Copy-Item -Path "$mountPath\Windows\Boot\PCAT\bootmgr" -Destination "${DriveLetter}:\" -Force
            Copy-Item -Path "$mountPath\Windows\Boot\EFI\bootmgfw.efi" -Destination "${DriveLetter}:\efi\boot\bootx64.efi" -Force
            Copy-Item -Path "$mountPath\Windows\Boot\EFI\bootmgr.efi" -Destination "${DriveLetter}:\" -Force

            Write-LogMessage "Unmounting WIM..." -Type Info
            Start-Process -FilePath $dismPath -ArgumentList "/unmount-wim /mountdir:$mountPath /commit" -Wait -NoNewWindow
        }

        # Cleanup mount point
        if (Test-Path $mountPath) {
            Remove-Item -Path $mountPath -Force -Recurse
        }

        # Write boot sector
        Write-LogMessage "Writing boot sector..." -Type Info
        $bootsectPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\BCDBoot\bootsect.exe"

        # Remove drive letter temporarily
        $diskpartRemovePath = Join-Path $env:TEMP "remove_letter.txt"
@"
select disk $diskNumber
select partition 1
remove
"@ | Out-File -FilePath $diskpartRemovePath -Encoding ASCII

        diskpart.exe /s $diskpartRemovePath
        Start-Sleep -Seconds 5

        & $bootsectPath /nt60 "${DriveLetter}:" /force

        # Reassign drive letter
        $diskpartAssignPath = Join-Path $env:TEMP "assign_letter.txt"
@"
select disk $diskNumber
select partition 1
assign letter=$DriveLetter
"@ | Out-File -FilePath $diskpartAssignPath -Encoding ASCII

        diskpart.exe /s $diskpartAssignPath
        Start-Sleep -Seconds 5

        # Create and configure BCD store
        Write-LogMessage "Creating BCD store..." -Type Info
        $bcdPath = "${DriveLetter}:\boot\bcd"

        Write-LogMessage "Initializing BCD store..." -Type Info
        bcdedit /createstore $bcdPath | Out-Null
        bcdedit /store $bcdPath /create "{bootmgr}" /d "Boot Manager" | Out-Null
        $bcdOutput = bcdedit /store $bcdPath /create /d "WinPE" /application osloader
        if ($bcdOutput -match "{[A-F0-9-]+}") {
            $guid = $matches[0]
            
            Write-LogMessage "Configuring BCD with GUID: $guid" -Type Info
            $bcdCommands = @(
                "bcdedit /store `"$bcdPath`" /set `"{bootmgr}`" default $guid",
                "bcdedit /store `"$bcdPath`" /set `"{bootmgr}`" timeout 30",
                "bcdedit /store `"$bcdPath`" /set `"$guid`" device ramdisk=[boot]\sources\boot.wim,{ramdiskoptions}",
                "bcdedit /store `"$bcdPath`" /set `"$guid`" path \windows\system32\winload.exe",
                "bcdedit /store `"$bcdPath`" /set `"$guid`" osdevice ramdisk=[boot]\sources\boot.wim,{ramdiskoptions}",
                "bcdedit /store `"$bcdPath`" /set `"$guid`" systemroot \windows",
                "bcdedit /store `"$bcdPath`" /set `"$guid`" detecthal yes",
                "bcdedit /store `"$bcdPath`" /set `"$guid`" winpe yes"
            )

            foreach ($cmd in $bcdCommands) {
                Invoke-Expression $cmd
            }
        }

        Write-LogMessage "USB drive preparation completed" -Type Info
    }
    catch {
        Write-LogMessage "Failed to prepare USB drive: $_" -Type Error
        throw
    }
    finally {
        # Cleanup
        @($diskpartCleanPath, $diskpartRemovePath, $diskpartAssignPath) | 
            Where-Object { $_ -and (Test-Path $_) } | 
            ForEach-Object { Remove-Item $_ -Force -ErrorAction SilentlyContinue }

        if (Test-Path $mountPath) {
            Start-Process -FilePath $dismPath -ArgumentList "/unmount-wim /mountdir:$mountPath /discard" -Wait -NoNewWindow
            Remove-Item -Path $mountPath -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}

# Main execution block
try {
    Write-LogMessage "Starting Dell BIOS Configuration USB creation process" -Type Info
    
    # Verify ADK installation
    Test-ADKInstallation
    
    # Create WinPE Workspace with explicit path capture and validation
    $arch = Get-SystemArchitecture
    Write-LogMessage "Detected system architecture: $arch" -Type Info
    
    $createdWorkspacePath = Create-WinPEWorkspace -Architecture $arch
    Write-LogMessage "WinPE workspace creation returned path: $createdWorkspacePath" -Type Info
    
    if ([string]::IsNullOrWhiteSpace($createdWorkspacePath)) {
        throw "WinPE workspace path is empty or null"
    }
    
    if (-not (Test-Path $createdWorkspacePath)) {
        throw "WinPE workspace was not created successfully at: $createdWorkspacePath"
    }
    
    # Verify media directory structure
    $mediaPath = Join-Path $createdWorkspacePath "media"
    if (-not (Test-Path $mediaPath)) {
        throw "Required media directory not found at: $mediaPath"
    }
    
    Write-LogMessage "Verified workspace exists at: $createdWorkspacePath" -Type Info
    
    # Improved USB drive detection
    $usbDrives = Get-WmiObject Win32_LogicalDisk | 
        Where-Object { 
            $_.DriveType -eq 2 -and  # Removable media
            $_.Size -gt 0 -and 
            $_.Size -lt 128GB  # Typical USB drive size limit
        } | 
        Select-Object DeviceID, Size, @{
            Name='SizeInGB'
            Expression={[math]::Round($_.Size / 1GB, 2)}
        }

    if ($usbDrives.Count -eq 0) {
        throw "No removable USB drives found. Please insert a USB drive."
    }

    Write-Host "`nAvailable USB drives:" -ForegroundColor Green
    $usbDrives | Format-Table -AutoSize

    do {
        $selectedDrive = Read-Host "Enter USB drive letter (default: D)"
        
        if ([string]::IsNullOrWhiteSpace($selectedDrive)) {
            $selectedDrive = "D"
        }
        
        $selectedDriveObj = $usbDrives | Where-Object { $_.DeviceID -eq "${selectedDrive}:" }
        
        if (-not $selectedDriveObj) {
            Write-Host "Invalid drive selection. Please choose from the available drives." -ForegroundColor Red
        }
    } while (-not $selectedDriveObj)

    $confirmation = Read-Host "Are you sure you want to format drive $selectedDrive`: with $($selectedDriveObj.SizeInGB)GB? (Y/N)"
    if ($confirmation -ne 'Y') {
        Write-Host "USB drive creation cancelled." -ForegroundColor Yellow
        exit
    }

    # Create bootable USB
    Write-LogMessage "Creating bootable USB on drive $selectedDrive..." -Type Info
    New-BootableUSB -DriveLetter $selectedDrive -WorkspacePath $createdWorkspacePath

    Write-LogMessage "USB creation process completed successfully" -Type Info
    Write-Host "`nNext steps:" -ForegroundColor Green
    Write-Host "1. Copy Dell Command Configure installer to ${selectedDrive}:\DCC\" -ForegroundColor Yellow
    Write-Host "2. Customize ${selectedDrive}:\Config\BIOSSettings.json" -ForegroundColor Yellow
    Write-Host "3. Use USB drive to boot target systems" -ForegroundColor Yellow
}
catch {
    Write-LogMessage "Failed to create bootable USB: $_" -Type Error
    
    # Improved cleanup attempt
    if ($mountPath -and (Test-Path $mountPath)) {
        Write-LogMessage "Attempting to clean up mount point..." -Type Info
        
        try {
            $adkPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit"
            $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
            $dismPath = Join-Path -Path $adkPath -ChildPath "Deployment Tools\$arch\DISM\dism.exe"
            
            # Check if ADK DISM exists, if not use system DISM
            if (-not (Test-Path $dismPath)) {
                Write-LogMessage "ADK DISM not found, using system DISM" -Type Warning
                $dismExe = Get-Command dism.exe -ErrorAction SilentlyContinue
                if ($dismExe) {
                    $dismPath = $dismExe.Path
                } else {
                    throw "Cannot find DISM executable"
                }
            }
            
            # Use Start-Process to properly handle the DISM command
            $dismArgs = @(
                "/Unmount-Image"
                "/MountDir:`"$mountPath`""
                "/Discard"
            )
            
            $process = Start-Process -FilePath $dismPath -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -ne 0) {
                Write-LogMessage "DISM cleanup failed with exit code: $($process.ExitCode)" -Type Warning
            }
        }
        catch {
            Write-LogMessage "Error during cleanup: $_" -Type Warning
        }
        finally {
            # Force remove mount directory if it still exists
            if (Test-Path $mountPath) {
                Remove-Item -Path $mountPath -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
    }
    
    exit 1
}
finally {
    Stop-Transcript
}