#Requires -RunAsAdministrator

# Start transcript logging
$logFile = "USB_Recovery_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logPath = Join-Path $env:USERPROFILE\Desktop $logFile
Start-Transcript -Path $logPath

function Repair-USBDrive {
    [CmdletBinding()]
    param(
        [switch]$Retry
    )
    
    Write-Host "Looking for USB drives..." -ForegroundColor Yellow
    $usbDisks = Get-Disk | Where-Object BusType -eq "USB"
    
    if (-not $usbDisks) {
        Write-Host "No USB drives found! Please ensure drive is connected." -ForegroundColor Red
        $retryChoice = Read-Host "Would you like to search again? (Y/N)"
        if ($retryChoice -eq 'Y') {
            Start-Sleep -Seconds 2  # Give time for drive to be connected
            Repair-USBDrive -Retry
            return
        }
        return
    }
    
    Write-Host "`nFound USB drives:" -ForegroundColor Green
    $usbDisks | Format-Table -Property Number, FriendlyName, Size, PartitionStyle
    
    $diskNumber = Read-Host "`nEnter disk number to recover (or 'R' to refresh list)"
    if ($diskNumber -eq 'R') {
        Clear-Host
        Repair-USBDrive -Retry
        return
    }
    
    $selectedDisk = Get-Disk -Number $diskNumber -ErrorAction SilentlyContinue
    if (-not $selectedDisk -or $selectedDisk.BusType -ne "USB") {
        Write-Host "Invalid disk selection or not a USB drive!" -ForegroundColor Red
        $retryChoice = Read-Host "Would you like to try again? (Y/N)"
        if ($retryChoice -eq 'Y') {
            Clear-Host
            Repair-USBDrive -Retry
            return
        }
        return
    }
    
    Write-Host "`nWARNING: This will erase all data on the selected USB drive!" -ForegroundColor Red
    Write-Host "Selected drive details:" -ForegroundColor Yellow
    $selectedDisk | Format-List FriendlyName, Size, PartitionStyle, OperationalStatus
    
    $confirm = Read-Host "Continue? (Y/N/R for refresh)"
    switch ($confirm) {
        'R' {
            Clear-Host
            Repair-USBDrive -Retry
            return
        }
        'Y' {
            # Continue with recovery
        }
        default {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            $retryChoice = Read-Host "Would you like to start over? (Y/N)"
            if ($retryChoice -eq 'Y') {
                Clear-Host
                Repair-USBDrive -Retry
            }
            return
        }
    }
    
    try {
        Write-Host "`nInitializing disk..." -ForegroundColor Yellow
        $selectedDisk | Initialize-Disk -PartitionStyle MBR -PassThru
        
        Write-Host "Creating partition..." -ForegroundColor Yellow
        $partition = $selectedDisk | New-Partition -UseMaximumSize -AssignDriveLetter
        
        Write-Host "Formatting volume..." -ForegroundColor Yellow
        $formatResult = $partition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "USB_DRIVE" -Confirm:$false
        
        if ($formatResult) {
            Write-Host "`nUSB drive recovery complete!" -ForegroundColor Green
            Write-Host "Drive is now accessible as $($partition.DriveLetter):" -ForegroundColor Green
            
            $continueChoice = Read-Host "Would you like to recover another drive? (Y/N)"
            if ($continueChoice -eq 'Y') {
                Clear-Host
                Repair-USBDrive -Retry
            }
        } else {
            throw "Format operation failed"
        }
    }
    catch {
        Write-Host "Error recovering USB drive: $_" -ForegroundColor Red
        $retryChoice = Read-Host "Would you like to try again? (Y/N)"
        if ($retryChoice -eq 'Y') {
            Clear-Host
            Repair-USBDrive -Retry
        }
    }
}

# Main execution block
try {
    Write-Host "USB Drive Recovery Tool" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host "This script will help you recover inaccessible USB drives." -ForegroundColor Yellow
    Write-Host "Please ensure you have administrator privileges." -ForegroundColor Yellow
    Write-Host ""
    
    # Automatically start the recovery process
    Repair-USBDrive
}
catch {
    Write-Host "An unexpected error occurred: $_" -ForegroundColor Red
}
finally {
    Stop-Transcript
}