## Introduction

I'm an IT Infrastructure/Systems Administrator with a focus on automating and streamlining enterprise systems management. This repository contains a collection of PowerShell scripts I've developed to handle various administration tasks across Active Directory, networking, BIOS management, M365, and other infrastructure components.

As I continue to expand my PowerShell capabilities, I'm increasingly exploring more advanced technical areas like Infrastructure as Code (IaC), configuration management, and automated reporting solutions. These scripts represent my ongoing journey to improve operational efficiency while developing deeper technical expertise.

## Script Collection

### Active Directory Management
- **ADSecurityGroupReports.ps1** - Generates detailed reports of HR security group memberships with HTML email reporting
- **Remove AD Security Group with Mail Report.ps1** - Removes computers from Domain Computers group with email notification
- **SearchADJoinedServersforUpdatesReport.ps1** - Comprehensive reporting tool for Windows Server patch status across the enterprise

### Email & M365 Management
- **ConvertUsertoSharedMailbox Grabs Email Config into Email Body Report.ps1** - Converts a user mailbox to shared in M365 and includes mail configuration details in the report

### Network Configuration
- **Disable IPV6 on all found interfaces and email report.ps1** - Disables IPv6 on all network interfaces with email reporting
- **DNSConfigQuad9.ps1** - Configures secure DNS using Quad9 with DoH (DNS over HTTPS)

### System Configuration
- **Configure BIOS onto Bootable Pendrive Generates a Password to use within Json.ps1** - Creates bootable WinPE USB for Dell BIOS configuration deployment
- **JSON Config for BIOS Pendrive.ps1** - Manages Dell BIOS settings with secure password handling
- **QuickUSBInitialiser.ps1** - Simple tool for quickly formatting and recovering USB drives

## Usage

Most scripts include detailed comments and logging functionality. Many utilize a standard email reporting system that can be customized to your organization's requirements. Scripts are designed to be run with administrative privileges where required.

## Future Development

I'm continuing to expand these tools with a focus on:
- Infrastructure as Code (IaC) implementations
- Advanced error handling and validation
- Cross-platform compatibility
- Improved security practices
- Automated deployment workflows

## Requirements

- Windows PowerShell 5.1 or PowerShell Core 7.x
- Appropriate admin rights for the systems being managed
- Corresponding modules (ActiveDirectory, ExchangeOnlineManagement, etc.)
