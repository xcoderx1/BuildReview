<#
.SYNOPSIS
    CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 - Automated Build Review Tool
.DESCRIPTION
    Comprehensive automated build review aligned to CIS Benchmark v5.0.0 covering:
    - BIOS/Firmware Configuration
    - Full Disk Encryption (BitLocker)
    - OS and Third-Party Patching
    - Local Service Hardening
    - File System Permissions Review
    - Security Product Inspection (AV, Firewall, HIPS)
    - Removable Media Controls
    - User Account and Password Configuration
    - Privilege Escalation Vectors
    - Lateral Movement Risks
    - Network Configuration
    - Logging and Auditing
    - System Hardening (CIS L1 + L2)
    - Low-Privilege User Assessment (attack path enumeration)

    Generates an HTML report with pass/fail/warning status for each check.
.NOTES
    Must be run as Administrator for full results.
    Reference: CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0
.EXAMPLE
    .\CIS_Win11_BuildReview.ps1
    .\CIS_Win11_BuildReview.ps1 -OutputPath "C:\Reports"
    .\CIS_Win11_BuildReview.ps1 -SkipCategories @("LateralMovement")
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [string[]]$SkipCategories = @(),
    [switch]$Verbose
)

#Requires -RunAsAdministrator

# ============================================================================
# GLOBAL VARIABLES & REPORT FRAMEWORK
# ============================================================================
$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$Script:OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$CISRef,
        [Parameter(Mandatory)][string]$CheckTitle,
        [Parameter(Mandatory)][ValidateSet("Pass","Fail","Warning","Info","Error","Manual")][string]$Status,
        [string]$Expected = "",
        [string]$Actual = "",
        [string]$Description = "",
        [ValidateSet("L1","L2","Custom")][string]$Profile = "L1",
        [ValidateSet("Critical","High","Medium","Low","Informational")][string]$Severity = "Medium"
    )
    $null = $Script:Results.Add([PSCustomObject]@{
        Category    = $Category
        CISRef      = $CISRef
        CheckTitle  = $CheckTitle
        Status      = $Status
        Expected    = $Expected
        Actual      = $Actual
        Description = $Description
        Profile     = $Profile
        Severity    = $Severity
    })
}

function Get-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        $Default = $null
    )
    try {
        $val = Get-ItemProperty -Path "Registry::$Path" -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $Default
    }
}

function Test-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue,
        [string]$Comparator = "eq"
    )
    $actual = Get-RegValue -Path $Path -Name $Name -Default "__NOT_CONFIGURED__"
    if ($actual -eq "__NOT_CONFIGURED__") { return @{ Match = $false; Actual = "Not Configured" } }
    $match = switch ($Comparator) {
        "eq"  { $actual -eq $ExpectedValue }
        "le"  { $actual -le $ExpectedValue }
        "ge"  { $actual -ge $ExpectedValue }
        "ne"  { $actual -ne $ExpectedValue }
        "gt"  { $actual -gt $ExpectedValue }
        "lt"  { $actual -lt $ExpectedValue }
        default { $actual -eq $ExpectedValue }
    }
    return @{ Match = $match; Actual = $actual }
}

function Get-ServiceStartType {
    param([string]$ServiceName)
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        return $svc.StartType.ToString()
    } catch {
        return "Not Installed"
    }
}

function Write-Progress2 {
    param([string]$Activity, [string]$Status)
    Write-Host "  [*] $Activity - $Status" -ForegroundColor Cyan
}

# ============================================================================
# CATEGORY 1: BIOS / FIRMWARE CONFIGURATION
# ============================================================================
function Test-BIOSConfiguration {
    Write-Host "`n[+] BIOS / Firmware Configuration Checks" -ForegroundColor Green

    # Secure Boot Status
    Write-Progress2 "BIOS" "Checking Secure Boot"
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Finding -Category "BIOS Configuration" -CISRef "18.9.5.2" -CheckTitle "Secure Boot Enabled" `
            -Status $(if($secureBoot){"Pass"}else{"Fail"}) `
            -Expected "Enabled" -Actual $(if($secureBoot){"Enabled"}else{"Disabled"}) `
            -Description "CIS 18.9.5.2: VBS Platform Security Level requires Secure Boot or higher." `
            -Severity "Critical"
    } catch {
        Add-Finding -Category "BIOS Configuration" -CISRef "18.9.5.2" -CheckTitle "Secure Boot Enabled" `
            -Status "Warning" -Expected "Enabled" -Actual "Unable to determine (Legacy BIOS?)" `
            -Description "Could not query Secure Boot. System may be using Legacy BIOS." -Severity "Critical"
    }

    # UEFI Mode Check
    Write-Progress2 "BIOS" "Checking UEFI firmware mode"
    try {
        $firmware = (Get-CimInstance -ClassName Win32_DiskPartition | Where-Object { $_.Type -like "*GPT*" })
        $isUEFI = ($null -ne $firmware)
        Add-Finding -Category "BIOS Configuration" -CISRef "Custom" -CheckTitle "UEFI Firmware Mode" `
            -Status $(if($isUEFI){"Pass"}else{"Fail"}) `
            -Expected "UEFI (GPT)" -Actual $(if($isUEFI){"UEFI (GPT Partitions Found)"}else{"Legacy BIOS (MBR)"}) `
            -Description "UEFI required for Secure Boot, VBS, Credential Guard." -Severity "High"
    } catch {
        Add-Finding -Category "BIOS Configuration" -CISRef "Custom" -CheckTitle "UEFI Firmware Mode" `
            -Status "Error" -Actual "Check failed: $_" -Severity "High"
    }

    # TPM Check
    Write-Progress2 "BIOS" "Checking TPM status"
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $tpmPresent = $tpm.TpmPresent
        $tpmReady = $tpm.TpmReady
        $tpmVersion = (Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
        if ($tpmVersion) { $tpmVersion = $tpmVersion.Split(",")[0].Trim() }

        Add-Finding -Category "BIOS Configuration" -CISRef "Custom" -CheckTitle "TPM Present and Ready" `
            -Status $(if($tpmPresent -and $tpmReady){"Pass"}else{"Fail"}) `
            -Expected "Present=True, Ready=True" -Actual "Present=$tpmPresent, Ready=$tpmReady, Version=$tpmVersion" `
            -Description "TPM 2.0 required for BitLocker, Credential Guard, Device Health Attestation." `
            -Severity "Critical"
    } catch {
        Add-Finding -Category "BIOS Configuration" -CISRef "Custom" -CheckTitle "TPM Present and Ready" `
            -Status "Fail" -Expected "TPM 2.0 Present" -Actual "TPM not detected or inaccessible" -Severity "Critical"
    }

    # Virtualization Based Security (VBS/HVCI)
    Write-Progress2 "BIOS" "Checking Virtualization Based Security"
    $vbs = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.5.1" -CheckTitle "Virtualization Based Security Enabled" `
        -Status $(if($vbs -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $vbs){"Not Configured"}else{$vbs}) `
        -Description "CIS 18.9.5.1: VBS uses hardware virtualization to protect code integrity." -Severity "High"

    # HVCI (Hypervisor Code Integrity)
    $hvci = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.5.3" -CheckTitle "HVCI - Code Integrity with UEFI Lock" `
        -Status $(if($hvci -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled with UEFI lock)" -Actual $(if($null -eq $hvci){"Not Configured"}else{$hvci}) `
        -Description "CIS 18.9.5.3: Virtualization Based Protection of Code Integrity." -Severity "High"

    # Credential Guard
    $credGuard = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.5.5" -CheckTitle "Credential Guard with UEFI Lock" `
        -Status $(if($credGuard -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled with UEFI lock)" -Actual $(if($null -eq $credGuard){"Not Configured"}else{$credGuard}) `
        -Description "CIS 18.9.5.5: Credential Guard protects domain credentials via VBS." -Severity "High"

    # Secure Launch (DRTM)
    $secureLaunch = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.5.6" -CheckTitle "Secure Launch Configuration" `
        -Status $(if($secureLaunch -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $secureLaunch){"Not Configured"}else{$secureLaunch}) `
        -Description "CIS 18.9.5.6: Dynamic Root of Trust for Measurement." -Severity "Medium"

    # Kernel DMA Protection
    Write-Progress2 "BIOS" "Checking Kernel DMA Protection"
    $dmaProtection = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.24.1" -CheckTitle "Kernel DMA Protection - Block All" `
        -Status $(if($dmaProtection -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Block All)" -Actual $(if($null -eq $dmaProtection){"Not Configured"}else{$dmaProtection}) `
        -Description "CIS 18.9.24.1: Block external DMA-capable devices." -Severity "High"

    # LSASS Protected Process
    $lsaPPL = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "RunAsPPL"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.27.2" -CheckTitle "LSASS runs as Protected Process (UEFI Lock)" `
        -Status $(if($lsaPPL -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled with UEFI Lock)" -Actual $(if($null -eq $lsaPPL){"Not Configured"}else{$lsaPPL}) `
        -Description "CIS 18.9.27.2: Prevents credential dumping from LSASS." -Severity "Critical"

    # Early Launch Antimalware
    $elam = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"
    Add-Finding -Category "BIOS Configuration" -CISRef "18.9.13.1" -CheckTitle "Boot-Start Driver Initialization Policy" `
        -Status $(if($elam -eq 3){"Pass"}elseif($elam -eq 1){"Pass"}elseif($elam -eq 7){"Pass"}else{"Fail"}) `
        -Expected "3 (Good, unknown, bad but critical)" -Actual $(if($null -eq $elam){"Not Configured"}else{$elam}) `
        -Description "CIS 18.9.13.1: Controls which boot-start drivers are initialized." -Severity "Medium"
}

# ============================================================================
# CATEGORY 2: FULL DISK ENCRYPTION (BitLocker)
# ============================================================================
function Test-FullDiskEncryption {
    Write-Host "`n[+] Full Disk Encryption (BitLocker) Checks" -ForegroundColor Green

    # BitLocker Status on all drives
    Write-Progress2 "BitLocker" "Checking encryption status on all volumes"
    try {
        $blVolumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($vol in $blVolumes) {
            $drive = $vol.MountPoint
            $status = $vol.ProtectionStatus
            $encPerc = $vol.EncryptionPercentage
            $encMethod = $vol.EncryptionMethod
            $volType = $vol.VolumeType

            $isProtected = ($status -eq "On") -and ($encPerc -eq 100)
            Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10" -CheckTitle "BitLocker: $drive ($volType)" `
                -Status $(if($isProtected){"Pass"}else{"Fail"}) `
                -Expected "Protection=On, Encrypted=100%" `
                -Actual "Protection=$status, Encrypted=${encPerc}%, Method=$encMethod" `
                -Description "All drives should be fully encrypted with BitLocker." -Severity "Critical"
        }
    } catch {
        Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10" -CheckTitle "BitLocker Volume Query" `
            -Status "Error" -Actual "Failed to query BitLocker: $_" -Severity "Critical"
    }

    # OS Drive - Allow enhanced PINs
    $enhancedPIN = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "UseEnhancedPin"
    Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10.2.1" -CheckTitle "Allow enhanced PINs for startup" `
        -Status $(if($enhancedPIN -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $enhancedPIN){"Not Configured"}else{$enhancedPIN}) `
        -Description "CIS 18.10.10.2.1: Enhanced PINs allow use of full keyboard characters." -Severity "Medium"

    # OS Drive - Allow Secure Boot validation
    $secureBootBL = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "OSAllowSecureBootForIntegrity"
    Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10.2.2" -CheckTitle "Allow Secure Boot for integrity validation" `
        -Status $(if($secureBootBL -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $secureBootBL){"Not Configured"}else{$secureBootBL}) `
        -Description "CIS 18.10.10.2.2: Use Secure Boot for BitLocker platform validation." -Severity "Medium"

    # Disable hardware encryption for OS drives
    $hwEncOS = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "OSHardwareEncryption"
    Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10.2.11" -CheckTitle "Disable hardware-based encryption for OS drives" `
        -Status $(if($hwEncOS -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $hwEncOS){"Not Configured"}else{$hwEncOS}) `
        -Description "CIS 18.10.10.2.11: Software encryption preferred due to hardware encryption vulnerabilities." `
        -Severity "High"

    # Disable hardware encryption for fixed drives
    $hwEncFixed = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "FDVHardwareEncryption"
    Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10.1.10" -CheckTitle "Disable hardware-based encryption for fixed drives" `
        -Status $(if($hwEncFixed -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $hwEncFixed){"Not Configured"}else{$hwEncFixed}) `
        -Description "CIS 18.10.10.1.10: Software encryption preferred." -Severity "High"

    # Removable drives - Deny write access if not BitLocker protected
    $denyWriteRemovable = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "RDVDenyWriteAccess"
    Add-Finding -Category "Full Disk Encryption" -CISRef "18.10.10.3.14" `
        -CheckTitle "Deny write to removable drives not BitLocker protected" `
        -Status $(if($denyWriteRemovable -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $denyWriteRemovable){"Not Configured"}else{$denyWriteRemovable}) `
        -Description "CIS 18.10.10.3.14: Prevent data exfiltration to unencrypted removable media." `
        -Severity "High"
}

# ============================================================================
# CATEGORY 3: OS AND THIRD-PARTY PATCHING
# ============================================================================
function Test-Patching {
    Write-Host "`n[+] Operating System & Third-Party Patching Checks" -ForegroundColor Green

    # Windows Update Configuration
    Write-Progress2 "Patching" "Checking Windows Update settings"
    $autoUpdate = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
    Add-Finding -Category "OS Patching" -CISRef "18.10.94.2.1" -CheckTitle "Automatic Updates Enabled" `
        -Status $(if($autoUpdate -eq 0 -or $null -eq $autoUpdate){"Pass"}else{"Fail"}) `
        -Expected "0 or Not Configured (Enabled)" -Actual $(if($null -eq $autoUpdate){"Not Configured (Default)"}else{$autoUpdate}) `
        -Description "CIS 18.10.94.2.1: Automatic Updates should be enabled." -Severity "High"

    # Scheduled install day
    $schedDay = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay"
    Add-Finding -Category "OS Patching" -CISRef "18.10.94.2.2" -CheckTitle "Scheduled install day = Every day" `
        -Status $(if($schedDay -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 (Every day)" -Actual $(if($null -eq $schedDay){"Not Configured"}else{$schedDay}) `
        -Description "CIS 18.10.94.2.2: Updates should install every day." -Severity "Medium"

    # Preview builds disabled
    $previewBuilds = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue"
    Add-Finding -Category "OS Patching" -CISRef "18.10.94.4.1" -CheckTitle "Preview Builds Disabled" `
        -Status $(if($previewBuilds -eq 1){"Pass"}else{"Warning"}) `
        -Expected "1 (Disabled)" -Actual $(if($null -eq $previewBuilds){"Not Configured"}else{$previewBuilds}) `
        -Description "CIS 18.10.94.4.1: Preview builds should not run on enterprise devices." -Severity "Medium"

    # Quality Updates - 0 days delay
    $qualityDelay = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays"
    Add-Finding -Category "OS Patching" -CISRef "18.10.94.4.2" -CheckTitle "Quality Updates received within 0 days" `
        -Status $(if($qualityDelay -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 days" -Actual $(if($null -eq $qualityDelay){"Not Configured"}else{"$qualityDelay days"}) `
        -Description "CIS 18.10.94.4.2: Quality updates should be received promptly." -Severity "Medium"

    # Disable new features via servicing
    $featuresOff = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "AllowTemporaryEnterpriseFeatureControl"
    Add-Finding -Category "OS Patching" -CISRef "18.10.94.2.3" -CheckTitle "Features via servicing disabled" `
        -Status $(if($featuresOff -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $featuresOff){"Not Configured"}else{$featuresOff}) `
        -Description "CIS 18.10.94.2.3: Prevent enabling features introduced via servicing by default." -Severity "Low"

    # Remove Pause Updates
    $pauseRemoved = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetDisablePauseUXAccess"
    Add-Finding -Category "OS Patching" -CISRef "18.10.94.2.4" -CheckTitle "Pause Updates feature removed" `
        -Status $(if($pauseRemoved -eq 1){"Pass"}else{"Warning"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $pauseRemoved){"Not Configured"}else{$pauseRemoved}) `
        -Description "CIS 18.10.94.2.4: Users should not be able to pause updates." -Severity "Medium"

    # Installed hotfixes - age check
    Write-Progress2 "Patching" "Checking installed hotfix recency"
    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
        $latestPatch = $hotfixes | Select-Object -First 1
        if ($latestPatch -and $latestPatch.InstalledOn) {
            $daysSincePatch = (New-TimeSpan -Start $latestPatch.InstalledOn -End (Get-Date)).Days
            $patchStatus = if ($daysSincePatch -le 30) { "Pass" } elseif ($daysSincePatch -le 60) { "Warning" } else { "Fail" }
            Add-Finding -Category "OS Patching" -CISRef "Custom" -CheckTitle "Latest patch age" `
                -Status $patchStatus `
                -Expected "Within 30 days" -Actual "$daysSincePatch days ago ($($latestPatch.HotFixID) on $($latestPatch.InstalledOn.ToString('yyyy-MM-dd')))" `
                -Description "System should be patched within organisational patching policy window." `
                -Severity $(if($daysSincePatch -gt 60){"Critical"}elseif($daysSincePatch -gt 30){"High"}else{"Low"})
        }

        # Count of patches
        Add-Finding -Category "OS Patching" -CISRef "Custom" -CheckTitle "Total installed hotfixes" `
            -Status "Info" -Actual "$($hotfixes.Count) hotfixes installed" `
            -Description "Informational: total number of OS patches applied." -Severity "Informational"
    } catch {
        Add-Finding -Category "OS Patching" -CISRef "Custom" -CheckTitle "Hotfix Query" `
            -Status "Error" -Actual "Failed to query hotfixes" -Severity "High"
    }

    # Third-party software check (common vulnerable apps)
    Write-Progress2 "Patching" "Checking third-party software versions"
    $thirdPartyApps = @()
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $installedApps = foreach ($rp in $regPaths) {
            Get-ItemProperty $rp -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
        }
        $appCount = ($installedApps | Select-Object -Unique DisplayName).Count
        Add-Finding -Category "OS Patching" -CISRef "Custom" -CheckTitle "Installed third-party applications" `
            -Status "Info" -Actual "$appCount applications detected" `
            -Description "Manual review: verify all third-party software is current and supported." -Severity "Informational"
    } catch {
        Add-Finding -Category "OS Patching" -CISRef "Custom" -CheckTitle "Third-party software audit" `
            -Status "Error" -Actual "Failed to enumerate" -Severity "Medium"
    }
}

# ============================================================================
# CATEGORY 4: LOCAL SERVICE CHECKS
# ============================================================================
function Test-LocalServices {
    Write-Host "`n[+] Local Service Hardening Checks" -ForegroundColor Green

    # CIS Section 5 - Services that should be Disabled
    $cisServices = @(
        @{ Name="BTAGService";       CIS="5.1";  Desc="Bluetooth Audio Gateway Service" },
        @{ Name="bthserv";           CIS="5.2";  Desc="Bluetooth Support Service" },
        @{ Name="Browser";           CIS="5.3";  Desc="Computer Browser" },
        @{ Name="MapsBroker";        CIS="5.4";  Desc="Downloaded Maps Manager" },
        @{ Name="GameInputSvc";      CIS="5.5";  Desc="GameInput Service" },
        @{ Name="lfsvc";             CIS="5.6";  Desc="Geolocation Service" },
        @{ Name="IISADMIN";          CIS="5.7";  Desc="IIS Admin Service" },
        @{ Name="irmon";             CIS="5.8";  Desc="Infrared Monitor" },
        @{ Name="lltdsvc";           CIS="5.9";  Desc="Link-Layer Topology Discovery Mapper" },
        @{ Name="FTPSVC";            CIS="5.10"; Desc="Microsoft FTP Service" },
        @{ Name="MSiSCSI";           CIS="5.11"; Desc="Microsoft iSCSI Initiator" },
        @{ Name="sshd";              CIS="5.12"; Desc="OpenSSH SSH Server" },
        @{ Name="PNRPsvc";           CIS="5.13"; Desc="Peer Name Resolution Protocol" },
        @{ Name="p2psvc";            CIS="5.14"; Desc="Peer Networking Grouping" },
        @{ Name="p2pimsvc";          CIS="5.15"; Desc="Peer Networking Identity Manager" },
        @{ Name="PNRPAutoReg";       CIS="5.16"; Desc="PNRP Machine Name Publication" },
        @{ Name="Spooler";           CIS="5.17"; Desc="Print Spooler" },
        @{ Name="wercplsupport";     CIS="5.18"; Desc="Problem Reports and Solutions" },
        @{ Name="RasAuto";           CIS="5.19"; Desc="Remote Access Auto Connection Manager" },
        @{ Name="SessionEnv";        CIS="5.20"; Desc="Remote Desktop Configuration" },
        @{ Name="TermService";       CIS="5.21"; Desc="Remote Desktop Services" },
        @{ Name="UmRdpService";      CIS="5.22"; Desc="RD UserMode Port Redirector" },
        @{ Name="RpcLocator";        CIS="5.23"; Desc="RPC Locator" },
        @{ Name="RemoteRegistry";    CIS="5.24"; Desc="Remote Registry" },
        @{ Name="RemoteAccess";      CIS="5.25"; Desc="Routing and Remote Access" },
        @{ Name="LanmanServer";      CIS="5.26"; Desc="Server (SMB)" },
        @{ Name="simptcp";           CIS="5.27"; Desc="Simple TCP/IP Services" },
        @{ Name="SNMP";              CIS="5.28"; Desc="SNMP Service" },
        @{ Name="sacsvr";            CIS="5.29"; Desc="Special Administration Console Helper" },
        @{ Name="SSDPSRV";           CIS="5.30"; Desc="SSDP Discovery" },
        @{ Name="upnphost";          CIS="5.31"; Desc="UPnP Device Host" },
        @{ Name="WMSvc";             CIS="5.32"; Desc="Web Management Service" },
        @{ Name="WerSvc";            CIS="5.33"; Desc="Windows Error Reporting" },
        @{ Name="Wecsvc";            CIS="5.34"; Desc="Windows Event Collector" },
        @{ Name="WMPNetworkSvc";     CIS="5.35"; Desc="WMP Network Sharing" },
        @{ Name="icssvc";            CIS="5.36"; Desc="Windows Mobile Hotspot" },
        @{ Name="WpnService";        CIS="5.37"; Desc="Windows Push Notifications System" },
        @{ Name="PushToInstall";     CIS="5.38"; Desc="Windows PushToInstall" },
        @{ Name="WinRM";             CIS="5.39"; Desc="Windows Remote Management" },
        @{ Name="W3SVC";             CIS="5.40"; Desc="World Wide Web Publishing" },
        @{ Name="XboxGipSvc";        CIS="5.41"; Desc="Xbox Accessory Management" },
        @{ Name="XblAuthManager";    CIS="5.42"; Desc="Xbox Live Auth Manager" },
        @{ Name="XblGameSave";       CIS="5.43"; Desc="Xbox Live Game Save" },
        @{ Name="XboxNetApiSvc";     CIS="5.44"; Desc="Xbox Live Networking" }
    )

    foreach ($svc in $cisServices) {
        $startType = Get-ServiceStartType $svc.Name
        $compliant = ($startType -eq "Disabled" -or $startType -eq "Not Installed")
        Add-Finding -Category "Local Services" -CISRef $svc.CIS `
            -CheckTitle "$($svc.Desc) ($($svc.Name)) = Disabled" `
            -Status $(if($compliant){"Pass"}else{"Fail"}) `
            -Expected "Disabled or Not Installed" -Actual $startType `
            -Description "CIS $($svc.CIS): $($svc.Desc) should be Disabled." `
            -Severity $(if($svc.Name -in @("TermService","RemoteRegistry","LanmanServer","sshd","WinRM")){"High"}else{"Medium"}) `
            -Profile "L2"
    }

    # Service binary permissions check (privilege escalation vector)
    Write-Progress2 "Services" "Checking service binary permissions (priv esc vectors)"
    try {
        $vulnerableSvcs = @()
        $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.State -eq "Running" }
        foreach ($s in $services | Select-Object -First 50) {
            $path = $s.PathName -replace '"', ''
            if ($path -match '^([a-zA-Z]:\\.+?\.(exe|dll))') {
                $exePath = $Matches[1]
                if (Test-Path $exePath) {
                    $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                    if ($acl) {
                        $weakPerms = $acl.Access | Where-Object {
                            $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                            $_.FileSystemRights -match "(Write|Modify|FullControl|ChangePermissions|TakeOwnership)"
                        }
                        if ($weakPerms) {
                            $vulnerableSvcs += "$($s.Name): $exePath"
                        }
                    }
                }
            }
        }
        Add-Finding -Category "Local Services" -CISRef "Custom" `
            -CheckTitle "Service binaries with weak permissions" `
            -Status $(if($vulnerableSvcs.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No writable service binaries by low-priv users" `
            -Actual $(if($vulnerableSvcs.Count -eq 0){"None found (sampled top 50 running services)"}else{($vulnerableSvcs | Select-Object -First 5) -join "; "}) `
            -Description "Services with writable binaries allow privilege escalation." -Severity "Critical"
    } catch {
        Add-Finding -Category "Local Services" -CISRef "Custom" -CheckTitle "Service binary permission audit" `
            -Status "Error" -Actual "Check failed: $_" -Severity "High"
    }

    # Unquoted service paths
    Write-Progress2 "Services" "Checking for unquoted service paths"
    try {
        $unquoted = Get-CimInstance Win32_Service | Where-Object {
            $_.PathName -and
            $_.PathName -notmatch '^\s*"' -and
            $_.PathName -match '\s' -and
            $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\' 
        }
        Add-Finding -Category "Local Services" -CISRef "Custom" `
            -CheckTitle "Unquoted service paths" `
            -Status $(if($unquoted.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No unquoted service paths with spaces" `
            -Actual $(if($unquoted.Count -eq 0){"None found"}else{"$($unquoted.Count) found: $(($unquoted | Select-Object -First 3 | ForEach-Object { $_.Name }) -join ', ')"}) `
            -Description "Unquoted paths with spaces allow binary planting attacks." -Severity "High"
    } catch {
        Add-Finding -Category "Local Services" -CISRef "Custom" -CheckTitle "Unquoted service path check" `
            -Status "Error" -Actual "Check failed" -Severity "High"
    }
}

# ============================================================================
# CATEGORY 5: FILE SYSTEM REVIEW
# ============================================================================
function Test-FileSystem {
    Write-Host "`n[+] File System Security Review" -ForegroundColor Green

    # Check world-writable directories in PATH
    Write-Progress2 "FileSystem" "Checking PATH for writable directories"
    try {
        $pathDirs = $env:PATH -split ";"
        $writablePaths = @()
        foreach ($dir in $pathDirs) {
            if ($dir -and (Test-Path $dir)) {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                if ($acl) {
                    $weak = $acl.Access | Where-Object {
                        $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)"
                    }
                    if ($weak) { $writablePaths += $dir }
                }
            }
        }
        Add-Finding -Category "File System" -CISRef "Custom" -CheckTitle "PATH directories writable by low-priv users" `
            -Status $(if($writablePaths.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No user-writable directories in system PATH" `
            -Actual $(if($writablePaths.Count -eq 0){"None found"}else{($writablePaths | Select-Object -First 5) -join "; "}) `
            -Description "Writable PATH directories enable DLL hijacking/binary planting." -Severity "Critical"
    } catch {
        Add-Finding -Category "File System" -CISRef "Custom" -CheckTitle "PATH writable check" -Status "Error" -Actual "$_" -Severity "High"
    }

    # Check common privilege escalation folders
    Write-Progress2 "FileSystem" "Checking common escalation paths"
    $sensitiveDirs = @(
        @{ Path="C:\Windows\System32"; Desc="System32" },
        @{ Path="C:\Windows\SysWOW64"; Desc="SysWOW64" },
        @{ Path="C:\Windows\Temp"; Desc="Windows Temp" },
        @{ Path="C:\ProgramData"; Desc="ProgramData root" }
    )
    foreach ($d in $sensitiveDirs) {
        if (Test-Path $d.Path) {
            $acl = Get-Acl $d.Path -ErrorAction SilentlyContinue
            $everyoneWrite = $acl.Access | Where-Object {
                $_.IdentityReference -eq "Everyone" -and
                $_.FileSystemRights -match "(Write|Modify|FullControl)"
            }
            Add-Finding -Category "File System" -CISRef "Custom" `
                -CheckTitle "$($d.Desc) - no Everyone write" `
                -Status $(if($everyoneWrite){"Fail"}else{"Pass"}) `
                -Expected "No 'Everyone' write access" `
                -Actual $(if($everyoneWrite){"Everyone has write access"}else{"Properly restricted"}) `
                -Description "Sensitive system directories should not allow Everyone write." -Severity "High"
        }
    }

    # AlwaysInstallElevated check
    Write-Progress2 "FileSystem" "Checking AlwaysInstallElevated"
    $aieHKLM = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieHKCU = Get-RegValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieVuln = ($aieHKLM -eq 1) -and ($aieHKCU -eq 1)
    Add-Finding -Category "File System" -CISRef "18.10.82.2" `
        -CheckTitle "AlwaysInstallElevated disabled" `
        -Status $(if($aieVuln){"Fail"}else{"Pass"}) `
        -Expected "0 or Not Configured in both HKLM and HKCU" `
        -Actual "HKLM=$aieHKLM, HKCU=$aieHKCU" `
        -Description "CIS 18.10.82.2: AlwaysInstallElevated=1 in both hives allows any MSI to run as SYSTEM." `
        -Severity "Critical"

    # Safe DLL Search Mode
    $safeDll = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"
    Add-Finding -Category "File System" -CISRef "18.5.9" -CheckTitle "Safe DLL Search Mode enabled" `
        -Status $(if($safeDll -eq 1 -or $null -eq $safeDll){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled) - default" -Actual $(if($null -eq $safeDll){"Not Configured (Default=Enabled)"}else{$safeDll}) `
        -Description "CIS 18.5.9: System directories searched before current directory for DLLs." -Severity "High"

    # SEHOP
    $sehop = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation"
    Add-Finding -Category "File System" -CISRef "18.4.5" -CheckTitle "SEHOP enabled" `
        -Status $(if($sehop -eq 0 -or $null -eq $sehop){"Pass"}else{"Fail"}) `
        -Expected "0 (Enabled)" -Actual $(if($null -eq $sehop){"Not Configured (Default)"}else{$sehop}) `
        -Description "CIS 18.4.5: Structured Exception Handling Overwrite Protection." -Severity "High"
}

# ============================================================================
# CATEGORY 6: SECURITY CONFIGURATION INSPECTION (AV, Firewall, HIPS)
# ============================================================================
function Test-SecurityProducts {
    Write-Host "`n[+] Security Product Inspection" -ForegroundColor Green

    # Windows Defender Status
    Write-Progress2 "Security" "Checking Windows Defender Antivirus"
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        # Real-time protection
        Add-Finding -Category "Security Products" -CISRef "18.10.42.10.3" `
            -CheckTitle "Defender Real-Time Protection enabled" `
            -Status $(if($mpStatus.RealTimeProtectionEnabled){"Pass"}else{"Fail"}) `
            -Expected "Enabled" -Actual $mpStatus.RealTimeProtectionEnabled.ToString() `
            -Description "CIS 18.10.42.10.3: Real-time protection must not be disabled." -Severity "Critical"

        # Behavior monitoring
        Add-Finding -Category "Security Products" -CISRef "18.10.42.10.4" `
            -CheckTitle "Defender Behavior Monitoring enabled" `
            -Status $(if($mpStatus.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) `
            -Expected "Enabled" -Actual $mpStatus.BehaviorMonitorEnabled.ToString() `
            -Description "CIS 18.10.42.10.4: Behavior monitoring detects suspicious process activity." -Severity "High"

        # Antivirus signature age
        $sigAge = $mpStatus.AntivirusSignatureAge
        Add-Finding -Category "Security Products" -CISRef "Custom" `
            -CheckTitle "Defender signature age" `
            -Status $(if($sigAge -le 1){"Pass"}elseif($sigAge -le 3){"Warning"}else{"Fail"}) `
            -Expected "1 day or less" -Actual "$sigAge day(s) old" `
            -Description "AV signatures should be updated daily." `
            -Severity $(if($sigAge -gt 7){"Critical"}elseif($sigAge -gt 3){"High"}else{"Low"})

        # Engine version
        Add-Finding -Category "Security Products" -CISRef "Custom" `
            -CheckTitle "Defender Engine & Signature Versions" `
            -Status "Info" `
            -Actual "Engine: $($mpStatus.AMEngineVersion), Sigs: $($mpStatus.AntivirusSignatureVersion), Product: $($mpStatus.AMProductVersion)" `
            -Description "Current AV engine and signature details." -Severity "Informational"

        # Antispyware enabled
        Add-Finding -Category "Security Products" -CISRef "Custom" `
            -CheckTitle "Antispyware enabled" `
            -Status $(if($mpStatus.AntispywareEnabled){"Pass"}else{"Fail"}) `
            -Expected "Enabled" -Actual $mpStatus.AntispywareEnabled.ToString() -Severity "High"

    } catch {
        Add-Finding -Category "Security Products" -CISRef "18.10.42" -CheckTitle "Windows Defender Status" `
            -Status "Warning" -Actual "Could not query Defender - may be using third-party AV" -Severity "High"
    }

    # Defender policy settings
    $defenderPolicies = @(
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"; CIS="18.10.42.10.3"; Desc="Real-time protection not disabled"; Expected=0; Sev="Critical" },
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="PUAProtection"; CIS="18.10.42.16"; Desc="PUA Protection = Block"; Expected=1; Sev="Medium" },
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableRemovableDriveScanning"; CIS="18.10.42.13.3"; Desc="Scan removable drives"; Expected=0; Sev="Medium" },
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableEmailScanning"; CIS="18.10.42.13.5"; Desc="Email scanning enabled"; Expected=0; Sev="Medium" },
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="SpynetReporting"; CIS="18.10.42.5.2"; Desc="MAPS reporting = Advanced"; Expected=2; Sev="Medium" },
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="EnableFileHashComputation"; CIS="18.10.42.7.1"; Desc="File hash computation enabled"; Expected=1; Sev="Low" },
        @{ Reg="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableScriptScanning"; CIS="18.10.42.10.5"; Desc="Script scanning enabled"; Expected=0; Sev="High" }
    )

    foreach ($pol in $defenderPolicies) {
        $result = Test-RegValue -Path $pol.Reg -Name $pol.Name -ExpectedValue $pol.Expected
        Add-Finding -Category "Security Products" -CISRef $pol.CIS -CheckTitle $pol.Desc `
            -Status $(if($result.Match){"Pass"}elseif($result.Actual -eq "Not Configured"){"Warning"}else{"Fail"}) `
            -Expected "$($pol.Expected)" -Actual "$($result.Actual)" `
            -Description "CIS $($pol.CIS): $($pol.Desc)" -Severity $pol.Sev
    }

    # ASR Rules
    Write-Progress2 "Security" "Checking Attack Surface Reduction rules"
    $asrEnabled = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules"
    Add-Finding -Category "Security Products" -CISRef "18.10.42.6.1.1" `
        -CheckTitle "Attack Surface Reduction rules configured" `
        -Status $(if($asrEnabled -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $asrEnabled){"Not Configured"}else{$asrEnabled}) `
        -Description "CIS 18.10.42.6.1.1: ASR rules mitigate common attack vectors." -Severity "High"

    # Network Protection
    $netProtect = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
    Add-Finding -Category "Security Products" -CISRef "18.10.42.6.3.1" `
        -CheckTitle "Network Protection = Block" `
        -Status $(if($netProtect -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Block)" -Actual $(if($null -eq $netProtect){"Not Configured"}else{$netProtect}) `
        -Description "CIS 18.10.42.6.3.1: Prevents connections to dangerous websites." -Severity "High"

    # SmartScreen
    $smartscreen = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
    Add-Finding -Category "Security Products" -CISRef "18.10.77.2.1" `
        -CheckTitle "SmartScreen = Warn and prevent bypass" `
        -Status $(if($smartscreen -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $smartscreen){"Not Configured"}else{$smartscreen}) `
        -Description "CIS 18.10.77.2.1: SmartScreen protects against malicious downloads." -Severity "High"

    # Windows Firewall - All Profiles
    Write-Progress2 "Security" "Checking Windows Firewall profiles"
    $fwProfiles = @(
        @{ Profile="Domain";  RegPath="HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; CISBase="9.1" },
        @{ Profile="Private"; RegPath="HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"; CISBase="9.2" },
        @{ Profile="Public";  RegPath="HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile";  CISBase="9.3" }
    )
    foreach ($fw in $fwProfiles) {
        # Firewall state
        $fwState = Get-RegValue $fw.RegPath "EnableFirewall"
        Add-Finding -Category "Security Products" -CISRef "$($fw.CISBase).1" `
            -CheckTitle "Firewall $($fw.Profile): State = On" `
            -Status $(if($fwState -eq 1){"Pass"}else{"Fail"}) `
            -Expected "1 (On)" -Actual $(if($null -eq $fwState){"Not Configured"}else{$fwState}) `
            -Description "CIS $($fw.CISBase).1: Firewall must be enabled for $($fw.Profile) profile." -Severity "Critical"

        # Inbound = Block
        $fwInbound = Get-RegValue $fw.RegPath "DefaultInboundAction"
        Add-Finding -Category "Security Products" -CISRef "$($fw.CISBase).2" `
            -CheckTitle "Firewall $($fw.Profile): Inbound = Block" `
            -Status $(if($fwInbound -eq 1){"Pass"}else{"Fail"}) `
            -Expected "1 (Block)" -Actual $(if($null -eq $fwInbound){"Not Configured"}else{$fwInbound}) `
            -Description "CIS $($fw.CISBase).2: Default block inbound connections." -Severity "High"

        # Log dropped packets
        $fwLogDrop = Get-RegValue "$($fw.RegPath)\Logging" "LogDroppedPackets"
        Add-Finding -Category "Security Products" -CISRef "$($fw.CISBase).6" `
            -CheckTitle "Firewall $($fw.Profile): Log dropped packets" `
            -Status $(if($fwLogDrop -eq 1){"Pass"}else{"Fail"}) `
            -Expected "1 (Yes)" -Actual $(if($null -eq $fwLogDrop){"Not Configured"}else{$fwLogDrop}) `
            -Description "CIS $($fw.CISBase).6: Log dropped packets for forensic analysis." -Severity "Medium"

        # Log successful connections
        $fwLogSuccess = Get-RegValue "$($fw.RegPath)\Logging" "LogSuccessfulConnections"
        Add-Finding -Category "Security Products" -CISRef "$($fw.CISBase).7" `
            -CheckTitle "Firewall $($fw.Profile): Log successful connections" `
            -Status $(if($fwLogSuccess -eq 1){"Pass"}else{"Fail"}) `
            -Expected "1 (Yes)" -Actual $(if($null -eq $fwLogSuccess){"Not Configured"}else{$fwLogSuccess}) `
            -Description "CIS $($fw.CISBase).7: Log successful connections for audit trail." -Severity "Medium"

        # Log size >= 16384
        $fwLogSize = Get-RegValue "$($fw.RegPath)\Logging" "LogFileSize"
        Add-Finding -Category "Security Products" -CISRef "$($fw.CISBase).5" `
            -CheckTitle "Firewall $($fw.Profile): Log size >= 16384 KB" `
            -Status $(if($fwLogSize -ge 16384){"Pass"}else{"Fail"}) `
            -Expected ">= 16384" -Actual $(if($null -eq $fwLogSize){"Not Configured"}else{$fwLogSize}) `
            -Description "CIS $($fw.CISBase).5: Adequate log file size." -Severity "Low"
    }

    # Enhanced Phishing Protection
    $phishChecks = @(
        @{ Name="NotifyMalicious"; CIS="18.10.77.1.2"; Desc="Notify on malicious sites" },
        @{ Name="NotifyPasswordReuse"; CIS="18.10.77.1.3"; Desc="Notify on password reuse" },
        @{ Name="NotifyUnsafeApp"; CIS="18.10.77.1.4"; Desc="Notify on unsafe apps" },
        @{ Name="ServiceEnabled"; CIS="18.10.77.1.5"; Desc="Phishing protection service enabled" }
    )
    foreach ($pc in $phishChecks) {
        $val = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" $pc.Name
        Add-Finding -Category "Security Products" -CISRef $pc.CIS `
            -CheckTitle "Enhanced Phishing: $($pc.Desc)" `
            -Status $(if($val -eq 1){"Pass"}else{"Fail"}) `
            -Expected "1 (Enabled)" -Actual $(if($null -eq $val){"Not Configured"}else{$val}) `
            -Description "CIS $($pc.CIS): $($pc.Desc)." -Severity "Medium"
    }
}

# ============================================================================
# CATEGORY 7: REMOVABLE MEDIA CHECKING
# ============================================================================
function Test-RemovableMedia {
    Write-Host "`n[+] Removable Media Controls" -ForegroundColor Green

    # AutoPlay disabled
    $autoplay = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
    Add-Finding -Category "Removable Media" -CISRef "18.10.8.3" -CheckTitle "AutoPlay disabled for all drives" `
        -Status $(if($autoplay -eq 255){"Pass"}else{"Fail"}) `
        -Expected "255 (All drives)" -Actual $(if($null -eq $autoplay){"Not Configured"}else{$autoplay}) `
        -Description "CIS 18.10.8.3: Disable AutoPlay to prevent automatic code execution from removable media." `
        -Severity "High"

    # AutoRun default behavior
    $autorun = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
    Add-Finding -Category "Removable Media" -CISRef "18.10.8.2" `
        -CheckTitle "Default AutoRun = Do not execute" `
        -Status $(if($autorun -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Do not execute)" -Actual $(if($null -eq $autorun){"Not Configured"}else{$autorun}) `
        -Description "CIS 18.10.8.2: Prevent autorun commands from executing." -Severity "High"

    # Disallow Autoplay for non-volume devices
    $noAutoplayNonVol = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume"
    Add-Finding -Category "Removable Media" -CISRef "18.10.8.1" `
        -CheckTitle "Disallow Autoplay for non-volume devices" `
        -Status $(if($noAutoplayNonVol -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $noAutoplayNonVol){"Not Configured"}else{$noAutoplayNonVol}) `
        -Description "CIS 18.10.8.1: Prevent autoplay on MTP/PTP devices." -Severity "Medium"

    # Device installation restrictions (IEEE 1394 / Thunderbolt DMA)
    $devInstall = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyDeviceClasses"
    Add-Finding -Category "Removable Media" -CISRef "18.9.7.1.1" `
        -CheckTitle "Device installation restrictions configured" `
        -Status $(if($devInstall -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $devInstall){"Not Configured"}else{$devInstall}) `
        -Description "CIS 18.9.7.1.1: Block installation of devices by device setup class (IEEE 1394)." `
        -Severity "High"

    # Audit removable storage
    Write-Progress2 "Removable Media" "Checking removable storage auditing"
    try {
        $auditRemovable = auditpol /get /subcategory:"{0cce9245-69ae-11d9-bed3-505054503030}" 2>$null
        $removableAudit = $auditRemovable | Select-String "Success and Failure"
        Add-Finding -Category "Removable Media" -CISRef "17.6.4" `
            -CheckTitle "Audit Removable Storage = Success and Failure" `
            -Status $(if($removableAudit){"Pass"}else{"Fail"}) `
            -Expected "Success and Failure" `
            -Actual $(if($removableAudit){"Success and Failure"}else{($auditRemovable | Select-String "Removable" | Out-String).Trim()}) `
            -Description "CIS 17.6.4: All removable storage access should be logged." -Severity "High"
    } catch {
        Add-Finding -Category "Removable Media" -CISRef "17.6.4" -CheckTitle "Audit Removable Storage" `
            -Status "Error" -Actual "auditpol query failed" -Severity "High"
    }

    # Camera disabled
    $camera = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera"
    Add-Finding -Category "Removable Media" -CISRef "18.10.11.1" -CheckTitle "Camera disabled" `
        -Status $(if($camera -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $camera){"Not Configured"}else{$camera}) `
        -Description "CIS 18.10.11.1: Camera should be disabled on hardened systems." -Severity "Low" -Profile "L2"
}

# ============================================================================
# CATEGORY 8: USER ACCOUNT AND PASSWORD CONFIGURATION
# ============================================================================
function Test-UserAccountConfig {
    Write-Host "`n[+] User Account & Password Configuration" -ForegroundColor Green

    # Export security policy for analysis
    Write-Progress2 "Accounts" "Exporting security policy"
    $secpolFile = "$env:TEMP\secpol_export.cfg"
    secedit /export /cfg $secpolFile /quiet 2>$null
    $secpol = @{}
    if (Test-Path $secpolFile) {
        Get-Content $secpolFile | ForEach-Object {
            if ($_ -match '^(.+?)\s*=\s*(.+)$') {
                $secpol[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
    }

    # 1.1.1 Password History >= 24
    $pwHistory = [int]$secpol["PasswordHistorySize"]
    Add-Finding -Category "User Accounts" -CISRef "1.1.1" -CheckTitle "Password history >= 24" `
        -Status $(if($pwHistory -ge 24){"Pass"}else{"Fail"}) `
        -Expected ">= 24" -Actual $pwHistory `
        -Description "CIS 1.1.1: Enforce password history of 24 or more." -Severity "Medium"

    # 1.1.2 Max password age <= 365 (not 0)
    $maxPwAge = [int]$secpol["MaximumPasswordAge"]
    Add-Finding -Category "User Accounts" -CISRef "1.1.2" -CheckTitle "Maximum password age <= 365 days, not 0" `
        -Status $(if($maxPwAge -ge 1 -and $maxPwAge -le 365){"Pass"}else{"Fail"}) `
        -Expected "1-365 days" -Actual "$maxPwAge days" `
        -Description "CIS 1.1.2: Passwords must expire within 365 days." -Severity "Medium"

    # 1.1.3 Min password age >= 1
    $minPwAge = [int]$secpol["MinimumPasswordAge"]
    Add-Finding -Category "User Accounts" -CISRef "1.1.3" -CheckTitle "Minimum password age >= 1 day" `
        -Status $(if($minPwAge -ge 1){"Pass"}else{"Fail"}) `
        -Expected ">= 1 day" -Actual "$minPwAge day(s)" `
        -Description "CIS 1.1.3: Prevent rapid password cycling." -Severity "Medium"

    # 1.1.4 Min password length >= 14
    $minPwLen = [int]$secpol["MinimumPasswordLength"]
    Add-Finding -Category "User Accounts" -CISRef "1.1.4" -CheckTitle "Minimum password length >= 14" `
        -Status $(if($minPwLen -ge 14){"Pass"}else{"Fail"}) `
        -Expected ">= 14" -Actual $minPwLen `
        -Description "CIS 1.1.4: Minimum 14 character password length." -Severity "High"

    # 1.1.5 Complexity enabled
    $complexity = [int]$secpol["PasswordComplexity"]
    Add-Finding -Category "User Accounts" -CISRef "1.1.5" -CheckTitle "Password complexity enabled" `
        -Status $(if($complexity -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $complexity `
        -Description "CIS 1.1.5: Passwords must meet complexity requirements." -Severity "High"

    # 1.1.7 Reversible encryption disabled
    $reversible = [int]$secpol["ClearTextPassword"]
    Add-Finding -Category "User Accounts" -CISRef "1.1.7" -CheckTitle "Reversible encryption disabled" `
        -Status $(if($reversible -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $reversible `
        -Description "CIS 1.1.7: Never store passwords using reversible encryption." -Severity "Critical"

    # 1.2.1 Lockout duration >= 15
    $lockDuration = [int]$secpol["LockoutDuration"]
    Add-Finding -Category "User Accounts" -CISRef "1.2.1" -CheckTitle "Account lockout duration >= 15 mins" `
        -Status $(if($lockDuration -ge 15){"Pass"}else{"Fail"}) `
        -Expected ">= 15 minutes" -Actual "$lockDuration minutes" `
        -Description "CIS 1.2.1: Accounts should be locked for at least 15 minutes." -Severity "Medium"

    # 1.2.2 Lockout threshold <= 5 (not 0)
    $lockThreshold = [int]$secpol["LockoutBadCount"]
    Add-Finding -Category "User Accounts" -CISRef "1.2.2" -CheckTitle "Account lockout threshold <= 5, not 0" `
        -Status $(if($lockThreshold -ge 1 -and $lockThreshold -le 5){"Pass"}else{"Fail"}) `
        -Expected "1-5 attempts" -Actual "$lockThreshold attempt(s)" `
        -Description "CIS 1.2.2: Lock account after 5 or fewer failed attempts." -Severity "High"

    # 1.2.4 Reset lockout counter >= 15
    $lockReset = [int]$secpol["ResetLockoutCount"]
    Add-Finding -Category "User Accounts" -CISRef "1.2.4" -CheckTitle "Reset lockout counter >= 15 mins" `
        -Status $(if($lockReset -ge 15){"Pass"}else{"Fail"}) `
        -Expected ">= 15 minutes" -Actual "$lockReset minutes" `
        -Description "CIS 1.2.4: Lockout counter should reset after at least 15 minutes." -Severity "Medium"

    # Guest account disabled
    $guestDisabled = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" "Guest"
    $guestAccount = Get-LocalUser | Where-Object { $_.Name -eq "Guest" -or $_.SID -like "*-501" }
    Add-Finding -Category "User Accounts" -CISRef "2.3.1.1" -CheckTitle "Guest account disabled" `
        -Status $(if($guestAccount -and -not $guestAccount.Enabled){"Pass"}else{"Fail"}) `
        -Expected "Disabled" -Actual $(if($guestAccount){"Enabled=$($guestAccount.Enabled)"}else{"Not Found"}) `
        -Description "CIS 2.3.1.1: Guest account must be disabled." -Severity "High"

    # Blank password restriction
    $blankPw = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
    Add-Finding -Category "User Accounts" -CISRef "2.3.1.2" `
        -CheckTitle "Blank passwords limited to console only" `
        -Status $(if($blankPw -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $blankPw){"Not Configured"}else{$blankPw}) `
        -Description "CIS 2.3.1.2: Accounts with blank passwords restricted to console logon." -Severity "Critical"

    # Admin account renamed
    Write-Progress2 "Accounts" "Checking admin/guest account names"
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    Add-Finding -Category "User Accounts" -CISRef "2.3.1.3" -CheckTitle "Administrator account renamed" `
        -Status $(if($adminAccount.Name -ne "Administrator"){"Pass"}else{"Fail"}) `
        -Expected "Not 'Administrator'" -Actual $adminAccount.Name `
        -Description "CIS 2.3.1.3: Built-in Administrator should be renamed." -Severity "Medium"

    # Guest account renamed
    $guestRename = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
    Add-Finding -Category "User Accounts" -CISRef "2.3.1.4" -CheckTitle "Guest account renamed" `
        -Status $(if($guestRename.Name -ne "Guest"){"Pass"}else{"Fail"}) `
        -Expected "Not 'Guest'" -Actual $guestRename.Name `
        -Description "CIS 2.3.1.4: Built-in Guest should be renamed." -Severity "Low"

    # UAC settings
    Write-Progress2 "Accounts" "Checking UAC configuration"
    $uacChecks = @(
        @{ Name="EnableLUA"; CIS="2.3.17.6"; Desc="Admin Approval Mode enabled"; Expected=1; Sev="Critical" },
        @{ Name="ConsentPromptBehaviorAdmin"; CIS="2.3.17.2"; Desc="Admin elevation prompt = Consent on secure desktop (2)"; Expected=2; Sev="High" },
        @{ Name="ConsentPromptBehaviorUser"; CIS="2.3.17.3"; Desc="Standard user auto deny elevation"; Expected=0; Sev="High" },
        @{ Name="PromptOnSecureDesktop"; CIS="2.3.17.7"; Desc="Elevation prompt on secure desktop"; Expected=1; Sev="High" },
        @{ Name="EnableInstallerDetection"; CIS="2.3.17.4"; Desc="Detect app installations and prompt"; Expected=1; Sev="Medium" },
        @{ Name="EnableSecureUIAPaths"; CIS="2.3.17.5"; Desc="UIAccess only from secure locations"; Expected=1; Sev="Medium" },
        @{ Name="EnableVirtualization"; CIS="2.3.17.8"; Desc="Virtualize file/reg write failures"; Expected=1; Sev="Low" },
        @{ Name="FilterAdministratorToken"; CIS="2.3.17.1"; Desc="Admin Approval Mode for built-in Admin"; Expected=1; Sev="High" }
    )
    foreach ($uac in $uacChecks) {
        $val = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" $uac.Name
        $match = if ($uac.Name -eq "ConsentPromptBehaviorAdmin") { $val -le 2 -and $val -ge 1 } else { $val -eq $uac.Expected }
        Add-Finding -Category "User Accounts" -CISRef $uac.CIS -CheckTitle $uac.Desc `
            -Status $(if($match){"Pass"}elseif($null -eq $val){"Fail"}else{"Fail"}) `
            -Expected "$($uac.Expected)" -Actual $(if($null -eq $val){"Not Configured"}else{$val}) `
            -Description "CIS $($uac.CIS): $($uac.Desc)" -Severity $uac.Sev
    }

    # Security Questions disabled
    $secQuestions = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "NoLocalPasswordResetQuestions"
    Add-Finding -Category "User Accounts" -CISRef "18.10.15.3" `
        -CheckTitle "Security questions for local accounts disabled" `
        -Status $(if($secQuestions -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $secQuestions){"Not Configured"}else{$secQuestions}) `
        -Description "CIS 18.10.15.3: Security questions can be used for social engineering." -Severity "Medium"

    # Credential storage
    $noCredStorage = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds"
    Add-Finding -Category "User Accounts" -CISRef "2.3.10.4" `
        -CheckTitle "No storage of passwords for network auth" `
        -Status $(if($noCredStorage -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $noCredStorage){"Not Configured"}else{$noCredStorage}) `
        -Description "CIS 2.3.10.4: Prevent caching of network credentials." -Severity "High"

    # WDigest disabled
    $wdigest = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-Finding -Category "User Accounts" -CISRef "18.4.7" `
        -CheckTitle "WDigest authentication disabled" `
        -Status $(if($wdigest -eq 0 -or $null -eq $wdigest){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $wdigest){"Not Configured (Default=Disabled on Win11)"}else{$wdigest}) `
        -Description "CIS 18.4.7: WDigest stores plaintext passwords in LSASS memory." -Severity "Critical"

    # Cleanup
    if (Test-Path $secpolFile) { Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue }
}

# ============================================================================
# CATEGORY 9: PRIVILEGE ESCALATION VECTORS
# ============================================================================
function Test-PrivilegeEscalation {
    Write-Host "`n[+] Privilege Escalation Vector Checks" -ForegroundColor Green

    # User Rights Assignment via secedit
    Write-Progress2 "PrivEsc" "Checking User Rights Assignment"
    $secpolFile = "$env:TEMP\secpol_privesc.cfg"
    secedit /export /cfg $secpolFile /quiet 2>$null
    $secpol = @{}
    if (Test-Path $secpolFile) {
        Get-Content $secpolFile | ForEach-Object {
            if ($_ -match '^(.+?)\s*=\s*(.+)$') {
                $secpol[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
    }

    # Debug Programs (SeDebugPrivilege)
    $debugProgs = $secpol["SeDebugPrivilege"]
    Add-Finding -Category "Privilege Escalation" -CISRef "2.2.14" `
        -CheckTitle "Debug programs = Administrators only" `
        -Status $(if($debugProgs -match "^\*S-1-5-32-544$"){"Pass"}else{"Fail"}) `
        -Expected "Administrators only" -Actual $(if($debugProgs){$debugProgs}else{"Not Configured"}) `
        -Description "CIS 2.2.14: SeDebugPrivilege allows access to any process memory." -Severity "Critical"

    # Act as part of OS
    $actAsOS = $secpol["SeTcbPrivilege"]
    Add-Finding -Category "Privilege Escalation" -CISRef "2.2.3" `
        -CheckTitle "Act as part of the OS = No One" `
        -Status $(if([string]::IsNullOrWhiteSpace($actAsOS)){"Pass"}else{"Fail"}) `
        -Expected "No One" -Actual $(if($actAsOS){$actAsOS}else{"No One (Compliant)"}) `
        -Description "CIS 2.2.3: SeTcbPrivilege grants SYSTEM-level access." -Severity "Critical"

    # Create Token Object
    $createToken = $secpol["SeCreateTokenPrivilege"]
    Add-Finding -Category "Privilege Escalation" -CISRef "2.2.10" `
        -CheckTitle "Create a token object = No One" `
        -Status $(if([string]::IsNullOrWhiteSpace($createToken)){"Pass"}else{"Fail"}) `
        -Expected "No One" -Actual $(if($createToken){$createToken}else{"No One (Compliant)"}) `
        -Description "CIS 2.2.10: Token creation allows impersonation of any user." -Severity "Critical"

    # Take ownership
    $takeOwnership = $secpol["SeTakeOwnershipPrivilege"]
    Add-Finding -Category "Privilege Escalation" -CISRef "2.2.38" `
        -CheckTitle "Take ownership = Administrators only" `
        -Status $(if($takeOwnership -match "^\*S-1-5-32-544$"){"Pass"}else{"Fail"}) `
        -Expected "Administrators only" -Actual $(if($takeOwnership){$takeOwnership}else{"Not Configured"}) `
        -Description "CIS 2.2.38: Taking ownership of files bypasses ACLs." -Severity "High"

    # Load/unload device drivers
    $loadDrivers = $secpol["SeLoadDriverPrivilege"]
    Add-Finding -Category "Privilege Escalation" -CISRef "2.2.25" `
        -CheckTitle "Load device drivers = Administrators only" `
        -Status $(if($loadDrivers -match "^\*S-1-5-32-544$"){"Pass"}else{"Fail"}) `
        -Expected "Administrators only" -Actual $(if($loadDrivers){$loadDrivers}else{"Not Configured"}) `
        -Description "CIS 2.2.25: Loading drivers can introduce kernel-level malware." -Severity "Critical"

    # Sudo disabled (new Win11 24H2)
    $sudo = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSudo"
    Add-Finding -Category "Privilege Escalation" -CISRef "18.9.54" `
        -CheckTitle "Sudo command disabled" `
        -Status $(if($sudo -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $sudo){"Not Configured"}else{$sudo}) `
        -Description "CIS 18.9.54: Windows sudo command should be disabled on enterprise systems." -Severity "Medium"

    # Credential delegation
    $credDeleg = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowDefaultCredentials"
    Add-Finding -Category "Privilege Escalation" -CISRef "18.9.4" `
        -CheckTitle "Credential delegation controlled" `
        -Status $(if($credDeleg -ne 1){"Pass"}else{"Fail"}) `
        -Expected "Not broadly delegating credentials" `
        -Actual $(if($null -eq $credDeleg){"Not Configured"}else{$credDeleg}) `
        -Description "Uncontrolled credential delegation enables lateral movement." -Severity "High"

    # Scheduled tasks with SYSTEM context
    Write-Progress2 "PrivEsc" "Checking for vulnerable scheduled tasks"
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|LocalSystem" -and
            $_.State -ne "Disabled" -and
            $_.TaskPath -notmatch "\\Microsoft\\"
        }
        Add-Finding -Category "Privilege Escalation" -CISRef "Custom" `
            -CheckTitle "Non-Microsoft SYSTEM scheduled tasks" `
            -Status $(if($tasks.Count -eq 0){"Pass"}else{"Warning"}) `
            -Expected "None (or verified legitimate)" `
            -Actual "$($tasks.Count) found$(if($tasks.Count -gt 0){': ' + (($tasks | Select-Object -First 3 | ForEach-Object { $_.TaskName }) -join ', ')})" `
            -Description "Scheduled tasks running as SYSTEM can be abused for privilege escalation." -Severity "Medium"
    } catch {
        Add-Finding -Category "Privilege Escalation" -CISRef "Custom" -CheckTitle "Scheduled task audit" `
            -Status "Error" -Actual "$_" -Severity "Medium"
    }

    if (Test-Path $secpolFile) { Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue }
}

# ============================================================================
# CATEGORY 10: LATERAL MOVEMENT
# ============================================================================
function Test-LateralMovement {
    Write-Host "`n[+] Lateral Movement Risk Checks" -ForegroundColor Green

    # RDP Disabled
    $rdpDisabled = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDenyTSConnections"
    Add-Finding -Category "Lateral Movement" -CISRef "18.10.57.3.2.1" `
        -CheckTitle "Remote Desktop connections disabled" `
        -Status $(if($rdpDisabled -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Disabled)" -Actual $(if($null -eq $rdpDisabled){"Not Configured"}else{$rdpDisabled}) `
        -Description "CIS 18.10.57.3.2.1: RDP should be disabled unless required." -Severity "High" -Profile "L2"

    # RDP NLA Required
    $rdpNLA = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"
    Add-Finding -Category "Lateral Movement" -CISRef "18.10.57.3.9.4" `
        -CheckTitle "RDP requires Network Level Authentication" `
        -Status $(if($rdpNLA -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $rdpNLA){"Not Configured"}else{$rdpNLA}) `
        -Description "CIS 18.10.57.3.9.4: NLA prevents pre-authentication attacks on RDP." -Severity "High"

    # RDP Encryption Level
    $rdpEncLevel = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
    Add-Finding -Category "Lateral Movement" -CISRef "18.10.57.3.9.5" `
        -CheckTitle "RDP Encryption Level = High" `
        -Status $(if($rdpEncLevel -eq 3){"Pass"}else{"Fail"}) `
        -Expected "3 (High)" -Actual $(if($null -eq $rdpEncLevel){"Not Configured"}else{$rdpEncLevel}) `
        -Description "CIS 18.10.57.3.9.5: High encryption for RDP sessions." -Severity "High"

    # RDP Security Layer = SSL
    $rdpSecLayer = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer"
    Add-Finding -Category "Lateral Movement" -CISRef "18.10.57.3.9.3" `
        -CheckTitle "RDP Security Layer = SSL" `
        -Status $(if($rdpSecLayer -eq 2){"Pass"}else{"Fail"}) `
        -Expected "2 (SSL)" -Actual $(if($null -eq $rdpSecLayer){"Not Configured"}else{$rdpSecLayer}) `
        -Description "CIS 18.10.57.3.9.3: Use SSL/TLS for RDP connections." -Severity "High"

    # WinRM Disabled
    $winrmDisabled = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig"
    Add-Finding -Category "Lateral Movement" -CISRef "18.10.90.2.2" `
        -CheckTitle "WinRM remote management disabled" `
        -Status $(if($winrmDisabled -eq 0 -or $null -eq $winrmDisabled){"Pass"}else{"Fail"}) `
        -Expected "0 or Not Configured" -Actual $(if($null -eq $winrmDisabled){"Not Configured"}else{$winrmDisabled}) `
        -Description "CIS 18.10.90.2.2: WinRM allows remote command execution." -Severity "High" -Profile "L2"

    # WinRM Basic auth disabled
    foreach ($path in @("Client","Service")) {
        $basicAuth = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\$path" "AllowBasic"
        Add-Finding -Category "Lateral Movement" -CISRef $(if($path -eq "Client"){"18.10.90.1.1"}else{"18.10.90.2.1"}) `
            -CheckTitle "WinRM $path Basic auth disabled" `
            -Status $(if($basicAuth -eq 0){"Pass"}else{"Fail"}) `
            -Expected "0 (Disabled)" -Actual $(if($null -eq $basicAuth){"Not Configured"}else{$basicAuth}) `
            -Description "CIS: Basic auth sends credentials in cleartext." -Severity "Critical"
    }

    # Remote Shell disabled
    $remoteShell = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess"
    Add-Finding -Category "Lateral Movement" -CISRef "18.10.91.1" `
        -CheckTitle "Remote Shell access disabled" `
        -Status $(if($remoteShell -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $remoteShell){"Not Configured"}else{$remoteShell}) `
        -Description "CIS 18.10.91.1: Remote shell enables remote command execution." -Severity "High" -Profile "L2"

    # Remote Assistance disabled
    $offerRA = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"
    Add-Finding -Category "Lateral Movement" -CISRef "18.9.37.1" `
        -CheckTitle "Offer Remote Assistance disabled" `
        -Status $(if($offerRA -eq 0 -or $null -eq $offerRA){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $offerRA){"Not Configured"}else{$offerRA}) `
        -Description "CIS 18.9.37.1: Disable unsolicited remote assistance." -Severity "Medium"

    # SMBv1 Disabled
    $smbv1Client = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start"
    Add-Finding -Category "Lateral Movement" -CISRef "18.4.2" `
        -CheckTitle "SMBv1 client driver disabled" `
        -Status $(if($smbv1Client -eq 4){"Pass"}else{"Fail"}) `
        -Expected "4 (Disabled)" -Actual $(if($null -eq $smbv1Client){"Not Configured"}else{$smbv1Client}) `
        -Description "CIS 18.4.2: SMBv1 is vulnerable to EternalBlue and other exploits." -Severity "Critical"

    $smbv1Server = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    Add-Finding -Category "Lateral Movement" -CISRef "18.4.3" `
        -CheckTitle "SMBv1 server disabled" `
        -Status $(if($smbv1Server -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $smbv1Server){"Not Configured"}else{$smbv1Server}) `
        -Description "CIS 18.4.3: SMBv1 server must be disabled." -Severity "Critical"

    # Network access restrictions
    $denyNetAccess = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    Add-Finding -Category "Lateral Movement" -CISRef "2.3.10.3" `
        -CheckTitle "Anonymous SAM enum restricted" `
        -Status $(if($denyNetAccess -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $denyNetAccess){"Not Configured"}else{$denyNetAccess}) `
        -Description "CIS 2.3.10.3: Prevent anonymous enumeration of SAM accounts and shares." -Severity "High"

    # NTLM hardening
    $lmLevel = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
    Add-Finding -Category "Lateral Movement" -CISRef "2.3.11.6" `
        -CheckTitle "LAN Manager auth = NTLMv2 only, refuse LM & NTLM" `
        -Status $(if($lmLevel -eq 5){"Pass"}else{"Fail"}) `
        -Expected "5 (Send NTLMv2 only, refuse LM & NTLM)" -Actual $(if($null -eq $lmLevel){"Not Configured"}else{$lmLevel}) `
        -Description "CIS 2.3.11.6: LM/NTLM hashes are easily cracked." -Severity "Critical"

    # Cached logon credentials
    $cachedLogons = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
    Add-Finding -Category "Lateral Movement" -CISRef "2.3.7.6" `
        -CheckTitle "Cached logons <= 4" `
        -Status $(if([int]$cachedLogons -le 4){"Pass"}else{"Fail"}) `
        -Expected "<= 4" -Actual $(if($null -eq $cachedLogons){"Not Configured (Default=10)"}else{$cachedLogons}) `
        -Description "CIS 2.3.7.6: Fewer cached credentials reduces credential theft risk." -Severity "High"
}

# ============================================================================
# CATEGORY 11: NETWORK CONFIGURATION
# ============================================================================
function Test-NetworkConfig {
    Write-Host "`n[+] Network Configuration Checks" -ForegroundColor Green

    # IPv6 disabled
    $ipv6Disabled = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents"
    Add-Finding -Category "Network Configuration" -CISRef "18.6.19.2.1" `
        -CheckTitle "IPv6 disabled (DisabledComponents=0xFF)" `
        -Status $(if($ipv6Disabled -eq 255){"Pass"}else{"Fail"}) `
        -Expected "255 (0xFF)" -Actual $(if($null -eq $ipv6Disabled){"Not Configured"}else{$ipv6Disabled}) `
        -Description "CIS 18.6.19.2.1: Disable IPv6 if not required." -Severity "Medium" -Profile "L2"

    # mDNS disabled
    $mdns = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
    Add-Finding -Category "Network Configuration" -CISRef "18.6.4.1" `
        -CheckTitle "Multicast DNS (mDNS) disabled" `
        -Status $(if($mdns -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $mdns){"Not Configured"}else{$mdns}) `
        -Description "CIS 18.6.4.1: mDNS can be used for name resolution poisoning." -Severity "Medium"

    # LLMNR disabled
    $llmnr = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
    Add-Finding -Category "Network Configuration" -CISRef "18.6.4.4" `
        -CheckTitle "Multicast name resolution (LLMNR) disabled" `
        -Status $(if($llmnr -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $llmnr){"Not Configured"}else{$llmnr}) `
        -Description "CIS 18.6.4.4: LLMNR is vulnerable to MITM/poisoning attacks." -Severity "High"

    # NetBIOS NodeType = P-node
    $netbtNode = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType"
    Add-Finding -Category "Network Configuration" -CISRef "18.4.6" `
        -CheckTitle "NetBT NodeType = P-node" `
        -Status $(if($netbtNode -eq 2){"Pass"}else{"Fail"}) `
        -Expected "2 (P-node)" -Actual $(if($null -eq $netbtNode){"Not Configured"}else{$netbtNode}) `
        -Description "CIS 18.4.6: P-node prevents NetBIOS broadcast-based attacks." -Severity "Medium"

    # IP Source Routing disabled
    $ipSourceRoute = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
    Add-Finding -Category "Network Configuration" -CISRef "18.5.3" `
        -CheckTitle "IP source routing disabled (highest protection)" `
        -Status $(if($ipSourceRoute -eq 2){"Pass"}else{"Fail"}) `
        -Expected "2 (Highest protection)" -Actual $(if($null -eq $ipSourceRoute){"Not Configured"}else{$ipSourceRoute}) `
        -Description "CIS 18.5.3: Source routing allows packet path manipulation." -Severity "Medium"

    # ICMP Redirects disabled
    $icmpRedirect = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"
    Add-Finding -Category "Network Configuration" -CISRef "18.5.5" `
        -CheckTitle "ICMP redirects disabled" `
        -Status $(if($icmpRedirect -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $icmpRedirect){"Not Configured"}else{$icmpRedirect}) `
        -Description "CIS 18.5.5: ICMP redirects can override OSPF routing." -Severity "Medium"

    # Hardened UNC Paths
    $uncPaths = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON"
    Add-Finding -Category "Network Configuration" -CISRef "18.6.14.1" `
        -CheckTitle "Hardened UNC Paths configured" `
        -Status $(if($uncPaths -match "RequireMutualAuthentication=1"){"Pass"}else{"Fail"}) `
        -Expected "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" `
        -Actual $(if($uncPaths){$uncPaths}else{"Not Configured"}) `
        -Description "CIS 18.6.14.1: Harden NETLOGON/SYSVOL UNC paths against MITM." -Severity "High"

    # WiFi auto-connect to open hotspots disabled
    $wifiHotspot = Get-RegValue "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM"
    Add-Finding -Category "Network Configuration" -CISRef "18.6.23.2.1" `
        -CheckTitle "Auto-connect to open hotspots disabled" `
        -Status $(if($wifiHotspot -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $wifiHotspot){"Not Configured"}else{$wifiHotspot}) `
        -Description "CIS 18.6.23.2.1: Prevent automatic connection to untrusted networks." -Severity "Medium"

    # Prohibit non-domain network when on domain network
    $domainNetOnly = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain"
    Add-Finding -Category "Network Configuration" -CISRef "18.6.21.2" `
        -CheckTitle "Block non-domain network when on domain" `
        -Status $(if($domainNetOnly -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $domainNetOnly){"Not Configured"}else{$domainNetOnly}) `
        -Description "CIS 18.6.21.2: Prevent dual-homed connections." -Severity "Medium"

    # SMB Signing
    $smbSignAlways = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
    Add-Finding -Category "Network Configuration" -CISRef "2.3.8.1" `
        -CheckTitle "SMB client signing always required" `
        -Status $(if($smbSignAlways -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $smbSignAlways){"Not Configured"}else{$smbSignAlways}) `
        -Description "CIS 2.3.8.1: SMB signing prevents relay attacks." -Severity "High"

    $smbServerSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
    Add-Finding -Category "Network Configuration" -CISRef "2.3.9.2" `
        -CheckTitle "SMB server signing always required" `
        -Status $(if($smbServerSign -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $smbServerSign){"Not Configured"}else{$smbServerSign}) `
        -Description "CIS 2.3.9.2: Server-side SMB signing." -Severity "High"

    # Plaintext password to SMB disabled
    $smbPlaintext = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
    Add-Finding -Category "Network Configuration" -CISRef "2.3.8.2" `
        -CheckTitle "SMB unencrypted password disabled" `
        -Status $(if($smbPlaintext -eq 0 -or $null -eq $smbPlaintext){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $smbPlaintext){"Not Configured (Default=Disabled)"}else{$smbPlaintext}) `
        -Description "CIS 2.3.8.2: Never send plaintext passwords to SMB servers." -Severity "Critical"

    # WPAD Disabled
    $wpadDisabled = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation" "DisableWPAD"
    Add-Finding -Category "Network Configuration" -CISRef "18.11.1" `
        -CheckTitle "WPAD disabled" `
        -Status $(if($wpadDisabled -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Disabled)" -Actual $(if($null -eq $wpadDisabled){"Not Configured"}else{$wpadDisabled}) `
        -Description "CIS 18.11.1: WPAD enables proxy auto-discovery hijacking." -Severity "High"
}

# ============================================================================
# CATEGORY 12: LOGGING AND AUDITING
# ============================================================================
function Test-LoggingAndAuditing {
    Write-Host "`n[+] Logging & Auditing Configuration" -ForegroundColor Green

    # Advanced Audit Policy checks using auditpol
    Write-Progress2 "Logging" "Checking Advanced Audit Policy"
    $auditChecks = @(
        @{ GUID="{0CCE923F-69AE-11D9-BED3-505054503030}"; Name="Credential Validation"; CIS="17.1.1"; Expected="Success and Failure" },
        @{ GUID="{0CCE9235-69AE-11D9-BED3-505054503030}"; Name="Security Group Management"; CIS="17.2.2"; Expected="Success" },
        @{ GUID="{0CCE9236-69AE-11D9-BED3-505054503030}"; Name="User Account Management"; CIS="17.2.3"; Expected="Success and Failure" },
        @{ GUID="{0CCE9248-69AE-11D9-BED3-505054503030}"; Name="PNP Activity"; CIS="17.3.1"; Expected="Success" },
        @{ GUID="{0CCE922B-69AE-11D9-BED3-505054503030}"; Name="Process Creation"; CIS="17.3.2"; Expected="Success" },
        @{ GUID="{0CCE9217-69AE-11D9-BED3-505054503030}"; Name="Account Lockout"; CIS="17.5.1"; Expected="Failure" },
        @{ GUID="{0CCE921C-69AE-11D9-BED3-505054503030}"; Name="Group Membership"; CIS="17.5.2"; Expected="Success" },
        @{ GUID="{0CCE921B-69AE-11D9-BED3-505054503030}"; Name="Logoff"; CIS="17.5.3"; Expected="Success" },
        @{ GUID="{0CCE9215-69AE-11D9-BED3-505054503030}"; Name="Logon"; CIS="17.5.4"; Expected="Success and Failure" },
        @{ GUID="{0CCE921A-69AE-11D9-BED3-505054503030}"; Name="Special Logon"; CIS="17.5.6"; Expected="Success" },
        @{ GUID="{0CCE9244-69AE-11D9-BED3-505054503030}"; Name="File Share"; CIS="17.6.2"; Expected="Success and Failure" },
        @{ GUID="{0CCE9245-69AE-11D9-BED3-505054503030}"; Name="Removable Storage"; CIS="17.6.4"; Expected="Success and Failure" },
        @{ GUID="{0CCE922F-69AE-11D9-BED3-505054503030}"; Name="Audit Policy Change"; CIS="17.7.1"; Expected="Success" },
        @{ GUID="{0CCE9230-69AE-11D9-BED3-505054503030}"; Name="Authentication Policy Change"; CIS="17.7.2"; Expected="Success" },
        @{ GUID="{0CCE9234-69AE-11D9-BED3-505054503030}"; Name="MPSSVC Rule-Level Policy Change"; CIS="17.7.4"; Expected="Success and Failure" },
        @{ GUID="{0CCE9228-69AE-11D9-BED3-505054503030}"; Name="Sensitive Privilege Use"; CIS="17.8.1"; Expected="Success" },
        @{ GUID="{0CCE9213-69AE-11D9-BED3-505054503030}"; Name="IPsec Driver"; CIS="17.9.1"; Expected="Success and Failure" },
        @{ GUID="{0CCE9210-69AE-11D9-BED3-505054503030}"; Name="Security State Change"; CIS="17.9.3"; Expected="Success" },
        @{ GUID="{0CCE9211-69AE-11D9-BED3-505054503030}"; Name="Security System Extension"; CIS="17.9.4"; Expected="Success" },
        @{ GUID="{0CCE9212-69AE-11D9-BED3-505054503030}"; Name="System Integrity"; CIS="17.9.5"; Expected="Success and Failure" }
    )

    foreach ($audit in $auditChecks) {
        try {
            $result = auditpol /get /subcategory:"$($audit.GUID)" 2>$null
            $settingLine = ($result | Select-String "(Success|Failure|No Auditing)" | Select-Object -Last 1).ToString().Trim()
            $currentSetting = if ($settingLine -match "(Success and Failure|Success|Failure|No Auditing)") { $Matches[1] } else { "Unknown" }

            $isCompliant = $false
            if ($audit.Expected -eq "Success and Failure") { $isCompliant = $currentSetting -eq "Success and Failure" }
            elseif ($audit.Expected -eq "Success") { $isCompliant = $currentSetting -match "Success" }
            elseif ($audit.Expected -eq "Failure") { $isCompliant = $currentSetting -match "Failure" }

            Add-Finding -Category "Logging & Auditing" -CISRef $audit.CIS `
                -CheckTitle "Audit $($audit.Name) = $($audit.Expected)" `
                -Status $(if($isCompliant){"Pass"}else{"Fail"}) `
                -Expected $audit.Expected -Actual $currentSetting `
                -Description "CIS $($audit.CIS): Advanced Audit Policy." -Severity "Medium"
        } catch {
            Add-Finding -Category "Logging & Auditing" -CISRef $audit.CIS `
                -CheckTitle "Audit $($audit.Name)" -Status "Error" -Actual "Query failed" -Severity "Medium"
        }
    }

    # Event Log Sizes
    Write-Progress2 "Logging" "Checking event log configurations"
    $logChecks = @(
        @{ Log="Application"; CIS="18.10.26.1.2"; MinSize=32768 },
        @{ Log="Security"; CIS="18.10.26.2.2"; MinSize=196608 },
        @{ Log="Setup"; CIS="18.10.26.3.2"; MinSize=32768 },
        @{ Log="System"; CIS="18.10.26.4.2"; MinSize=32768 }
    )
    foreach ($log in $logChecks) {
        $maxSize = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$($log.Log)" "MaxSize"
        Add-Finding -Category "Logging & Auditing" -CISRef $log.CIS `
            -CheckTitle "$($log.Log) log size >= $($log.MinSize) KB" `
            -Status $(if($maxSize -ge $log.MinSize){"Pass"}else{"Fail"}) `
            -Expected ">= $($log.MinSize) KB" `
            -Actual $(if($null -eq $maxSize){"Not Configured (defaults apply)"}else{"$maxSize KB"}) `
            -Description "CIS $($log.CIS): Adequate log retention." -Severity "Medium"
    }

    # Force audit policy subcategories
    $forceSubcat = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
    Add-Finding -Category "Logging & Auditing" -CISRef "2.3.2.1" `
        -CheckTitle "Force audit policy subcategory settings" `
        -Status $(if($forceSubcat -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $forceSubcat){"Not Configured"}else{$forceSubcat}) `
        -Description "CIS 2.3.2.1: Subcategories override legacy audit categories." -Severity "Medium"

    # Command line in process creation events
    $cmdLine = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled"
    Add-Finding -Category "Logging & Auditing" -CISRef "18.9.3.1" `
        -CheckTitle "Include command line in process creation events" `
        -Status $(if($cmdLine -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $cmdLine){"Not Configured"}else{$cmdLine}) `
        -Description "CIS 18.9.3.1: Command line logging is essential for incident response." -Severity "High"

    # PowerShell Script Block Logging
    $psLogging = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    Add-Finding -Category "Logging & Auditing" -CISRef "18.10.88.1" `
        -CheckTitle "PowerShell Script Block Logging enabled" `
        -Status $(if($psLogging -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $psLogging){"Not Configured"}else{$psLogging}) `
        -Description "CIS 18.10.88.1: Log all PowerShell script blocks for forensic analysis." -Severity "High"

    # PowerShell Transcription
    $psTranscript = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
    Add-Finding -Category "Logging & Auditing" -CISRef "18.10.88.2" `
        -CheckTitle "PowerShell Transcription enabled" `
        -Status $(if($psTranscript -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $psTranscript){"Not Configured"}else{$psTranscript}) `
        -Description "CIS 18.10.88.2: Full transcription of PS sessions." -Severity "Medium"
}

# ============================================================================
# CATEGORY 13: SYSTEM HARDENING
# ============================================================================
function Test-SystemHardening {
    Write-Host "`n[+] System Hardening Checks" -ForegroundColor Green

    # Interactive logon settings
    Write-Progress2 "Hardening" "Checking interactive logon settings"
    $dontDisplayLast = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
    Add-Finding -Category "System Hardening" -CISRef "2.3.7.2" `
        -CheckTitle "Don't display last signed-in user" `
        -Status $(if($dontDisplayLast -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $dontDisplayLast){"Not Configured"}else{$dontDisplayLast}) `
        -Description "CIS 2.3.7.2: Prevents username enumeration." -Severity "Medium"

    # Machine inactivity limit
    $inactivity = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
    Add-Finding -Category "System Hardening" -CISRef "2.3.7.3" `
        -CheckTitle "Machine inactivity limit <= 900 seconds" `
        -Status $(if($inactivity -ge 1 -and $inactivity -le 900){"Pass"}else{"Fail"}) `
        -Expected "1-900 seconds" -Actual $(if($null -eq $inactivity){"Not Configured"}else{"$inactivity seconds"}) `
        -Description "CIS 2.3.7.3: Screen lock after 15 minutes of inactivity." -Severity "Medium"

    # CTRL+ALT+DEL required
    $ctrlAltDel = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
    Add-Finding -Category "System Hardening" -CISRef "2.3.7.1" `
        -CheckTitle "CTRL+ALT+DEL required for logon" `
        -Status $(if($ctrlAltDel -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled = CAD required)" -Actual $(if($null -eq $ctrlAltDel){"Not Configured"}else{$ctrlAltDel}) `
        -Description "CIS 2.3.7.1: Prevents trojan logon screens." -Severity "Low"

    # Lock screen settings
    $lockCamera = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
    Add-Finding -Category "System Hardening" -CISRef "18.1.1.1" -CheckTitle "Lock screen camera disabled" `
        -Status $(if($lockCamera -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $lockCamera){"Not Configured"}else{$lockCamera}) `
        -Description "CIS 18.1.1.1: No camera on lock screen." -Severity "Low"

    $lockSlideshow = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
    Add-Finding -Category "System Hardening" -CISRef "18.1.1.2" -CheckTitle "Lock screen slideshow disabled" `
        -Status $(if($lockSlideshow -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $lockSlideshow){"Not Configured"}else{$lockSlideshow}) `
        -Description "CIS 18.1.1.2: No slideshow on lock screen." -Severity "Low"

    # Telemetry / Data Collection
    Write-Progress2 "Hardening" "Checking privacy and data collection settings"
    $telemetry = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
    Add-Finding -Category "System Hardening" -CISRef "18.10.16.1" `
        -CheckTitle "Telemetry = Off or Required only" `
        -Status $(if($telemetry -le 1){"Pass"}else{"Fail"}) `
        -Expected "0 (Off) or 1 (Required)" -Actual $(if($null -eq $telemetry){"Not Configured"}else{$telemetry}) `
        -Description "CIS 18.10.16.1: Minimize diagnostic data sent to Microsoft." -Severity "Medium"

    # OneDrive disabled
    $onedrive = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC"
    Add-Finding -Category "System Hardening" -CISRef "18.10.50.1" `
        -CheckTitle "OneDrive file storage disabled" `
        -Status $(if($onedrive -eq 1){"Pass"}else{"Warning"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $onedrive){"Not Configured"}else{$onedrive}) `
        -Description "CIS 18.10.50.1: Prevent data leakage via OneDrive." -Severity "Medium" -Profile "L2"

    # Windows Recall disabled
    $recall = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis"
    Add-Finding -Category "System Hardening" -CISRef "18.10.73.1" `
        -CheckTitle "Windows Recall disabled" `
        -Status $(if($recall -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Disabled)" -Actual $(if($null -eq $recall){"Not Configured"}else{$recall}) `
        -Description "CIS 18.10.73.1: Recall screenshots sensitive data." -Severity "High"

    # Cortana disabled
    $cortana = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"
    Add-Finding -Category "System Hardening" -CISRef "18.10.59.3" `
        -CheckTitle "Cortana disabled" `
        -Status $(if($cortana -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $cortana){"Not Configured"}else{$cortana}) `
        -Description "CIS 18.10.59.3: Cortana collects data and enables ambient listening." -Severity "Medium"

    # Speech recognition disabled
    $speech = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization"
    Add-Finding -Category "System Hardening" -CISRef "18.1.2.2" `
        -CheckTitle "Online speech recognition disabled" `
        -Status $(if($speech -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $speech){"Not Configured"}else{$speech}) `
        -Description "CIS 18.1.2.2: No online speech recognition services." -Severity "Low"

    # Widgets disabled
    $widgets = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests"
    Add-Finding -Category "System Hardening" -CISRef "18.10.72.1" `
        -CheckTitle "Widgets disabled" `
        -Status $(if($widgets -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $widgets){"Not Configured"}else{$widgets}) `
        -Description "CIS 18.10.72.1: Widgets increase attack surface." -Severity "Low"

    # AutoLogon disabled
    $autoLogon = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
    Add-Finding -Category "System Hardening" -CISRef "18.5.1" `
        -CheckTitle "Automatic Logon disabled" `
        -Status $(if($autoLogon -eq "0" -or $null -eq $autoLogon){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $autoLogon){"Not Configured"}else{$autoLogon}) `
        -Description "CIS 18.5.1: Automatic logon exposes credentials." -Severity "Critical"

    # UAC restrictions for local network logons
    $localAccountFilter = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy"
    Add-Finding -Category "System Hardening" -CISRef "18.4.1" `
        -CheckTitle "UAC restrictions on network logons for local accounts" `
        -Status $(if($localAccountFilter -eq 0 -or $null -eq $localAccountFilter){"Pass"}else{"Fail"}) `
        -Expected "0 (Enabled)" -Actual $(if($null -eq $localAccountFilter){"Not Configured (Default=Enabled)"}else{$localAccountFilter}) `
        -Description "CIS 18.4.1: Apply UAC to local accounts on network logons (mitigates pass-the-hash)." -Severity "Critical"

    # Password reveal button hidden
    $pwReveal = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"
    Add-Finding -Category "System Hardening" -CISRef "18.10.15.1" `
        -CheckTitle "Password reveal button disabled" `
        -Status $(if($pwReveal -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Enabled)" -Actual $(if($null -eq $pwReveal){"Not Configured"}else{$pwReveal}) `
        -Description "CIS 18.10.15.1: Prevent shoulder-surfing via password reveal." -Severity "Low"

    # Remote assistance
    Write-Progress2 "Hardening" "Checking miscellaneous hardening"

    # Game recording disabled
    $gameRec = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"
    Add-Finding -Category "System Hardening" -CISRef "18.10.79.1" `
        -CheckTitle "Game recording disabled" `
        -Status $(if($gameRec -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $gameRec){"Not Configured"}else{$gameRec}) `
        -Description "CIS 18.10.79.1: Game recording increases attack surface." -Severity "Low" -Profile "L2"

    # Windows Sandbox restrictions
    $sandboxNet = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox" "AllowNetworking"
    Add-Finding -Category "System Hardening" -CISRef "18.10.92.3" `
        -CheckTitle "Windows Sandbox networking disabled" `
        -Status $(if($sandboxNet -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $sandboxNet){"Not Configured"}else{$sandboxNet}) `
        -Description "CIS 18.10.92.3: Sandbox network access should be restricted." -Severity "Low" -Profile "L2"

    # Kerberos encryption types
    $kerbEncTypes = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"
    Add-Finding -Category "System Hardening" -CISRef "2.3.11.4" `
        -CheckTitle "Kerberos encryption = AES128+AES256+Future" `
        -Status $(if($kerbEncTypes -eq 2147483640){"Pass"}else{"Warning"}) `
        -Expected "2147483640 (AES128+AES256+Future)" `
        -Actual $(if($null -eq $kerbEncTypes){"Not Configured"}else{$kerbEncTypes}) `
        -Description "CIS 2.3.11.4: Only strong Kerberos encryption types allowed." -Severity "High"

    # Print Spooler client connections
    $spoolerClient = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint"
    Add-Finding -Category "System Hardening" -CISRef "18.7.1" `
        -CheckTitle "Print Spooler remote client connections disabled" `
        -Status $(if($spoolerClient -eq 2){"Pass"}else{"Fail"}) `
        -Expected "2 (Disabled)" -Actual $(if($null -eq $spoolerClient){"Not Configured"}else{$spoolerClient}) `
        -Description "CIS 18.7.1: Disable remote print spooler connections (PrintNightmare mitigation)." -Severity "High"

    # Clipboard sync disabled
    $clipSync = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard"
    Add-Finding -Category "System Hardening" -CISRef "18.9.33.1" `
        -CheckTitle "Clipboard sync across devices disabled" `
        -Status $(if($clipSync -eq 0){"Pass"}else{"Fail"}) `
        -Expected "0 (Disabled)" -Actual $(if($null -eq $clipSync){"Not Configured"}else{$clipSync}) `
        -Description "CIS 18.9.33.1: Prevent cross-device clipboard data leakage." -Severity "Medium"

    # Location services disabled
    $location = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation"
    Add-Finding -Category "System Hardening" -CISRef "18.10.36.1" `
        -CheckTitle "Location services disabled" `
        -Status $(if($location -eq 1){"Pass"}else{"Fail"}) `
        -Expected "1 (Disabled)" -Actual $(if($null -eq $location){"Not Configured"}else{$location}) `
        -Description "CIS 18.10.36.1: Disable location tracking on enterprise devices." -Severity "Low"
}

# ============================================================================
# HTML REPORT GENERATOR
# ============================================================================
function Generate-HTMLReport {
    Write-Host "`n[+] Generating HTML Report..." -ForegroundColor Green

    $endTime = Get-Date
    $duration = $endTime - $Script:StartTime

    $totalChecks = $Script:Results.Count
    $passCount = ($Script:Results | Where-Object Status -eq "Pass").Count
    $failCount = ($Script:Results | Where-Object Status -eq "Fail").Count
    $warnCount = ($Script:Results | Where-Object Status -eq "Warning").Count
    $infoCount = ($Script:Results | Where-Object Status -eq "Info").Count
    $errorCount = ($Script:Results | Where-Object Status -eq "Error").Count
    $manualCount = ($Script:Results | Where-Object Status -eq "Manual").Count

    $compliancePercent = if ($totalChecks -gt 0) { [math]::Round(($passCount / ($passCount + $failCount)) * 100, 1) } else { 0 }

    $categories = $Script:Results | Group-Object Category | Sort-Object Name

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $reportFile = Join-Path $OutputPath "CIS_Win11_BuildReview_${Script:ComputerName}_$timestamp.html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIS Windows 11 Build Review - $Script:ComputerName</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #1e293b 0%, #334155 100%); border-radius: 12px; padding: 30px; margin-bottom: 24px; border: 1px solid #475569; }
    .header h1 { font-size: 24px; color: #f8fafc; margin-bottom: 4px; }
    .header .subtitle { color: #94a3b8; font-size: 14px; }
    .header .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 20px; }
    .header .meta-item { background: #1e293b; padding: 12px 16px; border-radius: 8px; border: 1px solid #334155; }
    .header .meta-item .label { font-size: 11px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; }
    .header .meta-item .value { font-size: 16px; color: #f1f5f9; font-weight: 600; }
    .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: #1e293b; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #334155; }
    .stat-card .number { font-size: 32px; font-weight: 700; }
    .stat-card .label { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-card.pass .number { color: #4ade80; }
    .stat-card.fail .number { color: #f87171; }
    .stat-card.warn .number { color: #fbbf24; }
    .stat-card.info .number { color: #60a5fa; }
    .stat-card.total .number { color: #f1f5f9; }
    .stat-card.compliance .number { color: $(if($compliancePercent -ge 80){"#4ade80"}elseif($compliancePercent -ge 60){"#fbbf24"}else{"#f87171"}); }
    .compliance-bar { background: #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 24px; border: 1px solid #334155; }
    .compliance-bar h3 { margin-bottom: 10px; color: #f1f5f9; }
    .bar-container { background: #334155; border-radius: 8px; height: 24px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 8px; transition: width 0.5s; background: linear-gradient(90deg, $(if($compliancePercent -ge 80){"#22c55e, #4ade80"}elseif($compliancePercent -ge 60){"#eab308, #fbbf24"}else{"#ef4444, #f87171"})); }
    .category { background: #1e293b; border-radius: 10px; margin-bottom: 16px; border: 1px solid #334155; overflow: hidden; }
    .category-header { padding: 16px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: #1e293b; border-bottom: 1px solid #334155; }
    .category-header:hover { background: #253347; }
    .category-header h3 { font-size: 16px; color: #f1f5f9; }
    .category-stats { display: flex; gap: 12px; }
    .category-stats span { font-size: 12px; padding: 3px 10px; border-radius: 12px; font-weight: 600; }
    .cat-pass { background: #14532d; color: #4ade80; }
    .cat-fail { background: #7f1d1d; color: #f87171; }
    .cat-warn { background: #78350f; color: #fbbf24; }
    .category-body { display: none; }
    .category-body.open { display: block; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #0f172a; padding: 10px 12px; text-align: left; color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; }
    td { padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
    tr:hover td { background: #162032; }
    .status-badge { padding: 2px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; display: inline-block; min-width: 55px; text-align: center; }
    .status-Pass { background: #14532d; color: #4ade80; }
    .status-Fail { background: #7f1d1d; color: #f87171; }
    .status-Warning { background: #78350f; color: #fbbf24; }
    .status-Info { background: #1e3a5f; color: #60a5fa; }
    .status-Error { background: #581845; color: #e879f9; }
    .status-Manual { background: #3f3f46; color: #a1a1aa; }
    .severity-Critical { color: #f87171; font-weight: 700; }
    .severity-High { color: #fb923c; font-weight: 600; }
    .severity-Medium { color: #fbbf24; }
    .severity-Low { color: #94a3b8; }
    .severity-Informational { color: #64748b; }
    .description { color: #64748b; font-size: 11px; margin-top: 4px; }
    .footer { text-align: center; padding: 20px; color: #475569; font-size: 12px; }
    .exec-summary { background: #1e293b; border-radius: 10px; padding: 24px; margin-bottom: 24px; border: 1px solid #334155; }
    .exec-summary h3 { color: #f1f5f9; margin-bottom: 12px; }
    .exec-summary p { color: #94a3b8; margin-bottom: 8px; font-size: 14px; }
    .critical-findings { background: #1c1117; border: 1px solid #7f1d1d; border-radius: 10px; padding: 20px; margin-bottom: 24px; }
    .critical-findings h3 { color: #f87171; margin-bottom: 12px; }
    .critical-findings ul { list-style: none; }
    .critical-findings li { padding: 6px 0; color: #fca5a5; font-size: 13px; border-bottom: 1px solid #2d1318; }
    .critical-findings li:last-child { border-bottom: none; }
    .critical-findings li::before { content: "⚠ "; }
    .expand-all { background: #334155; border: none; color: #94a3b8; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 12px; margin-bottom: 12px; }
    .expand-all:hover { background: #475569; color: #f1f5f9; }
    @media print { body { background: white; color: black; } .category-body { display: block !important; } }
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0</h1>
    <div class="subtitle">Automated Build Review Report</div>
    <div class="meta">
        <div class="meta-item"><div class="label">Hostname</div><div class="value">$Script:ComputerName</div></div>
        <div class="meta-item"><div class="label">Operating System</div><div class="value">$Script:OSVersion (Build $Script:OSBuild)</div></div>
        <div class="meta-item"><div class="label">Scan Date</div><div class="value">$(Get-Date -Format 'dd MMM yyyy HH:mm:ss')</div></div>
        <div class="meta-item"><div class="label">Duration</div><div class="value">$([math]::Round($duration.TotalSeconds, 1)) seconds</div></div>
        <div class="meta-item"><div class="label">Run As</div><div class="value">$env:USERNAME</div></div>
        <div class="meta-item"><div class="label">Domain</div><div class="value">$env:USERDOMAIN</div></div>
    </div>
</div>

<div class="dashboard">
    <div class="stat-card total"><div class="number">$totalChecks</div><div class="label">Total Checks</div></div>
    <div class="stat-card pass"><div class="number">$passCount</div><div class="label">Passed</div></div>
    <div class="stat-card fail"><div class="number">$failCount</div><div class="label">Failed</div></div>
    <div class="stat-card warn"><div class="number">$warnCount</div><div class="label">Warnings</div></div>
    <div class="stat-card info"><div class="number">$($infoCount + $errorCount)</div><div class="label">Info / Errors</div></div>
    <div class="stat-card compliance"><div class="number">${compliancePercent}%</div><div class="label">Compliance</div></div>
</div>

<div class="compliance-bar">
    <h3>Overall CIS Compliance Score</h3>
    <div class="bar-container"><div class="bar-fill" style="width: ${compliancePercent}%"></div></div>
</div>

<div class="exec-summary">
    <h3>Executive Summary</h3>
    <p>This automated build review assessed <strong>$Script:ComputerName</strong> against the CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0. A total of <strong>$totalChecks</strong> security checks were performed across 13 assessment categories.</p>
    <p>The system achieved a compliance rate of <strong>${compliancePercent}%</strong> with <strong>$passCount</strong> checks passing, <strong>$failCount</strong> failing, and <strong>$warnCount</strong> warnings requiring attention.</p>
    <p>$(if($failCount -gt 0){"Immediate remediation is recommended for the $failCount failed checks, particularly those rated Critical or High severity."}else{"The system demonstrates strong compliance with the CIS benchmark."})</p>
</div>
"@

    # Critical findings section
    $criticalFails = $Script:Results | Where-Object { $_.Status -eq "Fail" -and $_.Severity -in @("Critical","High") } | Sort-Object Severity
    if ($criticalFails.Count -gt 0) {
        $html += @"
<div class="critical-findings">
    <h3>Critical & High Severity Failures ($($criticalFails.Count))</h3>
    <ul>
"@
        foreach ($cf in $criticalFails) {
            $html += "        <li><strong>[$($cf.Severity)]</strong> $($cf.CISRef) - $($cf.CheckTitle) (Current: $($cf.Actual))</li>`n"
        }
        $html += "    </ul>`n</div>`n"
    }

    # Category sections
    $html += '<button class="expand-all" onclick="document.querySelectorAll(''.category-body'').forEach(e=>e.classList.toggle(''open''))">Toggle All Sections</button>' + "`n"

    foreach ($cat in $categories) {
        $catPass = ($cat.Group | Where-Object Status -eq "Pass").Count
        $catFail = ($cat.Group | Where-Object Status -eq "Fail").Count
        $catWarn = ($cat.Group | Where-Object Status -eq "Warning").Count

        $html += @"
<div class="category">
    <div class="category-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <h3>$($cat.Name) ($($cat.Count) checks)</h3>
        <div class="category-stats">
            $(if($catPass){"<span class='cat-pass'>$catPass Pass</span>"})
            $(if($catFail){"<span class='cat-fail'>$catFail Fail</span>"})
            $(if($catWarn){"<span class='cat-warn'>$catWarn Warn</span>"})
        </div>
    </div>
    <div class="category-body">
        <table>
            <thead><tr><th>Status</th><th>Severity</th><th>CIS Ref</th><th>Check</th><th>Expected</th><th>Actual</th></tr></thead>
            <tbody>
"@
        foreach ($finding in $cat.Group | Sort-Object @{Expression={switch($_.Status){"Fail"{0}"Warning"{1}"Error"{2}"Manual"{3}"Info"{4}"Pass"{5}}};Ascending=$true}) {
            $html += @"
                <tr>
                    <td><span class="status-badge status-$($finding.Status)">$($finding.Status)</span></td>
                    <td><span class="severity-$($finding.Severity)">$($finding.Severity)</span></td>
                    <td>$($finding.CISRef)</td>
                    <td>$($finding.CheckTitle)$(if($finding.Description){"<div class='description'>$($finding.Description)</div>"})</td>
                    <td>$($finding.Expected)</td>
                    <td>$([System.Web.HttpUtility]::HtmlEncode($finding.Actual))</td>
                </tr>
"@
        }
        $html += "            </tbody>`n        </table>`n    </div>`n</div>`n"
    }

    $html += @"
<div class="footer">
    <p>CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 - Automated Build Review</p>
    <p>Generated $(Get-Date -Format 'dd MMMM yyyy HH:mm:ss') | Duration: $([math]::Round($duration.TotalSeconds, 1))s | Tool Version 1.0</p>
    <p>This report is for authorised use only. Findings should be validated and remediated according to organisational policy.</p>
</div>

</div>
</body>
</html>
"@

    # Write report
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $html | Out-File -FilePath $reportFile -Encoding UTF8 -Force
    return $reportFile
}

# ============================================================================
# CATEGORY 14: LOW-PRIVILEGE USER ASSESSMENT
# ============================================================================
function Test-LowPrivilegeUserAccess {
    Write-Host "`n[+] Low-Privilege User Assessment (What Can a Standard User Do?)" -ForegroundColor Green

    # ---------------------------------------------------------------
    # 14.1 USER ENUMERATION - What can a low-priv user discover?
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Assessing local user/group enumeration exposure"

    # Local Administrators group membership
    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminCount = $adminGroup.Count
        $adminNames = ($adminGroup | ForEach-Object { $_.Name }) -join ", "
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Local Administrators enumeration" `
            -Status "Info" -Expected "Minimal admin accounts" `
            -Actual "$adminCount members: $adminNames" `
            -Description "A low-priv user can enumerate local admin group members via 'net localgroup Administrators'." `
            -Severity "Informational"

        # Excessive admin accounts
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Excessive local admin accounts" `
            -Status $(if($adminCount -le 2){"Pass"}elseif($adminCount -le 4){"Warning"}else{"Fail"}) `
            -Expected "<= 2 admin accounts" -Actual "$adminCount admin accounts" `
            -Description "Each additional admin account increases lateral movement risk. Review necessity of all admin members." `
            -Severity $(if($adminCount -gt 4){"High"}else{"Medium"})
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Admin group enumeration" -Status "Error" -Actual "$_" -Severity "Medium"
    }

    # All local users and their status
    try {
        $allUsers = Get-LocalUser -ErrorAction Stop
        $enabledUsers = $allUsers | Where-Object { $_.Enabled -eq $true }
        $neverExpire = $enabledUsers | Where-Object { $_.PasswordExpires -eq $null }
        $noPasswordRequired = $enabledUsers | Where-Object { $_.PasswordRequired -eq $false }
        $passwordNeverExpires = $enabledUsers | Where-Object { $_.PasswordExpires -eq $null -and $_.Name -ne "DefaultAccount" }

        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Local user account inventory" `
            -Status "Info" `
            -Expected "Minimal enabled accounts with password expiry" `
            -Actual "Total=$($allUsers.Count), Enabled=$($enabledUsers.Count), Names=$(($enabledUsers | ForEach-Object { $_.Name }) -join ', ')" `
            -Description "All local accounts are visible to any authenticated user." -Severity "Informational"

        # Accounts with no password required
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Accounts with PasswordRequired=False" `
            -Status $(if($noPasswordRequired.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "0 accounts" `
            -Actual $(if($noPasswordRequired.Count -eq 0){"None found"}else{"$($noPasswordRequired.Count): $(($noPasswordRequired | ForEach-Object { $_.Name }) -join ', ')"}) `
            -Description "Accounts not requiring passwords can be accessed by any user with physical/network access." `
            -Severity "Critical"

        # Accounts with password that never expires
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Accounts with password never expires" `
            -Status $(if($passwordNeverExpires.Count -eq 0){"Pass"}else{"Warning"}) `
            -Expected "0 (except service accounts)" `
            -Actual $(if($passwordNeverExpires.Count -eq 0){"None found"}else{"$($passwordNeverExpires.Count): $(($passwordNeverExpires | ForEach-Object { $_.Name }) -join ', ')"}) `
            -Description "Non-expiring passwords increase window for credential abuse." -Severity "Medium"

        # Stale accounts (last logon > 90 days)
        $staleAccounts = $enabledUsers | Where-Object {
            $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) -and
            $_.Name -notin @("DefaultAccount","WDAGUtilityAccount")
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Stale enabled accounts (no logon > 90 days)" `
            -Status $(if($staleAccounts.Count -eq 0){"Pass"}else{"Warning"}) `
            -Expected "0 stale accounts" `
            -Actual $(if($staleAccounts.Count -eq 0){"None found"}else{"$($staleAccounts.Count): $(($staleAccounts | ForEach-Object { "$($_.Name) (last: $($_.LastLogon))" }) -join '; ')"}) `
            -Description "Stale accounts are prime targets for compromise — they are less likely to be monitored." `
            -Severity "Medium"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "User inventory" -Status "Error" -Actual "$_" -Severity "Medium"
    }

    # ---------------------------------------------------------------
    # 14.2 WRITABLE LOCATIONS - Where can a low-priv user write?
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Scanning for writable directories exploitable by standard users"

    # Startup Folders (persistence vector)
    $startupPaths = @(
        @{ Path="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Desc="All Users Startup Folder" },
        @{ Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Desc="Current User Startup Folder" }
    )
    foreach ($sp in $startupPaths) {
        if (Test-Path $sp.Path) {
            try {
                $acl = Get-Acl $sp.Path -ErrorAction Stop
                $usersCanWrite = $acl.Access | Where-Object {
                    $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)"
                }
                $existingItems = Get-ChildItem $sp.Path -ErrorAction SilentlyContinue
                Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
                    -CheckTitle "$($sp.Desc) writable by low-priv users" `
                    -Status $(if($usersCanWrite -and $sp.Desc -like "All*"){"Fail"}elseif($existingItems.Count -gt 0 -and $sp.Desc -like "All*"){"Warning"}else{"Pass"}) `
                    -Expected "Not writable by BUILTIN\Users (All Users path)" `
                    -Actual "Writable=$(if($usersCanWrite){'YES'}else{'No'}), Items=$($existingItems.Count)$(if($existingItems.Count -gt 0){': ' + (($existingItems | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ')})" `
                    -Description "Writable startup folders allow persistence — anything placed here runs at logon for all/current user." `
                    -Severity $(if($usersCanWrite -and $sp.Desc -like "All*"){"Critical"}else{"Medium"})
            } catch {
                Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
                    -CheckTitle "$($sp.Desc) check" -Status "Error" -Actual "$_" -Severity "Medium"
            }
        }
    }

    # Writable Program Files directories
    Write-Progress2 "LowPriv" "Checking Program Files for user-writable subdirectories"
    try {
        $writableProgramDirs = @()
        $progDirs = @("C:\Program Files", "C:\Program Files (x86)")
        foreach ($progDir in $progDirs) {
            if (Test-Path $progDir) {
                Get-ChildItem $progDir -Directory -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
                    $dirAcl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
                    if ($dirAcl) {
                        $weak = $dirAcl.Access | Where-Object {
                            $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                            $_.FileSystemRights -match "(Write|Modify|FullControl)" -and
                            $_.AccessControlType -eq "Allow"
                        }
                        if ($weak) { $writableProgramDirs += $_.FullName }
                    }
                }
            }
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "User-writable Program Files subdirectories" `
            -Status $(if($writableProgramDirs.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No writable directories in Program Files" `
            -Actual $(if($writableProgramDirs.Count -eq 0){"None found (sampled top 30 per root)"}else{"$($writableProgramDirs.Count) found: $(($writableProgramDirs | Select-Object -First 5) -join '; ')"}) `
            -Description "Writable Program Files directories allow DLL planting/binary replacement targeting installed software." `
            -Severity "Critical"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Program Files writable check" -Status "Error" -Actual "$_" -Severity "High"
    }

    # Writable C:\ root
    try {
        $rootAcl = Get-Acl "C:\" -ErrorAction Stop
        $rootWritable = $rootAcl.Access | Where-Object {
            $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
            $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles|CreateDirectories)" -and
            $_.AccessControlType -eq "Allow"
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "C:\ root writable by standard users" `
            -Status $(if($rootWritable){"Fail"}else{"Pass"}) `
            -Expected "Not writable by Users" `
            -Actual $(if($rootWritable){"YES - Users can create files/folders at C:\"}else{"Properly restricted"}) `
            -Description "Writable root allows planting DLLs in search paths and bypassing execution policies via trusted locations." `
            -Severity "High"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "C:\ root ACL check" -Status "Error" -Actual "$_" -Severity "High"
    }

    # ---------------------------------------------------------------
    # 14.3 CREDENTIAL HARVESTING OPPORTUNITIES
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking credential exposure vectors"

    # Saved Wi-Fi profiles (accessible to any local user on many configs)
    try {
        $wifiProfiles = netsh wlan show profiles 2>$null
        $profileCount = ($wifiProfiles | Select-String "All User Profile" | Measure-Object).Count
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Saved Wi-Fi profiles accessible" `
            -Status $(if($profileCount -eq 0){"Pass"}else{"Warning"}) `
            -Expected "0 or keys not exportable by non-admin" `
            -Actual "$profileCount Wi-Fi profiles saved" `
            -Description "A low-priv user can list profiles; admin can export keys. Verify 'key=clear' export is restricted." `
            -Severity "Medium"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Wi-Fi profile enumeration" -Status "Info" -Actual "WLAN service not available" -Severity "Informational"
    }

    # Credential Manager entries
    try {
        $credManGeneric = cmdkey /list 2>$null
        $credCount = ($credManGeneric | Select-String "Target:" | Measure-Object).Count
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Windows Credential Manager stored credentials" `
            -Status $(if($credCount -eq 0){"Pass"}else{"Warning"}) `
            -Expected "Minimal stored credentials" `
            -Actual "$credCount credential(s) stored for current user" `
            -Description "Stored credentials in Credential Manager can be extracted by tools like Mimikatz from user context." `
            -Severity $(if($credCount -gt 3){"High"}else{"Medium"})
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Credential Manager check" -Status "Error" -Actual "$_" -Severity "Medium"
    }

    # Unattend.xml / Sysprep files with potential cleartext passwords
    Write-Progress2 "LowPriv" "Scanning for sensitive files with potential credentials"
    $sensitiveFiles = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Autounattend.xml",
        "C:\Windows\Panther\autounattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml",
        "C:\Windows\system32\sysprep\Unattend.xml",
        "C:\unattend.xml",
        "C:\Windows\Panther\setupinfo",
        "C:\Windows\inf\setupapi.dev.log"
    )
    $foundSensitive = @()
    foreach ($sf in $sensitiveFiles) {
        if (Test-Path $sf -ErrorAction SilentlyContinue) {
            # Check if readable by current user
            try {
                $null = Get-Content $sf -TotalCount 1 -ErrorAction Stop
                $foundSensitive += $sf
            } catch {
                # Not readable, that's fine
            }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "Readable Unattend/Sysprep files (may contain passwords)" `
        -Status $(if($foundSensitive.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "No accessible unattend/sysprep files" `
        -Actual $(if($foundSensitive.Count -eq 0){"None found"}else{"$($foundSensitive.Count) found: $($foundSensitive -join '; ')"}) `
        -Description "Unattend.xml files often contain base64-encoded local admin passwords from deployment." `
        -Severity "Critical"

    # Search for files containing passwords in common locations
    $passwordFiles = @()
    $searchDirs = @("$env:USERPROFILE", "C:\Users\Public", "C:\ProgramData")
    foreach ($dir in $searchDirs) {
        if (Test-Path $dir) {
            try {
                $suspects = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue -Depth 3 |
                    Where-Object { $_.Name -match "(password|cred|secret|\.rdp|\.vnc|\.config|web\.config|\.ini|\.xml|\.txt)$" -and $_.Length -lt 1MB } |
                    Select-Object -First 20
                foreach ($s in $suspects) {
                    try {
                        $content = Get-Content $s.FullName -TotalCount 50 -ErrorAction Stop
                        if ($content -match "(password|passwd|pwd|credential|secret|connectionstring)\s*[:=]") {
                            $passwordFiles += $s.FullName
                        }
                    } catch { }
                }
            } catch { }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "Files containing potential cleartext passwords" `
        -Status $(if($passwordFiles.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "No accessible files with embedded credentials" `
        -Actual $(if($passwordFiles.Count -eq 0){"None found in sampled locations"}else{"$($passwordFiles.Count) found: $(($passwordFiles | Select-Object -First 5) -join '; ')"}) `
        -Description "Files with embedded credentials allow privilege escalation if they belong to higher-privileged services/users." `
        -Severity "High"

    # SAM/SYSTEM backup files accessible
    $samBackups = @(
        "C:\Windows\repair\SAM",
        "C:\Windows\repair\SYSTEM",
        "C:\Windows\System32\config\RegBack\SAM",
        "C:\Windows\System32\config\RegBack\SYSTEM"
    )
    $accessibleSAM = @()
    foreach ($sb in $samBackups) {
        if (Test-Path $sb -ErrorAction SilentlyContinue) {
            try {
                $null = [System.IO.File]::OpenRead($sb)
                $accessibleSAM += $sb
            } catch { }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "SAM/SYSTEM backup files accessible" `
        -Status $(if($accessibleSAM.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "Not readable by standard users" `
        -Actual $(if($accessibleSAM.Count -eq 0){"None accessible"}else{"$($accessibleSAM.Count) accessible: $($accessibleSAM -join '; ')"}) `
        -Description "SAM/SYSTEM backups allow offline hash extraction with tools like secretsdump/samdump2." `
        -Severity "Critical"

    # Volume Shadow Copies (potential SAM extraction)
    try {
        $shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Volume Shadow Copies present" `
            -Status $(if($shadows.Count -eq 0){"Pass"}else{"Warning"}) `
            -Expected "Awareness check" `
            -Actual "$($shadows.Count) shadow copies found" `
            -Description "Shadow copies can be mounted to extract SAM/SYSTEM/NTDS.dit by an admin. Low-priv users can enumerate them." `
            -Severity "Medium"
    } catch { }

    # ---------------------------------------------------------------
    # 14.4 REGISTRY PERSISTENCE & AUTORUN VECTORS
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking user-writable autorun/persistence registry keys"

    # HKCU Run keys (any user can add persistence here)
    $userAutorunPaths = @(
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Desc="HKCU Run" },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Desc="HKCU RunOnce" },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"; Desc="HKCU RunServices" },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Desc="HKCU Winlogon" },
        @{ Path="HKCU:\Environment"; Desc="HKCU Environment (UserInitMprLogonScript)" }
    )
    $autoruns = @()
    foreach ($ar in $userAutorunPaths) {
        if (Test-Path $ar.Path) {
            try {
                $props = Get-ItemProperty $ar.Path -ErrorAction SilentlyContinue
                $entries = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                foreach ($e in $entries) {
                    if ($e.Value -and $e.Value -match "\.(exe|bat|cmd|ps1|vbs|js|wsf|dll|com|scr)") {
                        $autoruns += "$($ar.Desc)\$($e.Name) = $($e.Value)"
                    }
                }
            } catch { }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "User autorun registry entries (HKCU)" `
        -Status $(if($autoruns.Count -eq 0){"Pass"}else{"Warning"}) `
        -Expected "Minimal/verified entries only" `
        -Actual $(if($autoruns.Count -eq 0){"No executable autoruns found in HKCU"}else{"$($autoruns.Count) found: $(($autoruns | Select-Object -First 5) -join '; ')"}) `
        -Description "Any user can write to HKCU Run keys for persistence. These execute at every logon for that user." `
        -Severity "Medium"

    # HKLM Run keys writable by users (would be a serious misconfiguration)
    $systemAutorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    $writableHKLMRun = @()
    foreach ($sa in $systemAutorunPaths) {
        if (Test-Path $sa) {
            try {
                $regAcl = Get-Acl $sa -ErrorAction Stop
                $weak = $regAcl.Access | Where-Object {
                    $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $_.RegistryRights -match "(WriteKey|SetValue|FullControl)" -and
                    $_.AccessControlType -eq "Allow"
                }
                if ($weak) { $writableHKLMRun += $sa }
            } catch { }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "HKLM autorun keys writable by standard users" `
        -Status $(if($writableHKLMRun.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "Not writable by Users/Everyone" `
        -Actual $(if($writableHKLMRun.Count -eq 0){"Properly restricted"}else{"$($writableHKLMRun.Count) writable: $($writableHKLMRun -join '; ')"}) `
        -Description "If HKLM Run keys are user-writable, any user can achieve SYSTEM-context persistence." `
        -Severity "Critical"

    # ---------------------------------------------------------------
    # 14.5 TOKEN AND PRIVILEGE ASSESSMENT
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking current user token privileges"

    try {
        $whoamiPrivs = whoami /priv 2>$null
        $enabledPrivs = ($whoamiPrivs | Select-String "Enabled" | Where-Object { $_ -notmatch "Disabled" }).Count
        $dangerousPrivs = @("SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege","SeDebugPrivilege",
                           "SeBackupPrivilege","SeRestorePrivilege","SeTakeOwnershipPrivilege",
                           "SeLoadDriverPrivilege","SeTcbPrivilege","SeCreateTokenPrivilege")
        $foundDangerous = @()
        foreach ($dp in $dangerousPrivs) {
            if ($whoamiPrivs -match $dp) {
                $foundDangerous += $dp
            }
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Current user dangerous token privileges" `
            -Status $(if($foundDangerous.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No dangerous privileges for standard users" `
            -Actual $(if($foundDangerous.Count -eq 0){"None found (good)"}else{"$($foundDangerous.Count) dangerous: $($foundDangerous -join ', ')"}) `
            -Description "Privileges like SeImpersonate allow potato-family attacks to SYSTEM. SeDebug allows process injection." `
            -Severity "Critical"

        # User group memberships
        $whoamiGroups = whoami /groups /fo csv 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
        $interestingGroups = $whoamiGroups | Where-Object {
            $_.'Group Name' -match "(Admin|Remote Desktop|Remote Management|Backup Operators|Power Users|Hyper-V|Network Configuration)" -and
            $_.'Group Name' -notmatch "Mandatory Label"
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Current user interesting group memberships" `
            -Status $(if($interestingGroups.Count -eq 0){"Pass"}else{"Warning"}) `
            -Expected "Only standard user groups" `
            -Actual $(if($interestingGroups.Count -eq 0){"Standard user groups only"}else{"$($interestingGroups.Count) notable: $(($interestingGroups | ForEach-Object { $_.'Group Name' }) -join ', ')"}) `
            -Description "Membership in privileged groups (Backup Operators, Hyper-V Admins, etc.) grants escalation paths." `
            -Severity "High"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Token privilege assessment" -Status "Error" -Actual "$_" -Severity "High"
    }

    # ---------------------------------------------------------------
    # 14.6 INSTALLED SOFTWARE EXPLOITATION VECTORS
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking installed software for escalation vectors"

    # Applications installed per-user (not in Program Files)
    try {
        $userInstalledApps = Get-CimInstance Win32_Product -ErrorAction SilentlyContinue |
            Where-Object { $_.InstallLocation -and $_.InstallLocation -notmatch "Program Files" } |
            Select-Object -First 10
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Applications installed outside Program Files" `
            -Status $(if($userInstalledApps.Count -eq 0){"Pass"}else{"Warning"}) `
            -Expected "All apps in protected Program Files" `
            -Actual $(if($userInstalledApps.Count -eq 0){"None found"}else{"$($userInstalledApps.Count) found in non-standard locations"}) `
            -Description "Software outside Program Files is often user-writable, allowing binary replacement attacks." `
            -Severity "Medium"
    } catch { }

    # PowerShell Execution Policy
    try {
        $execPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        $execPolicyUser = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "PowerShell Execution Policy" `
            -Status $(if($execPolicy -eq "Restricted" -or $execPolicy -eq "AllSigned"){"Pass"}else{"Warning"}) `
            -Expected "Restricted or AllSigned (Machine scope)" `
            -Actual "Machine=$execPolicy, CurrentUser=$execPolicyUser" `
            -Description "Unrestricted/Bypass execution policy allows any user to run arbitrary PowerShell scripts. Note: this is a defense-in-depth control, not a security boundary." `
            -Severity "Medium"
    } catch { }

    # PowerShell Constrained Language Mode
    try {
        $langMode = $ExecutionContext.SessionState.LanguageMode
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "PowerShell Language Mode" `
            -Status $(if($langMode -eq "ConstrainedLanguage"){"Pass"}else{"Warning"}) `
            -Expected "ConstrainedLanguage (for non-admin)" `
            -Actual $langMode.ToString() `
            -Description "FullLanguage mode gives low-priv users access to .NET, COM, and WMI via PowerShell — enables sophisticated attacks." `
            -Severity "Medium"
    } catch { }

    # AppLocker / WDAC status
    Write-Progress2 "LowPriv" "Checking application control policies"
    try {
        $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $applockerRules = $applockerPolicy.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "AppLocker policy configured" `
            -Status $(if($applockerRules.Sum -gt 0){"Pass"}else{"Fail"}) `
            -Expected "AppLocker or WDAC rules configured" `
            -Actual $(if($applockerRules.Sum -gt 0){"$($applockerRules.Sum) rules across collections"}else{"No rules configured"}) `
            -Description "Without AppLocker/WDAC, a low-priv user can execute any binary/script from any writable location." `
            -Severity "High"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "AppLocker policy configured" `
            -Status "Fail" -Expected "AppLocker rules in effect" `
            -Actual "AppLocker not configured or service not running" `
            -Description "No application whitelisting = any user can run arbitrary executables." -Severity "High"
    }

    # WDAC / Device Guard Code Integrity Policy
    try {
        $cipolicy = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $codeIntegrity = $cipolicy.CodeIntegrityPolicyEnforcementStatus
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "WDAC Code Integrity Policy enforcement" `
            -Status $(if($codeIntegrity -eq 2){"Pass"}elseif($codeIntegrity -eq 1){"Warning"}else{"Fail"}) `
            -Expected "2 (Enforced)" `
            -Actual $(switch($codeIntegrity){ 0 {"Off"} 1 {"Audit"} 2 {"Enforced"} default {"Unknown ($codeIntegrity)"} }) `
            -Description "WDAC prevents execution of unsigned/untrusted code. Without it, any executable can run." `
            -Severity "High"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "WDAC status" -Status "Warning" -Actual "Unable to query DeviceGuard WMI" -Severity "Medium"
    }

    # ---------------------------------------------------------------
    # 14.7 NETWORK EXPOSURE FROM LOW-PRIV CONTEXT
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking network exposure accessible to standard users"

    # Open network shares
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -notin @("ADMIN$","C$","IPC$","print$") -and $_.ShareType -eq "FileSystemDirectory"
        }
        $openShares = @()
        foreach ($share in $shares) {
            $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            $everyoneAccess = $shareAccess | Where-Object { $_.AccountName -match "(Everyone|BUILTIN\\Users)" }
            if ($everyoneAccess) { $openShares += "$($share.Name) ($($share.Path))" }
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "2.3.10.11" `
            -CheckTitle "Network shares accessible to Everyone/Users" `
            -Status $(if($openShares.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No shares accessible by Everyone" `
            -Actual $(if($openShares.Count -eq 0){"None found"}else{"$($openShares.Count): $($openShares -join '; ')"}) `
            -Description "CIS 2.3.10.11: Open shares allow data exfiltration and lateral movement for any authenticated user." `
            -Severity "High"
    } catch { }

    # Admin shares accessible
    $adminShares = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks"
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "Administrative shares (C$, ADMIN$) status" `
        -Status "Info" `
        -Actual $(if($adminShares -eq 0){"Admin shares disabled"}else{"Admin shares enabled (default)"}) `
        -Description "Admin shares accessible to local admins for remote administration. Low-priv users cannot access these unless misconfigured." `
        -Severity "Informational"

    # Listening services / open ports
    try {
        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" } |
            Sort-Object LocalPort -Unique
        $listeningPorts = ($listening | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            "$($_.LocalPort)/$($proc.ProcessName)"
        }) -join ", "
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Network services listening on non-loopback" `
            -Status "Info" `
            -Expected "Minimal externally-accessible services" `
            -Actual $(if($listening.Count -eq 0){"No external listeners"}else{"$($listening.Count) ports: $listeningPorts"}) `
            -Description "Low-priv users can enumerate all listening services. Each exposed service is a potential attack surface." `
            -Severity "Informational"
    } catch { }

    # ---------------------------------------------------------------
    # 14.8 SCHEDULED TASK ABUSE VECTORS
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking scheduled task exploitation vectors"

    try {
        # Tasks with writable binaries running as SYSTEM
        $systemTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|LocalSystem|LOCAL SERVICE|NETWORK SERVICE" -and
            $_.State -ne "Disabled"
        }
        $writableTaskBins = @()
        foreach ($task in $systemTasks | Select-Object -First 40) {
            foreach ($action in $task.Actions) {
                if ($action.Execute) {
                    $taskExe = $action.Execute -replace '"', ''
                    if ($taskExe -and (Test-Path $taskExe -ErrorAction SilentlyContinue)) {
                        $taskAcl = Get-Acl $taskExe -ErrorAction SilentlyContinue
                        if ($taskAcl) {
                            $weak = $taskAcl.Access | Where-Object {
                                $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                                $_.FileSystemRights -match "(Write|Modify|FullControl)"
                            }
                            if ($weak) { $writableTaskBins += "$($task.TaskName): $taskExe" }
                        }
                    }
                    # Also check if the directory containing the binary is writable
                    $taskDir = Split-Path $taskExe -Parent -ErrorAction SilentlyContinue
                    if ($taskDir -and (Test-Path $taskDir -ErrorAction SilentlyContinue)) {
                        $dirAcl = Get-Acl $taskDir -ErrorAction SilentlyContinue
                        if ($dirAcl) {
                            $weakDir = $dirAcl.Access | Where-Object {
                                $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                                $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)"
                            }
                            if ($weakDir) { $writableTaskBins += "$($task.TaskName): DIR $taskDir (writable)" }
                        }
                    }
                }
            }
        }
        $writableTaskBins = $writableTaskBins | Select-Object -Unique
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "SYSTEM scheduled tasks with writable binaries/dirs" `
            -Status $(if($writableTaskBins.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No user-writable SYSTEM task binaries" `
            -Actual $(if($writableTaskBins.Count -eq 0){"None found (sampled 40 tasks)"}else{"$($writableTaskBins.Count) found: $(($writableTaskBins | Select-Object -First 5) -join '; ')"}) `
            -Description "SYSTEM tasks with user-writable binaries/directories = trivial privilege escalation to SYSTEM." `
            -Severity "Critical"

        # Tasks modifiable by standard users
        $userModifiableTasks = @()
        foreach ($task in $systemTasks | Select-Object -First 20) {
            try {
                $taskPath = $task.TaskPath + $task.TaskName
                $sddl = (schtasks /query /tn $taskPath /xml 2>$null | Select-String "SecurityDescriptor") -replace '.*<SecurityDescriptor>(.*)</SecurityDescriptor>.*', '$1'
                if ($sddl -match "AU.*WD|BU.*WD|WD.*AU|WD.*BU") {
                    $userModifiableTasks += $task.TaskName
                }
            } catch { }
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "SYSTEM scheduled tasks modifiable by users" `
            -Status $(if($userModifiableTasks.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No user-modifiable SYSTEM tasks" `
            -Actual $(if($userModifiableTasks.Count -eq 0){"None found (sampled)"}else{"$($userModifiableTasks.Count): $($userModifiableTasks -join ', ')"}) `
            -Description "If a user can modify a SYSTEM task's actions, they can execute arbitrary code as SYSTEM." `
            -Severity "Critical"
    } catch {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Scheduled task audit" -Status "Error" -Actual "$_" -Severity "High"
    }

    # ---------------------------------------------------------------
    # 14.9 DLL HIJACKING VECTORS
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking DLL hijacking vectors"

    # User-writable directories in system PATH
    try {
        $systemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine") -split ";"
        $userWritablePath = @()
        foreach ($dir in $systemPath) {
            if ($dir -and (Test-Path $dir -ErrorAction SilentlyContinue)) {
                $dirAcl = Get-Acl $dir -ErrorAction SilentlyContinue
                if ($dirAcl) {
                    $weak = $dirAcl.Access | Where-Object {
                        $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and
                        $_.AccessControlType -eq "Allow"
                    }
                    if ($weak) { $userWritablePath += $dir }
                }
            }
        }
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "User-writable directories in system PATH" `
            -Status $(if($userWritablePath.Count -eq 0){"Pass"}else{"Fail"}) `
            -Expected "No user-writable PATH directories" `
            -Actual $(if($userWritablePath.Count -eq 0){"None found"}else{"$($userWritablePath.Count): $($userWritablePath -join '; ')"}) `
            -Description "DLL search order hijacking: if a user can write to a PATH directory, they can plant DLLs loaded by privileged processes." `
            -Severity "Critical"
    } catch { }

    # KnownDLLs bypass check - missing KnownDLLs that could be hijacked
    try {
        $knownDlls = Get-ItemProperty "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -ErrorAction SilentlyContinue
        $knownDllCount = ($knownDlls.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "KnownDLLs protection count" `
            -Status "Info" `
            -Actual "$knownDllCount DLLs in KnownDLLs registry (protected from hijacking)" `
            -Description "KnownDLLs are loaded from System32 only. DLLs NOT in this list may be vulnerable to search-order hijacking." `
            -Severity "Informational"
    } catch { }

    # ---------------------------------------------------------------
    # 14.10 NAMED PIPE & COM OBJECT VECTORS
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking named pipe and COM object exposure"

    try {
        $namedPipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Select-Object -First 30
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Named pipes visible to current user" `
            -Status "Info" `
            -Actual "$($namedPipes.Count)+ named pipes accessible (e.g., $(($namedPipes | Select-Object -First 5 | ForEach-Object { Split-Path $_ -Leaf }) -join ', '))" `
            -Description "Named pipes can be abused for impersonation attacks (e.g., PrintSpoofer, PetitPotam triggers)." `
            -Severity "Informational"
    } catch { }

    # Spooler named pipe (PrintSpoofer/SpoolFool vector)
    try {
        $spoolerPipe = Test-Path "\\.\pipe\spoolss" -ErrorAction SilentlyContinue
        $spoolerSvc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Print Spooler pipe available (PrintSpoofer vector)" `
            -Status $(if($spoolerSvc.Status -eq "Running"){"Fail"}else{"Pass"}) `
            -Expected "Spooler stopped (pipe not available)" `
            -Actual "Spooler Status=$($spoolerSvc.Status), Pipe=$(if($spoolerPipe){'Available'}else{'Not found'})" `
            -Description "Running Print Spooler + SeImpersonatePrivilege = instant SYSTEM via PrintSpoofer/SpoolFool." `
            -Severity "High"
    } catch { }

    # ---------------------------------------------------------------
    # 14.11 DPAPI & BROWSER CREDENTIAL EXPOSURE
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Checking browser and DPAPI credential exposure"

    # Browser credential databases accessible
    $browserDBs = @(
        @{ Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"; Browser="Chrome" },
        @{ Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"; Browser="Edge" },
        @{ Path="$env:APPDATA\Mozilla\Firefox\Profiles"; Browser="Firefox" }
    )
    $accessibleBrowserDBs = @()
    foreach ($db in $browserDBs) {
        if ($db.Browser -eq "Firefox") {
            if (Test-Path $db.Path -ErrorAction SilentlyContinue) {
                $ffProfiles = Get-ChildItem $db.Path -Directory -ErrorAction SilentlyContinue
                foreach ($ffp in $ffProfiles) {
                    if (Test-Path "$($ffp.FullName)\logins.json" -ErrorAction SilentlyContinue) {
                        $accessibleBrowserDBs += "Firefox ($($ffp.Name))"
                    }
                }
            }
        } else {
            if (Test-Path $db.Path -ErrorAction SilentlyContinue) {
                $accessibleBrowserDBs += "$($db.Browser) Login Data"
            }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "Browser credential databases accessible" `
        -Status $(if($accessibleBrowserDBs.Count -eq 0){"Pass"}else{"Warning"}) `
        -Expected "Awareness check - user-context databases" `
        -Actual $(if($accessibleBrowserDBs.Count -eq 0){"No browser credential databases found"}else{"$($accessibleBrowserDBs.Count) found: $($accessibleBrowserDBs -join ', ')"}) `
        -Description "Browser credential databases can be copied and decrypted offline. This is inherent to user-context operation but tools like SharpChromium automate extraction." `
        -Severity "Medium"

    # ---------------------------------------------------------------
    # 14.12 MISCELLANEOUS LOW-PRIV CHECKS
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Running miscellaneous low-privilege checks"

    # WSL installed (bypass vector)
    try {
        $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
        $wslInstalled = $null -ne $wsl
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Windows Subsystem for Linux (WSL) installed" `
            -Status $(if($wslInstalled){"Warning"}else{"Pass"}) `
            -Expected "Not installed (on hardened systems)" `
            -Actual $(if($wslInstalled){"WSL is installed"}else{"Not installed"}) `
            -Description "WSL allows users to run Linux binaries, bypassing many Windows security controls including AppLocker/AV." `
            -Severity "Medium"
    } catch { }

    # Hyper-V enabled (VM escape risk if user has access)
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
            -CheckTitle "Hyper-V feature status" `
            -Status "Info" `
            -Actual "Hyper-V: $(if($hyperv.State -eq 'Enabled'){'Enabled'}else{'Not Enabled'})" `
            -Description "Hyper-V Admins group members can escalate to SYSTEM. Verify group membership." `
            -Severity "Informational"
    } catch { }

    # Clipboard history enabled (data exposure)
    $clipHistory = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory"
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "Clipboard history" `
        -Status $(if($clipHistory -eq 0){"Pass"}else{"Warning"}) `
        -Expected "0 (Disabled)" `
        -Actual $(if($null -eq $clipHistory){"Not Configured (Enabled by default)"}else{$clipHistory}) `
        -Description "Clipboard history retains copied data including passwords. Any process in user context can read it." `
        -Severity "Low"

    # RDP shadowing possibility
    $rdpShadow = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "Shadow"
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "RDP session shadowing policy" `
        -Status $(if($rdpShadow -eq 0){"Pass"}else{"Info"}) `
        -Expected "0 (Disabled) or Requires consent" `
        -Actual $(switch($rdpShadow){ 0 {"Disabled"} 1 {"Full control, no consent"} 2 {"Full control, with consent"} 3 {"View only, no consent"} 4 {"View only, with consent"} default {"Not Configured"} }) `
        -Description "RDP shadow without consent allows an admin to view or control a user's session without notification." `
        -Severity $(if($rdpShadow -eq 1){"High"}else{"Low"})

    # Always Install Elevated (repeat for emphasis in this context)
    $aieHKCU = Get-RegValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieHKLM = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    if ($aieHKCU -eq 1 -and $aieHKLM -eq 1) {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "18.10.82.2" `
            -CheckTitle "AlwaysInstallElevated = EXPLOITABLE" `
            -Status "Fail" `
            -Expected "Not set to 1 in both hives" -Actual "HKLM=1, HKCU=1 — INSTANT SYSTEM VIA MSI" `
            -Description "msfvenom -p windows/x64/shell_reverse_tcp ... -f msi > evil.msi && msiexec /i evil.msi = SYSTEM shell." `
            -Severity "Critical"
    }

    # Cached GPP Passwords (legacy but still found)
    Write-Progress2 "LowPriv" "Checking for cached Group Policy Preference passwords"
    $gppPaths = @(
        "$env:ALLUSERSPROFILE\Microsoft\Group Policy\History",
        "C:\Windows\SYSVOL"
    )
    $gppFiles = @()
    foreach ($gp in $gppPaths) {
        if (Test-Path $gp -ErrorAction SilentlyContinue) {
            try {
                $xmlFiles = Get-ChildItem -Path $gp -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue -Depth 5
                foreach ($xml in $xmlFiles) {
                    try {
                        $content = Get-Content $xml.FullName -Raw -ErrorAction Stop
                        if ($content -match "cpassword") {
                            $gppFiles += $xml.FullName
                        }
                    } catch { }
                }
            } catch { }
        }
    }
    Add-Finding -Category "Low-Priv User Assessment" -CISRef "Custom" `
        -CheckTitle "Cached GPP files with cpassword" `
        -Status $(if($gppFiles.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "No GPP files with cpassword" `
        -Actual $(if($gppFiles.Count -eq 0){"None found"}else{"$($gppFiles.Count) found: $($gppFiles -join '; ')"}) `
        -Description "GPP cpassword is trivially decryptable (MS14-025). Grants immediate access to the embedded account." `
        -Severity "Critical"

    # ---------------------------------------------------------------
    # 14.13 SUMMARY: ATTACK PATHS AVAILABLE TO LOW-PRIV USER
    # ---------------------------------------------------------------
    Write-Progress2 "LowPriv" "Compiling attack path summary"

    # Generate a summary of all identified attack paths
    $attackPaths = @()
    $lowPrivFindings = $Script:Results | Where-Object { $_.Category -eq "Low-Priv User Assessment" -and $_.Status -eq "Fail" }
    foreach ($f in $lowPrivFindings) {
        $attackPaths += "[$($f.Severity)] $($f.CheckTitle)"
    }

    if ($attackPaths.Count -gt 0) {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Summary" `
            -CheckTitle "ATTACK PATH SUMMARY: $($attackPaths.Count) escalation/abuse vectors identified" `
            -Status "Fail" `
            -Expected "0 exploitable attack paths" `
            -Actual ($attackPaths -join " | ") `
            -Description "Each failed check represents a verified attack path a low-privileged user could exploit for escalation, persistence, or data access." `
            -Severity "Critical"
    } else {
        Add-Finding -Category "Low-Priv User Assessment" -CISRef "Summary" `
            -CheckTitle "ATTACK PATH SUMMARY" `
            -Status "Pass" `
            -Expected "Minimal attack surface" -Actual "No critical low-priv escalation vectors identified" `
            -Description "The system appears well-hardened against low-privilege user abuse. Warnings should still be reviewed." `
            -Severity "Informational"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
function Invoke-BuildReview {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  CIS Windows 11 Enterprise Benchmark v5.0.0 Build Review" -ForegroundColor Cyan
    Write-Host "  Target: $Script:ComputerName | OS: $Script:OSVersion" -ForegroundColor Gray
    Write-Host "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor White

    $testFunctions = @{
        "BIOSConfig"         = { Test-BIOSConfiguration }
        "FullDiskEncryption"  = { Test-FullDiskEncryption }
        "Patching"           = { Test-Patching }
        "LocalServices"      = { Test-LocalServices }
        "FileSystem"         = { Test-FileSystem }
        "SecurityProducts"   = { Test-SecurityProducts }
        "RemovableMedia"     = { Test-RemovableMedia }
        "UserAccounts"       = { Test-UserAccountConfig }
        "PrivilegeEscalation" = { Test-PrivilegeEscalation }
        "LateralMovement"    = { Test-LateralMovement }
        "NetworkConfig"      = { Test-NetworkConfig }
        "LoggingAuditing"    = { Test-LoggingAndAuditing }
        "SystemHardening"    = { Test-SystemHardening }
        "LowPrivilegeUser"   = { Test-LowPrivilegeUserAccess }
    }

    foreach ($key in $testFunctions.Keys) {
        if ($SkipCategories -notcontains $key) {
            try {
                & $testFunctions[$key]
            } catch {
                Write-Host "  [!] Error in $key: $_" -ForegroundColor Red
                Add-Finding -Category $key -CISRef "N/A" -CheckTitle "Category execution error" `
                    -Status "Error" -Actual $_.ToString() -Severity "High"
            }
        } else {
            Write-Host "`n[-] Skipping: $key" -ForegroundColor Yellow
        }
    }

    $reportPath = Generate-HTMLReport
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host "  SCAN COMPLETE" -ForegroundColor Green
    Write-Host "  Total Checks: $($Script:Results.Count)" -ForegroundColor White
    Write-Host "  Pass: $(($Script:Results | Where-Object Status -eq 'Pass').Count) | Fail: $(($Script:Results | Where-Object Status -eq 'Fail').Count) | Warn: $(($Script:Results | Where-Object Status -eq 'Warning').Count)" -ForegroundColor White
    Write-Host "  Report: $reportPath" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White

    # Also export CSV for further analysis
    $csvPath = $reportPath -replace '\.html$', '.csv'
    $Script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV:    $csvPath" -ForegroundColor Cyan

    return $reportPath
}

# Run the build review
Invoke-BuildReview
