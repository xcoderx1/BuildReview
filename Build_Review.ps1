<#
.SYNOPSIS
    Comprehensive Windows Build Review - All Task Areas + CIS Benchmarks
.DESCRIPTION
    Covers all 13 assessment areas: BIOS, FDE, Patching, Services, File System,
    Security Config, Removable Media, Accounts, Priv Esc, Lateral Movement,
    Network Config, Logging/Auditing, System Hardening. Plus CIS L1/L2.
    REQUIRES ADMINISTRATOR. POC runs automatically.
    Single self-contained HTML report with all evidence embedded.
.EXAMPLE
    .\Build_Review.ps1
    .\Build_Review.ps1 -OutputPath C:\Temp
#>
[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Host "`n  [!] This script REQUIRES Administrator privileges." -ForegroundColor Red
    Write-Host "  Right-click PowerShell > Run as Administrator`n" -ForegroundColor Yellow
    exit
}

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$Script:OSBuild = try { (Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { "Unknown" }
$Script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Script:POCTag = "BR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$Script:IsDomainJoined = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$CheckTitle,
        [Parameter(Mandatory)][ValidateSet("Pass","Fail","Warning","Info","Error")][string]$Status,
        [string]$Expected = "", [string]$Actual = "", [string]$Description = "",
        [ValidateSet("Critical","High","Medium","Low","Informational")][string]$Severity = "Medium",
        [string]$Remediation = "", [string]$ExploitCmd = "", [string]$POCResult = "",
        [string]$CISRef = ""
    )
    $title = if ($CISRef) { "[$CISRef] $CheckTitle" } else { $CheckTitle }
    $null = $Script:Results.Add([PSCustomObject]@{
        Category=$Category; CheckTitle=$title; Status=$Status; Expected=$Expected
        Actual=$Actual; Description=$Description; Severity=$Severity
        Remediation=$Remediation; ExploitCmd=$ExploitCmd; POCResult=$POCResult
    })
}

function Get-RegValue { param([string]$Path, [string]$Name, $Default=$null)
    try { $v = Get-ItemProperty -Path "Registry::$Path" -Name $Name -ErrorAction Stop; return $v.$Name } catch { return $Default }
}

function ConvertTo-HtmlSafe { param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $a = [string][char]38; $dq = [string][char]34
    $Text = $Text -replace $a, ($a + 'amp;')
    $Text = $Text -replace '<', ($a + 'lt;')
    $Text = $Text -replace '>', ($a + 'gt;')
    $Text = $Text -replace $dq, ($a + 'quot;')
    return $Text
}

function Get-IcaclsOutput { param([string]$Path)
    try { return (icacls $Path 2>$null) -join "`n" } catch { return "icacls failed" }
}

function Test-POCWrite { param([string]$Path, [string]$Label)
    $f = Join-Path $Path "$Script:POCTag.txt"
    try { "POC write test $(Get-Date)" | Out-File $f -Force -ErrorAction Stop
        $r = "WRITE CONFIRMED: $f as $Script:CurrentUser"
        Remove-Item $f -Force -ErrorAction SilentlyContinue; $r += " [cleaned]"
        Write-Host "    [POC] $Label - WRITE OK" -ForegroundColor Red; return $r
    } catch { return "Write blocked: $($_.Exception.Message)" }
}

function Write-Section { param([string]$Name) Write-Host "`n[+] $Name" -ForegroundColor Green }


# ============================================================================
# 1. BIOS CONFIGURATION
# ============================================================================
function Test-BIOSConfiguration {
    Write-Section "1. BIOS Configuration"

    # Secure Boot
    try { $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Add-Finding -Category "BIOS Configuration" -CheckTitle "Secure Boot" `
            -Status $(if($sb){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($sb){"Enabled"}else{"Disabled"}) -Severity "High" `
            -POCResult "SecureBoot: $sb" -Remediation "Enable Secure Boot in UEFI firmware." `
            -ExploitCmd $(if(-not $sb){"Bootkit/rootkit installation possible"}else{""}) `
            -Description "Without Secure Boot, boot-level malware can persist."
    } catch { Add-Finding -Category "BIOS Configuration" -CheckTitle "Secure Boot" -Status "Warning" -Actual "Cannot query (legacy BIOS or access denied)" -Severity "High" }

    # TPM
    try { $tpm = Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm -ErrorAction Stop
        $tpmVer = $tpm.SpecVersion -split ","
        $tpmMajor = if ($tpmVer) { $tpmVer[0].Trim() } else { "Unknown" }
        $poc = "TPM Present: $($tpm.IsEnabled_InitialValue)`nActivated: $($tpm.IsActivated_InitialValue)`nOwned: $($tpm.IsOwned_InitialValue)`nSpec: $($tpm.SpecVersion)`nManufacturer: $($tpm.ManufacturerIdTxt)"
        Add-Finding -Category "BIOS Configuration" -CheckTitle "TPM version" `
            -Status $(if($tpmMajor -ge "2"){"Pass"}elseif($tpm.IsEnabled_InitialValue){"Warning"}else{"Fail"}) `
            -Expected "TPM 2.0" -Actual "TPM $tpmMajor (Enabled=$($tpm.IsEnabled_InitialValue))" `
            -Severity "High" -POCResult $poc -Remediation "Upgrade to TPM 2.0 hardware." `
            -Description "TPM 2.0 required for BitLocker, Credential Guard, measured boot."
    } catch { Add-Finding -Category "BIOS Configuration" -CheckTitle "TPM" -Status "Fail" -Actual "Not detected or access denied" -Severity "High" -Remediation "Enable TPM in BIOS." }

    # UEFI vs Legacy
    try { $fw = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction SilentlyContinue
        $isUEFI = if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State") { $true } else {
            try { $env:firmware_type -eq "UEFI" -or (bcdedit /enum firmware 2>$null) -match "UEFI" } catch { $false } }
        Add-Finding -Category "BIOS Configuration" -CheckTitle "UEFI boot mode" `
            -Status $(if($isUEFI){"Pass"}else{"Fail"}) -Expected "UEFI" `
            -Actual $(if($isUEFI){"UEFI"}else{"Legacy BIOS"}) -Severity "High" `
            -Remediation "Convert to UEFI boot (mbr2gpt)." `
            -Description "Legacy BIOS cannot use Secure Boot or VBS."
    } catch {}

    # Virtualization support (VBS prerequisite)
    $vbs = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    $hvci = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
    $poc = "VBS=$vbs`nHVCI=$hvci"
    try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) { $poc += "`nVBS Status: $($dg.VirtualizationBasedSecurityStatus)`nSecurityServicesRunning: $($dg.SecurityServicesRunning -join ',')" }
    } catch {}
    Add-Finding -Category "BIOS Configuration" -CheckTitle "Virtualization Based Security" `
        -Status $(if($vbs -eq 1){"Pass"}else{"Warning"}) -Expected "Enabled" `
        -Actual $(if($vbs -eq 1){"Enabled"}else{"Not configured"}) -Severity "High" `
        -POCResult $poc -Remediation "GPO: Enable VBS + HVCI." `
        -Description "VBS isolates security-critical processes from the OS."

    # BIOS/Firmware version
    try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        Add-Finding -Category "BIOS Configuration" -CheckTitle "BIOS/Firmware info" -Status "Info" `
            -Actual "$($bios.Manufacturer) v$($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate))" `
            -Severity "Informational" -POCResult "Manufacturer: $($bios.Manufacturer)`nVersion: $($bios.SMBIOSBIOSVersion)`nRelease: $($bios.ReleaseDate)`nSerial: $($bios.SerialNumber)" `
            -Remediation "Keep firmware updated for security patches."
    } catch {}
}


# ============================================================================
# 2. FULL DISK ENCRYPTION
# ============================================================================
function Test-FullDiskEncryption {
    Write-Section "2. Full Disk Encryption"

    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($vol in $volumes) {
            $isOS = $vol.MountPoint -eq "C:"
            $keyTypes = ($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
            $hasRecoveryPw = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
            $poc = "Volume: $($vol.MountPoint)`nStatus: $($vol.ProtectionStatus)`nEncryption: $($vol.EncryptionMethod)`nPercentage: $($vol.EncryptionPercentage)%`nLock: $($vol.LockStatus)`nKeyProtectors: $keyTypes"
            if ($hasRecoveryPw) { $poc += "`nRecovery key IDs: $(($hasRecoveryPw|ForEach-Object{$_.KeyProtectorId}) -join ', ')" }

            Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker $($vol.MountPoint)" -CISRef $(if($isOS){"18.10.9.1"}else{""}) `
                -Status $(if($vol.ProtectionStatus -eq "On"){"Pass"}else{"Fail"}) `
                -Expected "On with XtsAes256" `
                -Actual "$($vol.ProtectionStatus) ($($vol.EncryptionMethod)) Keys=$keyTypes" `
                -Severity $(if($isOS){"High"}else{"Medium"}) -POCResult $poc `
                -Remediation "Enable-BitLocker -MountPoint $($vol.MountPoint) -EncryptionMethod XtsAes256 -TpmProtector" `
                -ExploitCmd $(if($vol.ProtectionStatus -ne "On"){"Physical disk access = full data theft"}else{""}) `
                -Description "Unencrypted volumes expose data to physical access attacks."

            if ($isOS -and $vol.ProtectionStatus -eq "On") {
                # Check encryption strength
                $strongEnc = $vol.EncryptionMethod -match "(XtsAes256|Aes256)"
                Add-Finding -Category "Full Disk Encryption" -CheckTitle "Encryption strength $($vol.MountPoint)" `
                    -Status $(if($strongEnc){"Pass"}else{"Warning"}) -Expected "XtsAes256" `
                    -Actual $vol.EncryptionMethod -Severity "Medium" `
                    -Remediation "Re-encrypt with: manage-bde -ChangeKey C: -EncryptionMethod XtsAes256"
            }
        }

        # Recovery key storage
        $recoveryInAD = $false
        try { if ($Script:IsDomainJoined) { $recoveryInAD = (Get-ADObject -Filter 'objectclass -eq "msFVE-RecoveryInformation"' -ErrorAction SilentlyContinue).Count -gt 0 } } catch {}
        Add-Finding -Category "Full Disk Encryption" -CheckTitle "Recovery key backup policy" `
            -Status "Info" -Expected "Backed up to AD/Azure/escrow" `
            -Actual $(if($recoveryInAD){"Keys escrowed to AD"}else{"Check backup location manually"}) `
            -Severity "Medium" -Remediation "GPO: Store BitLocker recovery info in AD DS" `
            -Description "Recovery keys must be securely escrowed."
    } catch {
        Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker" -Status "Fail" `
            -Expected "Enabled" -Actual "Cannot query: $($_.Exception.Message)" -Severity "High" `
            -POCResult "BitLocker query failed. May not be available on this edition." `
            -Remediation "Enable BitLocker. Windows Home requires device encryption."
    }

    # Suspend check
    try { $suspended = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.ProtectionStatus -eq "Off" -and $_.VolumeStatus -ne "FullyDecrypted" }
        if ($suspended) {
            Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker suspended volumes" `
                -Status "Fail" -Expected "None suspended" `
                -Actual "$($suspended.Count): $(($suspended|ForEach-Object{$_.MountPoint}) -join ', ')" `
                -Severity "High" -Remediation "Resume-BitLocker -MountPoint X:" `
                -Description "Suspended BitLocker = unprotected until resumed."
        }
    } catch {}
}


# ============================================================================
# 3. OS & THIRD-PARTY SOFTWARE PATCHING
# ============================================================================
function Test-Patching {
    Write-Section "3. OS & Third-Party Patching"

    # Windows Updates
    try { $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
        $latest = $hf | Select-Object -First 1
        $days = if ($latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
        $poc = "Total hotfixes: $($hf.Count)`nLatest: $($latest.HotFixID) ($days days ago)`nRecent 5:`n$(($hf|Select-Object -First 5|ForEach-Object{"  $($_.HotFixID) $($_.InstalledOn) $($_.Description)"}) -join "`n")"
        Add-Finding -Category "OS Patching" -CheckTitle "Windows Update status" `
            -Status $(if($days -le 30){"Pass"}elseif($days -le 90){"Warning"}else{"Fail"}) `
            -Expected "Updated within 30 days" -Actual "$days days since last update ($($latest.HotFixID))" `
            -Severity $(if($days -gt 90){"Critical"}else{"Medium"}) -POCResult $poc `
            -Remediation "Install all pending Windows Updates." `
            -Description "Missing patches = known CVE exploitation."
    } catch {}

    # OS Build vs latest
    try { $build = [System.Environment]::OSVersion.Version
        Add-Finding -Category "OS Patching" -CheckTitle "OS build version" -Status "Info" `
            -Actual "Build $($build.Build).$($build.Revision)" -Severity "Informational" `
            -POCResult "Major=$($build.Major) Minor=$($build.Minor) Build=$($build.Build) Rev=$($build.Revision)" `
            -Remediation "Compare against Microsoft release health dashboard."
    } catch {}

    # Third-party software
    try {
        $sw = @()
        $paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        foreach ($p in $paths) { if (Test-Path $p) {
            Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -and $props.DisplayName -notmatch "^(Update|Security Update|Hotfix)") {
                    $sw += [PSCustomObject]@{Name=$props.DisplayName;Version=$props.DisplayVersion;Publisher=$props.Publisher;InstallDate=$props.InstallDate}
                }
            }
        }}
        $sw = $sw | Sort-Object Name -Unique
        $poc = "Installed software ($($sw.Count) packages):`n$(($sw|Select-Object -First 40|ForEach-Object{"  $($_.Name) v$($_.Version) [$($_.Publisher)]"}) -join "`n")"
        Add-Finding -Category "OS Patching" -CheckTitle "Third-party software inventory" -Status "Info" `
            -Actual "$($sw.Count) packages" -Severity "Informational" -POCResult $poc `
            -Remediation "Review for EOL/vulnerable software. Remove unnecessary packages." `
            -Description "Each package is potential attack surface."

        # Flag known risky software
        $risky = $sw | Where-Object { $_.Name -match "(Java \d|Adobe Flash|Adobe Reader \d|Silverlight|Python 2\.|PHP [0-4]\.|Apache [0-1]\.|OpenSSL 1\.0)" }
        if ($risky.Count -gt 0) {
            Add-Finding -Category "OS Patching" -CheckTitle "Potentially vulnerable software" `
                -Status "Warning" -Expected "None" `
                -Actual "$($risky.Count): $(($risky|ForEach-Object{$_.Name}) -join ', ')" `
                -Severity "High" -Remediation "Update or remove flagged software." `
                -Description "Known vulnerable or EOL software detected."
        }
    } catch {}

    # Windows Update service
    try { $wuSvc = Get-Service wuauserv -ErrorAction SilentlyContinue
        $wuAuto = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" "AUOptions" 0
        Add-Finding -Category "OS Patching" -CheckTitle "Windows Update configuration" `
            -Status $(if($wuSvc.Status -eq "Running" -or $wuSvc.StartType -ne "Disabled"){"Pass"}else{"Fail"}) `
            -Expected "Service enabled, auto-update" -Actual "Service=$($wuSvc.Status)/$($wuSvc.StartType), AUOptions=$wuAuto" `
            -Severity "High" -Remediation "Set-Service wuauserv -StartupType Automatic"
    } catch {}
}


# ============================================================================
# 4. LOCAL SERVICE CHECKS
# ============================================================================
function Test-LocalServices {
    Write-Section "4. Local Service Checks"
    $dq = [string][char]34

    # Writable binaries
    try {
        $vuln = @(); $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.State -eq "Running" }
        foreach ($s in $svcs | Select-Object -First 80) {
            $p = $s.PathName -replace $dq,''
            if ($p -match '^([a-zA-Z]:\\.+?\.(exe|dll))') { $ep = $Matches[1]
                if (Test-Path $ep) { $a = Get-Acl $ep -ErrorAction SilentlyContinue
                    if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" }; if ($w) { $vuln += "$($s.Name): $ep" } } } } }
        $poc = "Scanned $($svcs.Count) running services.`n$(if($vuln.Count -gt 0){($vuln -join "`n")}else{'None writable.'})"
        Add-Finding -Category "Local Services" -CheckTitle "Writable service binaries" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None"}else{"$($vuln.Count): $(($vuln|Select-Object -First 5) -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "icacls BINARY /reset" `
            -ExploitCmd "copy payload.exe BINARY; sc stop/start SVC"
    } catch {}

    # Unquoted paths
    try { $uq = Get-CimInstance Win32_Service | Where-Object {
            $_.PathName -and $_.PathName -notmatch ('^\s*' + $dq) -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\' }
        $poc = if ($uq.Count -gt 0) { ($uq|Select-Object -First 5|ForEach-Object{"$($_.Name): $($_.PathName)"}) -join "`n" } else { "" }
        Add-Finding -Category "Local Services" -CheckTitle "Unquoted service paths" `
            -Status $(if($uq.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($uq.Count -eq 0){"None"}else{"$($uq.Count)"}) -Severity "High" -POCResult $poc `
            -Remediation "sc config SVC binPath= `"quoted path`"" -ExploitCmd "copy payload.exe C:\Program.exe"
    } catch {}

    # Weak DACLs
    try {
        $weakSvcPerms = @()
        foreach ($s in $svcs | Select-Object -First 30) {
            $sd = sc.exe sdshow $s.Name 2>$null | Where-Object { $_ -match "D:" }
            if ($sd -match "A;.*?(BU|AU|WD);.*?(WP|WD|GA|GW)") { $weakSvcPerms += "$($s.Name)" }
        }
        Add-Finding -Category "Local Services" -CheckTitle "Services with weak DACLs" `
            -Status $(if($weakSvcPerms.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($weakSvcPerms.Count -eq 0){"None (sampled 30)"}else{"$($weakSvcPerms.Count): $($weakSvcPerms -join ', ')"}) `
            -Severity "High" -Remediation "sc sdset SVC to restrict." -ExploitCmd "sc config SVC binPath= payload.exe"
    } catch {}

    # AlwaysInstallElevated
    $aieHKCU = Get-RegValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieHKLM = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieVuln = $aieHKCU -eq 1 -and $aieHKLM -eq 1
    Add-Finding -Category "Local Services" -CheckTitle "AlwaysInstallElevated" `
        -Status $(if($aieVuln){"Fail"}else{"Pass"}) -Expected "Not 1 in both" `
        -Actual "HKLM=$(if($null -eq $aieHKLM){'N/A'}else{$aieHKLM}), HKCU=$(if($null -eq $aieHKCU){'N/A'}else{$aieHKCU})" `
        -Severity "Critical" -ExploitCmd $(if($aieVuln){"msfvenom -f msi > evil.msi; msiexec /quiet /i evil.msi"}else{""})

    # Print Spooler
    try { $sp = Get-Service Spooler -ErrorAction SilentlyContinue
        Add-Finding -Category "Local Services" -CheckTitle "Print Spooler" -CISRef "5.36" `
            -Status $(if($sp.Status -ne "Running"){"Pass"}else{"Fail"}) -Expected "Stopped" `
            -Actual $sp.Status -Severity "High" -Remediation "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled" `
            -ExploitCmd "PrintNightmare / PrintSpoofer.exe"
    } catch {}

    # Remote Registry
    try { $rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
        Add-Finding -Category "Local Services" -CheckTitle "Remote Registry" -CISRef "5.27" `
            -Status $(if($rr.Status -ne "Running" -and $rr.StartType -eq "Disabled"){"Pass"}else{"Fail"}) `
            -Expected "Disabled" -Actual "Status=$($rr.Status), Start=$($rr.StartType)" -Severity "Medium" `
            -Remediation "Set-Service RemoteRegistry -StartupType Disabled"
    } catch {}

    # RMM tools
    $rmmTools = @()
    foreach ($rp in @("AnyDesk","TeamViewer","TeamViewer_Service","vncserver","rustdesk","ScreenConnect","ConnectWise","LogMeIn")) {
        $p = Get-Process -Name $rp -ErrorAction SilentlyContinue; if ($p) { $rmmTools += "$rp (PID: $(($p|ForEach-Object{$_.Id}) -join ','))" } }
    $rmmSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(AnyDesk|TeamViewer|VNC|RustDesk|ScreenConnect)" -and $_.Status -eq "Running" }
    foreach ($rs in $rmmSvcs) { $rmmTools += "$($rs.DisplayName) (svc)" }
    # Service account analysis
    try {
        $sysServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Running" }
        $asSystem = ($sysServices | Where-Object { $_.StartName -match "LocalSystem|SYSTEM" }).Count
        $asLocalSvc = ($sysServices | Where-Object { $_.StartName -match "LocalService|LOCAL SERVICE" }).Count
        $asNetSvc = ($sysServices | Where-Object { $_.StartName -match "NetworkService|NETWORK SERVICE" }).Count
        $asUser = $sysServices | Where-Object { $_.StartName -and $_.StartName -notmatch "(LocalSystem|SYSTEM|LocalService|NetworkService|LOCAL SERVICE|NETWORK SERVICE)" }
        $poc = "Running as SYSTEM: $asSystem`nLocalService: $asLocalSvc`nNetworkService: $asNetSvc`nUser accounts: $($asUser.Count)"
        if ($asUser.Count -gt 0) { $poc += "`n$(($asUser|Select-Object -First 10|ForEach-Object{"  $($_.Name) -> $($_.StartName)"}) -join "`n")" }
        Add-Finding -Category "Local Services" -CheckTitle "Service account analysis" `
            -Status $(if($asUser.Count -gt 5){"Warning"}else{"Info"}) -Expected "Minimal user-context services" `
            -Actual "SYSTEM=$asSystem, User=$($asUser.Count)" -Severity "Medium" -POCResult $poc `
            -Description "Services running as user accounts may have stored credentials."
    } catch {}

    Add-Finding -Category "Local Services" -CheckTitle "Remote access tools (RMM)" `
        -Status $(if($rmmTools.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None or approved" `
        -Actual $(if($rmmTools.Count -eq 0){"None"}else{"$($rmmTools.Count): $($rmmTools -join ', ')"}) `
        -Severity $(if($rmmTools.Count -gt 0){"High"}else{"Medium"}) `
        -POCResult "RMM: $(if($rmmTools.Count -gt 0){$rmmTools -join "`n"}else{'None'})" `
        -Remediation "Remove unapproved RMM tools." -Description "RMM = persistent remote access."
}


# ============================================================================
# 5. FILE SYSTEM REVIEW
# ============================================================================
function Test-FileSystem {
    Write-Section "5. File System Review"

    # Startup folders
    foreach ($sp in @(
        @{Path="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp";Desc="All Users Startup";Sev="Critical"},
        @{Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup";Desc="Current User Startup";Sev="Medium"}
    )) { if (Test-Path $sp.Path) { try {
        $acl = Get-Acl $sp.Path -ErrorAction Stop
        $weak = $acl.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" }
        $items = Get-ChildItem $sp.Path -ErrorAction SilentlyContinue
        $poc = "icacls:`n$(Get-IcaclsOutput $sp.Path)"
        if ($weak) { $poc += "`n$(Test-POCWrite $sp.Path $sp.Desc)" }
        if ($items.Count -gt 0) { $poc += "`nItems: $(($items|ForEach-Object{$_.Name}) -join ', ')" }
        Add-Finding -Category "File System" -CheckTitle "$($sp.Desc) permissions" `
            -Status $(if($weak){"Fail"}else{"Pass"}) -Expected "Not writable by Users" `
            -Actual "Writable=$(if($weak){'YES'}else{'No'}), Items=$($items.Count)" `
            -Severity $sp.Sev -POCResult $poc -Remediation "icacls PATH /remove:g `"BUILTIN\Users`""
    } catch {} } }

    # Writable Program Files
    try {
        $writable = @()
        foreach ($pd in @("C:\Program Files","C:\Program Files (x86)")) {
            if (Test-Path $pd) { Get-ChildItem $pd -Directory -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
                $da = Get-Acl $_.FullName -ErrorAction SilentlyContinue
                if ($da) { $w = $da.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $_.FileSystemRights -match "(Write|Modify|FullControl)" -and $_.AccessControlType -eq "Allow" }
                    if ($w) { $writable += $_.FullName } } } } }
        $poc = if ($writable.Count -gt 0) { ($writable|Select-Object -First 3|ForEach-Object{"$_`n$(Get-IcaclsOutput $_)"}) -join "`n" } else { "" }
        Add-Finding -Category "File System" -CheckTitle "Writable Program Files subdirs" `
            -Status $(if($writable.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writable.Count -eq 0){"None"}else{"$($writable.Count): $(($writable|Select-Object -First 5) -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "icacls DIR /reset /T"
    } catch {}

    # Writable PATH dirs
    try {
        $sp2 = [Environment]::GetEnvironmentVariable("PATH","Machine") -split ";"
        $writablePath = @()
        foreach ($d in $sp2) { if ($d -and (Test-Path $d -ErrorAction SilentlyContinue)) {
            $a = Get-Acl $d -ErrorAction SilentlyContinue
            if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow" }
                if ($w) { $writablePath += $d } } } }
        $poc = "System PATH dirs: $($sp2.Count)`n"
        if ($writablePath.Count -gt 0) { foreach ($w in $writablePath|Select-Object -First 3) { $poc += "--- $w ---`n$(Get-IcaclsOutput $w)`n$(Test-POCWrite $w 'PATH')`n" } }
        Add-Finding -Category "File System" -CheckTitle "Writable system PATH dirs" `
            -Status $(if($writablePath.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writablePath.Count -eq 0){"None"}else{"$($writablePath.Count): $($writablePath -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "Fix ACLs: icacls DIR /remove:g Users" `
            -ExploitCmd "copy version.dll WRITABLE_PATH\ (DLL hijacking)"
    } catch {}

    # Unattend/Sysprep
    $sf = @(); foreach ($p in @(
        "C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\unattend.xml","C:\Windows\Panther\Autounattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml","C:\Windows\system32\sysprep\Unattend.xml","C:\unattend.xml"
    )) { if (Test-Path $p -ErrorAction SilentlyContinue) { try { $null = Get-Content $p -TotalCount 1 -ErrorAction Stop; $sf += $p } catch {} } }
    $poc = ""
    if ($sf.Count -gt 0) { foreach ($f in $sf) { $poc += "=== $f ===`n"; try {
        $c = Get-Content $f -Raw -ErrorAction Stop
        if ($c -match '(?i)password') { $poc += "!! PASSWORD keyword found`n" }
    } catch {} } }
    Add-Finding -Category "File System" -CheckTitle "Deployment files (Unattend/Sysprep)" `
        -Status $(if($sf.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($sf.Count -eq 0){"None"}else{"$($sf.Count): $($sf -join '; ')"}) `
        -Severity "Critical" -POCResult $poc -Remediation "Delete all deployment XML files." `
        -ExploitCmd "type FILE | findstr /i password (base64 decode)"

    # Accessibility hijack
    $accessHijack = @()
    foreach ($tool in @("sethc.exe","utilman.exe","narrator.exe","magnify.exe","osk.exe")) {
        $ifeo = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tool" "Debugger"
        if ($ifeo) { $accessHijack += "$tool IFEO=$ifeo" }
        $fp = "C:\Windows\System32\$tool"
        if (Test-Path $fp) { $fi = Get-Item $fp -ErrorAction SilentlyContinue
            if ($fi -and $fi.VersionInfo.CompanyName -notmatch "Microsoft") { $accessHijack += "$tool NOT Microsoft!" } } }
    # SAM/SYSTEM backup files
    $samPaths = @()
    foreach ($sp3 in @("C:\Windows\Repair\SAM","C:\Windows\Repair\SYSTEM","C:\Windows\Repair\SECURITY",
        "C:\Windows\System32\config\RegBack\SAM","C:\Windows\System32\config\RegBack\SYSTEM")) {
        if (Test-Path $sp3 -ErrorAction SilentlyContinue) { try { $null = Get-Content $sp3 -TotalCount 1 -ErrorAction Stop; $samPaths += "$sp3 (READABLE!)" } catch { $samPaths += "$sp3 (exists, locked)" } } }
    Add-Finding -Category "File System" -CheckTitle "SAM/SYSTEM backup files" `
        -Status $(if(($samPaths|Where-Object{$_ -match "READABLE"}).Count -gt 0){"Fail"}elseif($samPaths.Count -gt 0){"Info"}else{"Pass"}) `
        -Expected "None accessible" -Actual $(if($samPaths.Count -eq 0){"None"}else{"$($samPaths.Count): $($samPaths -join '; ')"}) `
        -Severity "Critical" -ExploitCmd "impacket-secretsdump -sam SAM -system SYSTEM LOCAL" `
        -POCResult $(if($samPaths.Count -gt 0){$samPaths -join "`n"}else{""})

    # Shadow copies
    try { $vss = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
        $poc = "Shadow copies: $($vss.Count)"
        if ($vss.Count -gt 0) { $poc += "`n$(($vss|Select-Object -First 3|ForEach-Object{"  $($_.DeviceObject) Created=$($_.InstallDate)"}) -join "`n")" }
        Add-Finding -Category "File System" -CheckTitle "Volume shadow copies" `
            -Status $(if($vss.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Reviewed" `
            -Actual "$($vss.Count) shadows" -Severity "High" -POCResult $poc `
            -ExploitCmd $(if($vss.Count -gt 0){"mklink /d C:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\ (access old SAM)"}else{""})
    } catch {}

    # GPP cpassword
    $gppFound = @()
    $sysvolPaths = @("$env:ALLUSERSPROFILE\Microsoft\Group Policy\History","C:\Windows\SYSVOL")
    foreach ($gp in $sysvolPaths) { if (Test-Path $gp) {
        Get-ChildItem $gp -Recurse -Include "*.xml" -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
            try { $gc = Get-Content $_.FullName -Raw -ErrorAction Stop
                if ($gc -match "cpassword") { $gppFound += $_.FullName }
            } catch {} } } }
    Add-Finding -Category "File System" -CheckTitle "GPP cpassword files" `
        -Status $(if($gppFound.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($gppFound.Count -eq 0){"None"}else{"$($gppFound.Count): $($gppFound -join '; ')"}) `
        -Severity "Critical" -ExploitCmd "gpp-decrypt CPASSWORD"

    # Writable C:\ root
    try { $cRootAcl = Get-Acl "C:\" -ErrorAction Stop
        $cWeak = $cRootAcl.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
            $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow" -and
            $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" }
        Add-Finding -Category "File System" -CheckTitle "Writable C:\ root" `
            -Status $(if($cWeak){"Fail"}else{"Pass"}) -Expected "Not user-writable" `
            -Actual $(if($cWeak){"Users can write to C:\"}else{"Restricted"}) `
            -Severity "High" -ExploitCmd $(if($cWeak){"copy malicious.dll C:\; DLL search order hijack"}else{""})
    } catch {}

    Add-Finding -Category "File System" -CheckTitle "Accessibility tool hijacking" `
        -Status $(if($accessHijack.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($accessHijack.Count -eq 0){"Clean"}else{$accessHijack -join '; '}) `
        -Severity "Critical" -Remediation "Restore originals. Remove IFEO debuggers." `
        -ExploitCmd $(if($accessHijack.Count -gt 0){"Shift 5x at login = SYSTEM shell"}else{""})
}


# ============================================================================
# 6. SECURITY CONFIGURATION INSPECTION
# ============================================================================
function Test-SecurityConfig {
    Write-Section "6. Security Configuration"

    # Windows Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $poc = "RealTime=$($mp.RealTimeProtectionEnabled)`nBehavior=$($mp.BehaviorMonitorEnabled)`nIOAV=$($mp.IoavProtectionEnabled)`nTamper=$($mp.IsTamperProtected)`nNIS=$($mp.NISEnabled)`nSigAge=$($mp.AntivirusSignatureAge)d`nEngine=$($mp.AMEngineVersion)"

        Add-Finding -Category "Security Config" -CheckTitle "Defender Real-Time Protection" -CISRef "18.10.43.10.1" `
            -Status $(if($mp.RealTimeProtectionEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.RealTimeProtectionEnabled){"On"}else{"OFF"}) -Severity "Critical" -POCResult $poc

        Add-Finding -Category "Security Config" -CheckTitle "Defender Tamper Protection" `
            -Status $(if($mp.IsTamperProtected){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.IsTamperProtected){"On"}else{"OFF"}) -Severity "High" `
            -Remediation "Enable via Windows Security UI."

        Add-Finding -Category "Security Config" -CheckTitle "Signature age" `
            -Status $(if($mp.AntivirusSignatureAge -le 3){"Pass"}elseif($mp.AntivirusSignatureAge -le 7){"Warning"}else{"Fail"}) `
            -Expected "3 days" -Actual "$($mp.AntivirusSignatureAge) days" -Severity $(if($mp.AntivirusSignatureAge -gt 7){"High"}else{"Medium"})

        Add-Finding -Category "Security Config" -CheckTitle "ASR rules" -CISRef "18.10.43.6" `
            -Status $(if(($pref.AttackSurfaceReductionRules_Actions|Where-Object{$_ -ge 1}).Count -ge 5){"Pass"}else{"Fail"}) `
            -Expected "5+ rules" -Actual "$(($pref.AttackSurfaceReductionRules_Actions|Where-Object{$_ -ge 1}).Count) active" `
            -Severity "High" -Remediation "Deploy ASR rules via Intune/GPO."

        # Exclusions
        $allExc = @()
        if ($pref.ExclusionPath) { $pref.ExclusionPath | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Path: $_" } }
        if ($pref.ExclusionProcess) { $pref.ExclusionProcess | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Proc: $_" } }
        if ($pref.ExclusionExtension) { $pref.ExclusionExtension | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Ext: $_" } }
        Add-Finding -Category "Security Config" -CheckTitle "Behavior monitoring" -CISRef "18.10.43.10.2" `
            -Status $(if($mp.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.BehaviorMonitorEnabled){"On"}else{"OFF"}) -Severity "High"

        Add-Finding -Category "Security Config" -CheckTitle "PUA protection" -CISRef "18.10.43.10" `
            -Status $(if($pref.PUAProtection -eq 1){"Pass"}else{"Warning"}) -Expected "1 (Enabled)" `
            -Actual $pref.PUAProtection -Severity "Medium"

        $maps = $pref.MAPSReporting
        Add-Finding -Category "Security Config" -CheckTitle "Cloud-delivered protection (MAPS)" -CISRef "18.10.43.5.1" `
            -Status $(if($maps -eq 2){"Pass"}elseif($maps -ge 1){"Warning"}else{"Fail"}) `
            -Expected "2 (Advanced)" -Actual $maps -Severity "Medium" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced"

        Add-Finding -Category "Security Config" -CheckTitle "Defender exclusions" `
            -Status $(if($allExc.Count -eq 0){"Pass"}elseif($allExc.Count -le 3){"Warning"}else{"Fail"}) `
            -Expected "Minimal" -Actual "$($allExc.Count) exclusions" -Severity $(if($allExc.Count -gt 5){"High"}else{"Medium"}) `
            -POCResult "Exclusions:`n$(if($allExc.Count -gt 0){$allExc -join "`n"}else{'None'})" `
            -ExploitCmd $(if($allExc.Count -gt 0){"Drop payload in excluded path"}else{""})
    } catch { Add-Finding -Category "Security Config" -CheckTitle "Defender" -Status "Warning" -Actual "Cannot query: $_" -Severity "Critical" }

    # Firewall
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $poc = "$($p.Name): Enabled=$($p.Enabled) In=$($p.DefaultInboundAction) Out=$($p.DefaultOutboundAction) LogBlocked=$($p.LogBlocked)"
            Add-Finding -Category "Security Config" -CheckTitle "$($p.Name) firewall" -CISRef "9.$($p.Name)" `
                -Status $(if($p.Enabled){"Pass"}else{"Fail"}) -Expected "Enabled + Block inbound" `
                -Actual "Enabled=$($p.Enabled), In=$($p.DefaultInboundAction)" -Severity "High" -POCResult $poc `
                -Remediation "Set-NetFirewallProfile -Name $($p.Name) -Enabled True -DefaultInboundAction Block"

            Add-Finding -Category "Security Config" -CheckTitle "$($p.Name) firewall logging" `
                -Status $(if($p.LogBlocked -eq $true){"Pass"}else{"Fail"}) -Expected "LogBlocked=True" `
                -Actual "LogBlocked=$($p.LogBlocked)" -Severity "Medium" `
                -Remediation "Set-NetFirewallProfile -Name $($p.Name) -LogBlocked True -LogMaxSizeKilobytes 16384"
        }
    } catch {}

    # LSASS protection
    $runAsPPL = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $pplMap = @{0="Disabled";1="Enabled";2="Enabled+UEFI lock"}
    $pplOK = $runAsPPL -eq 1 -or $runAsPPL -eq 2
    Add-Finding -Category "Security Config" -CheckTitle "LSASS RunAsPPL" -CISRef "18.4.7" `
        -Status $(if($pplOK){"Pass"}else{"Fail"}) -Expected "1 or 2" `
        -Actual $(if($pplOK){"Protected ($($pplMap[[int]$runAsPPL]))"}else{"Unprotected"}) `
        -Severity "Critical" -POCResult "RunAsPPL=$(if($null -eq $runAsPPL){'Not set'}else{"$runAsPPL ($($pplMap[[int]$runAsPPL]))"})" `
        -ExploitCmd $(if(-not $pplOK){"mimikatz # sekurlsa::logonpasswords"}else{""})

    # Credential Guard
    $credGuard = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    Add-Finding -Category "Security Config" -CheckTitle "Credential Guard" -CISRef "18.4.1" `
        -Status $(if($credGuard -ge 1){"Pass"}else{"Fail"}) -Expected "1+" `
        -Actual $(if($credGuard -ge 1){"Enabled ($credGuard)"}else{"Not configured"}) -Severity "High" `
        -Remediation "GPO: Enable Credential Guard with UEFI lock."

    # WDigest
    $wdigest = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-Finding -Category "Security Config" -CheckTitle "WDigest plaintext" -CISRef "18.4.8" `
        -Status $(if($wdigest -eq 1){"Fail"}else{"Pass"}) -Expected "0 or not set" `
        -Actual $(if($wdigest -eq 1){"ENABLED!"}else{"Disabled (default)"}) -Severity "Critical" `
        -ExploitCmd $(if($wdigest -eq 1){"mimikatz # sekurlsa::wdigest"}else{""})

    # AMSI
    try { $amsi = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        Add-Finding -Category "Security Config" -CheckTitle "AMSI providers" `
            -Status $(if($amsi.Count -gt 0){"Pass"}else{"Warning"}) -Expected "1+" `
            -Actual "$($amsi.Count) providers" -Severity "Medium"
    } catch {}

    # Sysmon / EDR
    try { $sysmon = Get-Service Sysmon* -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
        Add-Finding -Category "Security Config" -CheckTitle "Sysmon" `
            -Status $(if($sysmon){"Pass"}else{"Warning"}) -Expected "Running" `
            -Actual $(if($sysmon){"$($sysmon.Name)"}else{"Not installed"}) -Severity "Medium" `
            -Remediation "Install Sysmon with SwiftOnSecurity config."
    } catch {}

    # 3rd party EDR
    $edrProcs = @("MsSense","CylanceSvc","CrowdStrike","csfalconservice","SentinelAgent","SentinelOne",
        "CarbonBlack","cb","TaniumClient","qualysagent","nessuscli","Elastic.Agent")
    $foundEDR = @()
    foreach ($e in $edrProcs) { $p = Get-Process -Name $e -ErrorAction SilentlyContinue; if ($p) { $foundEDR += $e } }
    $edrSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(Defender for Endpoint|CrowdStrike|SentinelOne|Carbon Black|Cylance|Tanium|Elastic Agent)" -and $_.Status -eq "Running" }
    foreach ($es in $edrSvcs) { $foundEDR += $es.DisplayName }
    Add-Finding -Category "Security Config" -CheckTitle "EDR/XDR detection" -Status "Info" `
        -Actual $(if($foundEDR.Count -gt 0){"$($foundEDR.Count): $($foundEDR -join ', ')"}else{"None detected"}) `
        -Severity "Informational" -POCResult "EDR: $(if($foundEDR.Count -gt 0){$foundEDR -join "`n"}else{'None found'})" `
        -Remediation "Deploy EDR solution."
}


# ============================================================================
# 7. REMOVABLE MEDIA CHECKING
# ============================================================================
function Test-RemovableMedia {
    Write-Section "7. Removable Media"

    # USB storage policy
    $usbStor = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" "Start" 3
    Add-Finding -Category "Removable Media" -CheckTitle "USB storage driver" `
        -Status $(if($usbStor -eq 4){"Pass"}else{"Fail"}) -Expected "4 (Disabled)" `
        -Actual $(if($usbStor -eq 4){"Disabled"}elseif($usbStor -eq 3){"Enabled (default)"}else{$usbStor}) `
        -Severity "High" -POCResult "USBSTOR Start = $usbStor (3=enabled, 4=disabled)" `
        -Remediation "reg add HKLM\SYSTEM\...\USBSTOR /v Start /t REG_DWORD /d 4" `
        -ExploitCmd $(if($usbStor -ne 4){"Insert USB = data exfiltration / malware delivery"}else{""}) `
        -Description "USB storage allows data exfiltration with physical access."

    # Device installation restrictions
    $denyAll = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyAll" 0
    $denyRemovable = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyRemovable" 0
    $denyClasses = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyDeviceClasses" 0
    Add-Finding -Category "Removable Media" -CheckTitle "Device installation restrictions" `
        -Status $(if($denyAll -eq 1 -or $denyRemovable -eq 1){"Pass"}else{"Fail"}) `
        -Expected "DenyAll or DenyRemovable = 1" `
        -Actual "DenyAll=$denyAll, DenyRemovable=$denyRemovable, DenyClasses=$denyClasses" `
        -Severity "High" -POCResult "DenyAll=$denyAll`nDenyRemovable=$denyRemovable`nDenyDeviceClasses=$denyClasses" `
        -Remediation "GPO: Prevent installation of removable devices = Enabled" `
        -Description "Without restrictions, any USB device can be plugged in."

    # AutoRun / AutoPlay
    $autorun = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 0
    $autoplay = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 0
    $disableAutoplay = Get-RegValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay" 0
    Add-Finding -Category "Removable Media" -CheckTitle "AutoRun disabled" -CISRef "18.10.25.1" `
        -Status $(if($autorun -eq 255 -or $autoplay -eq 1){"Pass"}else{"Fail"}) `
        -Expected "NoDriveTypeAutoRun=255 or NoAutorun=1" `
        -Actual "NoDriveType=$autorun, NoAutorun=$autoplay, UserAutoplay=$disableAutoplay" `
        -Severity "High" -POCResult "NoDriveTypeAutoRun=$autorun (255=all)`nNoAutorun=$autoplay`nDisableAutoplay=$disableAutoplay" `
        -Remediation "GPO: Turn off Autoplay = All drives" `
        -ExploitCmd $(if($autorun -ne 255){"Autorun.inf on USB = auto-execute malware"}else{""}) `
        -Description "AutoRun executes code automatically when media is inserted."

    # DMA protection
    $dmaGuard = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
    $thunderbolt = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\PnP" "DisableThunderboltDMA"
    Add-Finding -Category "Removable Media" -CheckTitle "DMA protection (Thunderbolt/PCIe)" `
        -Status $(if($dmaGuard -eq 0 -or $thunderbolt -eq 1){"Pass"}else{"Warning"}) `
        -Expected "Kernel DMA Protection enabled" `
        -Actual "DMAGuard=$(if($null -eq $dmaGuard){'Not set'}else{$dmaGuard}), ThunderboltDMA=$(if($null -eq $thunderbolt){'Not set'}else{$thunderbolt})" `
        -Severity "Medium" -POCResult "DeviceEnumerationPolicy=$dmaGuard`nDisableThunderboltDMA=$thunderbolt" `
        -Remediation "GPO: Kernel DMA Protection + disable new DMA devices when locked" `
        -Description "DMA attacks via Thunderbolt/PCIe can bypass OS security."

    # WPD (Windows Portable Devices) write access
    $wpdWrite = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{WPD Devices}" "Deny_Write" 0
    $wpdRead = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{WPD Devices}" "Deny_Read" 0
    $removWrite = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_Write" 0
    Add-Finding -Category "Removable Media" -CheckTitle "Removable storage write access" `
        -Status $(if($removWrite -eq 1 -or $wpdWrite -eq 1){"Pass"}else{"Fail"}) `
        -Expected "Write denied" -Actual "RemovWrite=$removWrite, WPDWrite=$wpdWrite, WPDRead=$wpdRead" `
        -Severity "High" -POCResult "Deny_Write (removable)=$removWrite`nDeny_Write (WPD)=$wpdWrite`nDeny_Read (WPD)=$wpdRead" `
        -Remediation "GPO: Removable Disks: Deny write access = Enabled" `
        -Description "Write access to removable media enables data exfiltration."

    # BitLocker To Go
    $btgRequire = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "RDVDenyWriteAccess" 0
    Add-Finding -Category "Removable Media" -CheckTitle "BitLocker To Go enforcement" `
        -Status $(if($btgRequire -eq 1){"Pass"}else{"Warning"}) -Expected "1 (Require encryption)" `
        -Actual $(if($btgRequire -eq 1){"Enforced"}else{"Not enforced"}) -Severity "Medium" `
        -Remediation "GPO: Deny write access to removable drives not protected by BitLocker"
}


# ============================================================================
# 8. USER ACCOUNT & PASSWORD CONFIGURATION
# ============================================================================
function Test-AccountConfig {
    Write-Section "8. User Account & Password Config"

    # Secedit export
    $secpolWorked = $false
    try {
        $tmpInf = Join-Path $env:TEMP "$Script:POCTag.inf"
        secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>&1 | Out-Null
        if ((Test-Path $tmpInf) -and (Get-Item $tmpInf).Length -gt 100) {
            $secpol = Get-Content $tmpInf; Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue; $secpolWorked = $true
            $complexity = if ($secpol -match "PasswordComplexity\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
            $reversible = if ($secpol -match "ClearTextPassword\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
            $lockThr = if ($secpol -match "LockoutBadCount\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
            $lockDur = if ($secpol -match "LockoutDuration\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }

            Add-Finding -Category "Account Config" -CheckTitle "Password complexity" -CISRef "1.1.5" `
                -Status $(if($complexity -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $complexity -Severity "High"
            Add-Finding -Category "Account Config" -CheckTitle "Reversible encryption" -CISRef "1.1.6" `
                -Status $(if($reversible -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $reversible -Severity "Critical"
            Add-Finding -Category "Account Config" -CheckTitle "Account lockout threshold" -CISRef "1.2.2" `
                -Status $(if($lockThr -gt 0 -and $lockThr -le 5){"Pass"}else{"Fail"}) `
                -Expected "1-5" -Actual $(if($lockThr -eq 0){"Never"}else{$lockThr}) -Severity "High" `
                -ExploitCmd $(if($lockThr -eq 0){"Unlimited brute force"}else{""})
            Add-Finding -Category "Account Config" -CheckTitle "Lockout duration" -CISRef "1.2.1" `
                -Status $(if($lockDur -ge 15){"Pass"}else{"Fail"}) -Expected "15+ min" -Actual "$lockDur min" -Severity "High"
    }} catch {}

    # net accounts
    try {
        $na = net accounts 2>$null
        $poc = ($na | Out-String).Trim()
        $minLen = if ($na -match "Minimum password length:\s+(\d+)") { [int]$Matches[1] } else { 0 }
        $history = if ($na -match "Length of password history maintained:\s+(\d+|None)") { $Matches[1] } else { "0" }
        Add-Finding -Category "Account Config" -CheckTitle "Minimum password length" -CISRef "1.1.4" `
            -Status $(if($minLen -ge 14){"Pass"}elseif($minLen -ge 8){"Warning"}else{"Fail"}) `
            -Expected "14" -Actual "$minLen chars" -Severity $(if($minLen -lt 8){"Critical"}else{"High"}) -POCResult $poc
        Add-Finding -Category "Account Config" -CheckTitle "Password history" -CISRef "1.1.1" `
            -Status $(if($history -ne "None" -and [int]$history -ge 24){"Pass"}else{"Fail"}) `
            -Expected "24" -Actual $history -Severity "Medium"
    } catch {}

    # Password max/min age from secedit
    if ($secpolWorked) {
        $maxAge = if ($secpol -match "MaximumPasswordAge\s*=\s*(-?\d+)") { [int]$Matches[1] } else { -1 }
        $minAge = if ($secpol -match "MinimumPasswordAge\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
        Add-Finding -Category "Account Config" -CheckTitle "Password max age" -CISRef "1.1.2" `
            -Status $(if($maxAge -ge 1 -and $maxAge -le 365){"Pass"}else{"Fail"}) `
            -Expected "1-365 days" -Actual $(if($maxAge -eq -1){"Never expires"}else{"$maxAge days"}) `
            -Severity "High" -ExploitCmd $(if($maxAge -eq -1 -or $maxAge -eq 0){"Passwords never expire = persistent compromise"}else{""})
        Add-Finding -Category "Account Config" -CheckTitle "Password min age" -CISRef "1.1.3" `
            -Status $(if($minAge -ge 1){"Pass"}else{"Fail"}) -Expected "1+ days" -Actual "$minAge days" `
            -Severity "Medium" -Description "Prevents rapid password cycling to reuse old passwords."
    }

    # Stale/disabled accounts
    try { $locals = Get-LocalUser -ErrorAction SilentlyContinue
        $stale = $locals | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) }
        $neverLogon = $locals | Where-Object { $_.Enabled -and -not $_.LastLogon }
        $poc = "Enabled: $(($locals|Where-Object Enabled).Count)`nDisabled: $(($locals|Where-Object{-not $_.Enabled}).Count)`n"
        if ($stale) { $poc += "Stale (90d+): $(($stale|ForEach-Object{"$($_.Name) last=$($_.LastLogon)"}) -join ', ')`n" }
        if ($neverLogon) { $poc += "Never logged on: $(($neverLogon|ForEach-Object{$_.Name}) -join ', ')" }
        Add-Finding -Category "Account Config" -CheckTitle "Stale/inactive accounts" `
            -Status $(if($stale.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None stale >90 days" `
            -Actual "$(if($stale){"$($stale.Count) stale"}else{'None'}), $(if($neverLogon){"$($neverLogon.Count) never logged on"}else{'all active'})" `
            -Severity "Medium" -POCResult $poc -Remediation "Disable-LocalUser -Name ACCOUNT"
    } catch {}

    # Credential Manager
    try { $cm = cmdkey /list 2>$null
        $creds = ($cm | Select-String "Target:" | Measure-Object).Count
        Add-Finding -Category "Account Config" -CheckTitle "Credential Manager stored creds" `
            -Status $(if($creds -eq 0){"Pass"}else{"Warning"}) -Expected "Minimal" `
            -Actual "$creds stored credentials" -Severity "Medium" `
            -POCResult "$(($cm|Out-String).Trim())" `
            -ExploitCmd $(if($creds -gt 0){"mimikatz # vault::cred (extract stored creds)"}else{""})
    } catch {}

    # Blank password users
    try { $blankPw = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordRequired -eq $false }
        $poc = "PasswordRequired=False: $(if($blankPw){($blankPw|ForEach-Object{$_.Name}) -join ', '}else{'None'})"
        Add-Finding -Category "Account Config" -CheckTitle "Blank password accounts" `
            -Status $(if($blankPw.Count -eq 0){"Pass"}else{"Fail"}) -Expected "0" `
            -Actual $(if($blankPw.Count -eq 0){"None"}else{"$($blankPw.Count): $(($blankPw|ForEach-Object{$_.Name}) -join ', ')"}) `
            -Severity "Critical" -POCResult $poc -ExploitCmd $(if($blankPw.Count -gt 0){"runas /user:NAME cmd"}else{""})
    } catch {}

    # Admin group
    try { $ag = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        Add-Finding -Category "Account Config" -CheckTitle "Local admin count" `
            -Status $(if($ag.Count -le 2){"Pass"}else{"Warning"}) -Expected "2 or fewer" `
            -Actual "$($ag.Count): $(($ag|ForEach-Object{$_.Name}) -join ', ')" -Severity "Medium" `
            -Remediation "Remove unnecessary admins." -POCResult ((net localgroup Administrators 2>$null) -join "`n")
    } catch {}

    # UAC
    $uacEnable = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    $uacConsent = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    $uacSecure = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    Add-Finding -Category "Account Config" -CheckTitle "UAC configuration" -CISRef "2.3.17" `
        -Status $(if($uacEnable -eq 1 -and $uacConsent -le 2 -and $uacSecure -eq 1){"Pass"}elseif($uacEnable -eq 1){"Warning"}else{"Fail"}) `
        -Expected "Enabled+Consent+SecureDesktop" -Actual "UAC=$uacEnable Consent=$uacConsent Secure=$uacSecure" `
        -Severity $(if($uacEnable -ne 1){"Critical"}else{"High"}) `
        -POCResult "EnableLUA=$uacEnable`nConsentPromptBehaviorAdmin=$uacConsent`nPromptOnSecureDesktop=$uacSecure"

    # AutoLogon
    $autoPass = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    Add-Finding -Category "Account Config" -CheckTitle "AutoLogon credentials" -CISRef "2.3.7.4" `
        -Status $(if($autoPass){"Fail"}else{"Pass"}) -Expected "No stored password" `
        -Actual $(if($autoPass){"CLEARTEXT PASSWORD STORED"}else{"Not configured"}) -Severity "Critical" `
        -ExploitCmd $(if($autoPass){"reg query HKLM\...\Winlogon (plaintext password)"}else{""})

    # Cached logons
    $cached = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10"
    Add-Finding -Category "Account Config" -CheckTitle "Cached domain logons" -CISRef "2.3.7.5" `
        -Status $(if([int]$cached -le 4){"Pass"}else{"Warning"}) -Expected "4 or fewer" `
        -Actual $cached -Severity "Medium"
}


# ============================================================================
# 9. PRIVILEGE ESCALATION VECTORS
# ============================================================================
function Test-PrivilegeEscalation {
    Write-Section "9. Privilege Escalation"

    # Token privileges
    try {
        $wp = whoami /priv 2>$null
        $dangerous = @("SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege","SeDebugPrivilege",
            "SeBackupPrivilege","SeRestorePrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege","SeTcbPrivilege")
        $found = @(); foreach ($d in $dangerous) { if ($wp -match $d) { $found += $d } }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "Dangerous token privileges" `
            -Status $(if($found.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($found.Count -eq 0){"None"}else{"$($found.Count): $($found -join ', ')"}) `
            -Severity "Critical" -POCResult "whoami /priv:`n$(($wp|Out-String).Trim())"
    } catch {}

    # SYSTEM scheduled tasks writable
    try {
        $st = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|LocalSystem" -and $_.State -ne "Disabled" }
        $vuln = @(); $dq = [string][char]34
        foreach ($t in $st|Select-Object -First 50) { foreach ($a in $t.Actions) {
            if ($a.Execute) { $te = $a.Execute -replace $dq,''
                if ($te -and (Test-Path $te -ErrorAction SilentlyContinue)) {
                    $ta = Get-Acl $te -ErrorAction SilentlyContinue
                    if ($ta) { $w = $ta.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" }; if ($w) { $vuln += "$($t.TaskName): $te" } } } } } }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "SYSTEM tasks with writable binaries" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None (sampled 50)"}else{($vuln|Select-Object -First 5) -join '; '}) `
            -Severity "Critical" -POCResult "SYSTEM tasks: $($st.Count)`n$(if($vuln.Count -gt 0){$vuln -join "`n"}else{'None writable'})"
    } catch {}

    # HKLM Run writable
    $writableRun = @()
    foreach ($k in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
        if (Test-Path $k) { try { $a = Get-Acl $k -ErrorAction Stop
            $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                $_.RegistryRights -match "(WriteKey|SetValue|FullControl)" -and $_.AccessControlType -eq "Allow" }
            if ($w) { $writableRun += $k }
        } catch {} } }
    Add-Finding -Category "Privilege Escalation" -CheckTitle "HKLM Run writable" `
        -Status $(if($writableRun.Count -eq 0){"Pass"}else{"Fail"}) -Expected "Restricted" `
        -Actual $(if($writableRun.Count -eq 0){"Properly restricted"}else{"$($writableRun.Count) writable"}) -Severity "Critical"

    # IFEO + WMI persistence
    $ifeoHijacks = @()
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) { Get-ChildItem $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
        if ($dbg.Debugger) { $ifeoHijacks += "$($_.PSChildName): $($dbg.Debugger)" } } }
    Add-Finding -Category "Privilege Escalation" -CheckTitle "IFEO debugger hijacks" `
        -Status $(if($ifeoHijacks.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($ifeoHijacks.Count -eq 0){"None"}else{$ifeoHijacks -join '; '}) -Severity "High"

    try { $wmi = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
        Add-Finding -Category "Privilege Escalation" -CheckTitle "WMI persistence" `
            -Status $(if($wmi.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None" `
            -Actual "$($wmi.Count) consumers" -Severity "High" `
            -POCResult "WMI: $(if($wmi.Count -gt 0){($wmi|ForEach-Object{"$($_.Name)"}) -join ', '}else{'None'})"
    } catch {}

    # DLL hijacking - KnownDLLs gaps
    try { $kd = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -ErrorAction Stop
        $kdList = $kd.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { $_.Value }
        $commonDLLs = @("version.dll","dbghelp.dll","wer.dll","profapi.dll","mswsock.dll")
        $missing = $commonDLLs | Where-Object { $_ -notin $kdList }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "KnownDLLs hijackable" `
            -Status $(if($missing.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Common DLLs protected" `
            -Actual "$($missing.Count) common DLLs not in KnownDLLs: $($missing -join ', ')" `
            -Severity "Medium" -POCResult "KnownDLLs: $($kdList.Count) entries`nNot protected: $($missing -join ', ')" `
            -ExploitCmd "copy malicious.dll PATH\version.dll (DLL sideloading)"
    } catch {}

    # Named pipes - PrintSpoofer vector
    try { $pipes = @([System.IO.Directory]::GetFiles("\\.\pipe\"))
        $spoolerPipe = $pipes | Where-Object { $_ -match "spoolss" }
        $poc = "Total pipes: $($pipes.Count)`n$(($pipes|Select-Object -First 15|ForEach-Object{[System.IO.Path]::GetFileName($_)}) -join "`n")"
        Add-Finding -Category "Privilege Escalation" -CheckTitle "Named pipes (PrintSpoofer vector)" `
            -Status $(if($spoolerPipe){"Warning"}else{"Pass"}) -Expected "spoolss not exposed" `
            -Actual "$($pipes.Count) pipes $(if($spoolerPipe){'(spoolss PRESENT)'}else{'(no spoolss)'})" `
            -Severity "High" -POCResult $poc `
            -ExploitCmd $(if($spoolerPipe){"PrintSpoofer.exe -i -c cmd (SYSTEM via SeImpersonatePrivilege)"}else{""})
    } catch {}

    # COM hijacking
    try { $comHijack = @()
        foreach ($clsid in @("{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}","{BCDE0395-E52F-467C-8E3D-C4579291692E}")) {
            $hkcu = Get-RegValue "HKCU\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" "(default)"
            if ($hkcu) { $comHijack += "$clsid -> $hkcu" }
        }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "COM object hijacking" `
            -Status $(if($comHijack.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($comHijack.Count -eq 0){"None detected"}else{$comHijack -join '; '}) `
            -Severity "High" -POCResult $(if($comHijack.Count -gt 0){$comHijack -join "`n"}else{""})
    } catch {}

    # AppLocker / WDAC
    try { $ap = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $rc = ($ap.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        Add-Finding -Category "Privilege Escalation" -CheckTitle "AppLocker" `
            -Status $(if($rc -gt 0){"Pass"}else{"Fail"}) -Expected "Rules configured" `
            -Actual $(if($rc -gt 0){"$rc rules"}else{"Not configured"}) -Severity "High"
    } catch { Add-Finding -Category "Privilege Escalation" -CheckTitle "AppLocker" -Status "Fail" -Actual "Not configured" -Severity "High" `
        -ExploitCmd "Run any binary from any writable path" }

    # PSv2
    try { $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $psv2State = if ($psv2.State) { $psv2.State.ToString() } else { "Unknown" }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "PowerShell v2" -CISRef "18.10.40.1" `
            -Status $(if($psv2State -match "Disabled"){"Pass"}else{"Fail"}) -Expected "Disabled" `
            -Actual $(if($psv2State -match "Disabled"){$psv2State}else{"Enabled"}) -Severity "High" `
            -ExploitCmd "powershell -version 2 (bypasses AMSI + ScriptBlock logging)"
    } catch {}
}


# ============================================================================
# 10. LATERAL MOVEMENT & 11. NETWORK CONFIGURATION
# ============================================================================
function Test-NetworkAndLateral {
    Write-Section "10/11. Network & Lateral Movement"

    # SMB signing
    $smbServer = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    $smbClient = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 0
    Add-Finding -Category "Network Config" -CheckTitle "SMB server signing" -CISRef "2.3.9.2" `
        -Status $(if($smbServer -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $smbServer -Severity "High" `
        -ExploitCmd "ntlmrelayx.py (relay without signing)"
    Add-Finding -Category "Network Config" -CheckTitle "SMB client signing" -CISRef "2.3.9.1" `
        -Status $(if($smbClient -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $smbClient -Severity "High"

    # SMBv1
    $smbv1Client = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4
    $smbv1Server = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 1
    $smbv1On = $smbv1Client -ne 4 -or $smbv1Server -eq 1
    Add-Finding -Category "Network Config" -CheckTitle "SMBv1 protocol" -CISRef "18.4.9" `
        -Status $(if(-not $smbv1On){"Pass"}else{"Fail"}) -Expected "Disabled" `
        -Actual "Client=$(if($smbv1Client -eq 4){'Off'}else{'On'}), Server=$(if($smbv1Server -eq 0){'Off'}else{'On'})" `
        -Severity "Critical" -ExploitCmd $(if($smbv1On){"EternalBlue (MS17-010)"}else{""})

    # LLMNR
    $llmnr = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
    Add-Finding -Category "Network Config" -CheckTitle "LLMNR" -CISRef "18.6.4.1" `
        -Status $(if($llmnr -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $llmnr -Severity "High" `
        -ExploitCmd "Responder -I eth0 (capture NTLMv2)"

    # NetBIOS
    try { $nics = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
        $nbtOn = $false; foreach ($n in $nics) { $v = Get-ItemProperty $n.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
            if ($null -eq $v -or $v.NetbiosOptions -ne 2) { $nbtOn = $true; break } }
        Add-Finding -Category "Network Config" -CheckTitle "NetBIOS over TCP/IP" `
            -Status $(if(-not $nbtOn){"Pass"}else{"Warning"}) -Expected "Disabled" `
            -Actual $(if($nbtOn){"Enabled"}else{"Disabled"}) -Severity "Medium" `
            -ExploitCmd "Responder NBT-NS poisoning"
    } catch {}

    # NTLM auth level
    $lmLevel = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    Add-Finding -Category "Network Config" -CheckTitle "LAN Manager auth level" -CISRef "2.3.11.7" `
        -Status $(if($lmLevel -ge 5){"Pass"}elseif($lmLevel -ge 3){"Warning"}else{"Fail"}) `
        -Expected "5 (NTLMv2 only)" -Actual "Level $lmLevel" -Severity $(if($lmLevel -lt 3){"Critical"}else{"High"}) `
        -POCResult "LmCompatibilityLevel=$lmLevel"

    # WinRM / RDP
    try { $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        Add-Finding -Category "Network Config" -CheckTitle "WinRM" `
            -Status $(if($winrm.Status -ne "Running"){"Pass"}else{"Warning"}) `
            -Expected "Stopped" -Actual $winrm.Status -Severity "Medium"
    } catch {}

    $rdpDeny = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    $rdpNLA = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    Add-Finding -Category "Network Config" -CheckTitle "RDP NLA" -CISRef "18.10.57.3.9.1" `
        -Status $(if($rdpDeny -eq 1 -or $rdpNLA -eq 1){"Pass"}else{"Fail"}) `
        -Expected "NLA required" -Actual "RDP=$(if($rdpDeny -eq 0){'On'}else{'Off'}), NLA=$rdpNLA" -Severity "High"

    # Wi-Fi stored passwords
    try { $profiles2 = (netsh wlan show profiles 2>$null) | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
        $wifiCreds = @()
        foreach ($pn in $profiles2 | Select-Object -First 10) {
            $detail = netsh wlan show profile name="$pn" key=clear 2>$null
            $keyLine = $detail | Select-String "Key Content\s*:\s*(.+)"
            if ($keyLine) { $wifiCreds += "$pn = $($keyLine.Matches[0].Groups[1].Value.Trim())" }
        }
        Add-Finding -Category "Lateral Movement" -CheckTitle "Wi-Fi stored passwords" `
            -Status $(if($wifiCreds.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None extractable" `
            -Actual "$($wifiCreds.Count) passwords recovered" -Severity "High" `
            -POCResult "$(if($wifiCreds.Count -gt 0){$wifiCreds -join "`n"}else{'No cleartext keys found'})" `
            -ExploitCmd "netsh wlan show profile name=SSID key=clear" `
            -Description "Stored Wi-Fi passwords enable rogue AP and lateral movement."
    } catch {}

    # DPAPI master keys
    $dpapiSys = "C:\Windows\System32\Microsoft\Protect"
    $dpapiUser = "$env:APPDATA\Microsoft\Protect"
    $dpapiCount = 0
    foreach ($dp in @($dpapiSys,$dpapiUser)) { if (Test-Path $dp) {
        try { $dpapiCount += (Get-ChildItem $dp -Recurse -File -ErrorAction SilentlyContinue).Count } catch {} } }
    Add-Finding -Category "Lateral Movement" -CheckTitle "DPAPI master keys" `
        -Status $(if($dpapiCount -eq 0){"Pass"}else{"Info"}) -Expected "Protected by Credential Guard" `
        -Actual "$dpapiCount DPAPI files" -Severity "Medium" `
        -POCResult "System DPAPI: $dpapiSys`nUser DPAPI: $dpapiUser`nTotal files: $dpapiCount" `
        -ExploitCmd "mimikatz # dpapi::masterkey (decrypt stored credentials)" `
        -Remediation "Enable Credential Guard to protect DPAPI."

    # RDP saved connections
    $rdpFiles = @()
    try { Get-ChildItem "$env:USERPROFILE\Documents" -Filter "*.rdp" -Recurse -ErrorAction SilentlyContinue -Depth 2 | ForEach-Object { $rdpFiles += $_.FullName } } catch {}
    $rdpReg = Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
    Add-Finding -Category "Lateral Movement" -CheckTitle "RDP saved connections" `
        -Status $(if($rdpFiles.Count -eq 0 -and (-not $rdpReg -or $rdpReg.Count -eq 0)){"Pass"}else{"Warning"}) `
        -Expected "None" -Actual "Files=$($rdpFiles.Count), Registry=$(if($rdpReg){$rdpReg.Count}else{0})" `
        -Severity "Medium" -POCResult "RDP files: $(if($rdpFiles.Count -gt 0){$rdpFiles -join "`n"}else{'None'})`nRegistry servers: $(if($rdpReg){($rdpReg|ForEach-Object{$_.PSChildName}) -join ', '}else{'None'})" `
        -ExploitCmd $(if($rdpReg){"Stored RDP creds + NTLMv2 hashes via rogue RDP server"}else{""})

    # PuTTY saved sessions
    $putty = Get-ChildItem "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue
    Add-Finding -Category "Lateral Movement" -CheckTitle "PuTTY saved sessions" `
        -Status $(if(-not $putty -or $putty.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None" `
        -Actual $(if($putty){"$($putty.Count): $(($putty|ForEach-Object{$_.PSChildName}) -join ', ')"}else{"None"}) `
        -Severity "Medium" -ExploitCmd $(if($putty){"PuTTY sessions may contain saved proxy creds"}else{""})

    # WinSCP stored credentials
    $winscp = Get-ChildItem "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions" -ErrorAction SilentlyContinue
    Add-Finding -Category "Lateral Movement" -CheckTitle "WinSCP saved sessions" `
        -Status $(if(-not $winscp -or $winscp.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($winscp){"$($winscp.Count) sessions"}else{"None"}) `
        -Severity "High" -ExploitCmd $(if($winscp){"WinSCP passwords are weakly encrypted (decrypt with winscppasswd)"}else{""})

    # VPN / Network profiles
    try { $wifiProfiles = netsh wlan show profiles 2>$null
        $pc = ($wifiProfiles | Select-String "All User Profile" | Measure-Object).Count
        Add-Finding -Category "Network Config" -CheckTitle "Wi-Fi profiles stored" `
            -Status $(if($pc -eq 0){"Pass"}else{"Warning"}) -Expected "Minimal" `
            -Actual "$pc profiles" -Severity "Medium" `
            -POCResult "$(($wifiProfiles|Out-String).Trim())" `
            -ExploitCmd "netsh wlan show profile name=SSID key=clear"
    } catch {}

    # Network shares
    try { $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("ADMIN$","C$","IPC$","print$") }
        $open = @(); foreach ($s in $shares) { $sa = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
            if ($sa | Where-Object { $_.AccountName -match "Everyone" }) { $open += "$($s.Name)" } }
        Add-Finding -Category "Network Config" -CheckTitle "Shares accessible to Everyone" `
            -Status $(if($open.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($open.Count -eq 0){"None"}else{$open -join ', '}) -Severity "High"
    } catch {}

    # Anonymous restrictions
    $restrictAnon = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    $restrictSAM = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1
    Add-Finding -Category "Network Config" -CheckTitle "Anonymous restrictions" -CISRef "2.3.10" `
        -Status $(if($restrictAnon -ge 1 -and $restrictSAM -eq 1){"Pass"}else{"Warning"}) `
        -Expected "Both restricted" -Actual "Anon=$restrictAnon, SAM=$restrictSAM" -Severity "Medium"

    # DNS configuration
    try { $dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 }
        $poc = ($dns|Select-Object -First 6|ForEach-Object{"$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')"}) -join "`n"
        Add-Finding -Category "Network Config" -CheckTitle "DNS configuration" -Status "Info" `
            -Actual "$(($dns|Select-Object -Unique InterfaceAlias).Count) interfaces with DNS" `
            -Severity "Informational" -POCResult $poc
    } catch {}

    # WPAD / Proxy
    $wpad = Get-RegValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoConfigURL"
    $proxy = Get-RegValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
    $proxyEnable = Get-RegValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
    Add-Finding -Category "Network Config" -CheckTitle "Proxy/WPAD settings" `
        -Status $(if($wpad){"Warning"}else{"Info"}) -Expected "No WPAD (mitm risk)" `
        -Actual "WPAD=$(if($wpad){$wpad}else{'None'}), Proxy=$(if($proxy){$proxy}else{'None'}), Enabled=$proxyEnable" `
        -Severity $(if($wpad){"Medium"}else{"Low"}) -ExploitCmd $(if($wpad){"WPAD poisoning via Responder for credential capture"}else{""})

    # Null session pipes
    $nullPipes = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    Add-Finding -Category "Network Config" -CheckTitle "Null session pipes" -CISRef "2.3.10.8" `
        -Status $(if(-not $nullPipes -or $nullPipes.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "Empty" -Actual $(if($nullPipes -and $nullPipes.Count -gt 0){"$($nullPipes -join ', ')"}else{"Empty"}) `
        -Severity "Medium"

    # IPv6
    try { $ipv6 = Get-NetAdapterBinding -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object Enabled
        Add-Finding -Category "Network Config" -CheckTitle "IPv6" `
            -Status $(if($ipv6.Count -eq 0){"Pass"}else{"Info"}) -Expected "Disabled if not needed" `
            -Actual "$($ipv6.Count) adapters" -Severity "Low" -Description "IPv6 enables mitm6 attacks."
    } catch {}

    # Listening ports
    try {
        $l = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" } | Sort-Object LocalPort -Unique
        $poc = ($l|Select-Object -First 20|ForEach-Object{ $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "$($_.LocalAddress):$($_.LocalPort) $($p.ProcessName)" }) -join "`n"
        Add-Finding -Category "Network Config" -CheckTitle "Exposed listening ports" -Status "Info" `
            -Actual "$($l.Count) ports" -Severity "Informational" -POCResult $poc
    } catch {}
}


# ============================================================================
# 12. LOGGING & AUDITING
# ============================================================================
function Test-LoggingAuditing {
    Write-Section "12. Logging & Auditing"

    # Audit policy
    $auditpol = auditpol /get /category:* 2>$null
    $checks = @(
        @{Sub="Credential Validation";CIS="17.1.1";Expect="Success and Failure";Sev="High"},
        @{Sub="Security Group Management";CIS="17.2.5";Expect="Success";Sev="Medium"},
        @{Sub="User Account Management";CIS="17.2.6";Expect="Success and Failure";Sev="Medium"},
        @{Sub="Process Creation";CIS="17.3.1";Expect="Success";Sev="High"},
        @{Sub="Logon";CIS="17.5.3";Expect="Success and Failure";Sev="High"},
        @{Sub="Logoff";CIS="17.5.2";Expect="Success";Sev="Medium"},
        @{Sub="Special Logon";CIS="17.5.6";Expect="Success";Sev="High"},
        @{Sub="Removable Storage";CIS="17.6.4";Expect="Success and Failure";Sev="Medium"},
        @{Sub="Audit Policy Change";CIS="17.7.1";Expect="Success";Sev="Medium"},
        @{Sub="Sensitive Privilege Use";CIS="17.8.1";Expect="Success and Failure";Sev="Medium"},
        @{Sub="Security State Change";CIS="17.9.3";Expect="Success";Sev="Medium"},
        @{Sub="System Integrity";CIS="17.9.5";Expect="Success and Failure";Sev="Medium"},
        @{Sub="Authentication Policy Change";CIS="17.7.2";Expect="Success";Sev="Medium"},
        @{Sub="Security System Extension";CIS="17.9.4";Expect="Success";Sev="Medium"}
    )
    foreach ($c in $checks) {
        $line = $auditpol | Select-String "^\s+$($c.Sub)\s" | Select-Object -First 1
        $actual = if ($line) { ($line -split "\s{2,}")[-1].Trim() } else { "Not found" }
        $pass = $actual -match "Success" -and ($c.Expect -notmatch "Failure" -or $actual -match "Failure")
        Add-Finding -Category "Logging & Auditing" -CheckTitle "$($c.Sub)" -CISRef $c.CIS `
            -Status $(if($pass){"Pass"}else{"Fail"}) -Expected $c.Expect -Actual $actual -Severity $c.Sev `
            -POCResult "auditpol: $($c.Sub) = $actual" `
            -Remediation "auditpol /set /subcategory:`"$($c.Sub)`" /success:enable $(if($c.Expect -match 'Failure'){'/failure:enable'})"
    }

    # Command line logging
    $cmdLine = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-Finding -Category "Logging & Auditing" -CheckTitle "Command line in process events" -CISRef "18.9.3.1" `
        -Status $(if($cmdLine -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $cmdLine -Severity "High"

    # PowerShell logging
    $sbLog = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    $trans = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    $modLog = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 0
    $score = ([int]($sbLog -eq 1)) + ([int]($trans -eq 1)) + ([int]($modLog -eq 1))
    Add-Finding -Category "Logging & Auditing" -CheckTitle "PowerShell logging" -CISRef "18.10.40.2" `
        -Status $(if($score -ge 2){"Pass"}elseif($score -eq 1){"Warning"}else{"Fail"}) `
        -Expected "All 3" -Actual "Score=$score/3 (SB=$sbLog Trans=$trans Mod=$modLog)" -Severity "High"

    # Event log sizes
    foreach ($log in @(
        @{N="Security";Min=1024000;CIS="18.9.27.2.1"},
        @{N="Application";Min=32768;CIS="18.9.27.1.1"},
        @{N="System";Min=32768;CIS="18.9.27.3.1"}
    )) { try { $el = Get-WinEvent -ListLog $log.N -ErrorAction Stop
        Add-Finding -Category "Logging & Auditing" -CheckTitle "$($log.N) log max size" -CISRef $log.CIS `
            -Status $(if($el.MaximumSizeInBytes -ge $log.Min){"Pass"}else{"Fail"}) `
            -Expected "$([math]::Round($log.Min/1024))KB" -Actual "$([math]::Round($el.MaximumSizeInBytes/1024))KB" -Severity "Medium"
    } catch {} }
}


# ============================================================================
# 13. SYSTEM HARDENING
# ============================================================================
function Test-SystemHardening {
    Write-Section "13. System Hardening"

    # DEP
    try { $dep = (Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
        $m = @{0="Off";1="Essential";2="OptOut";3="AlwaysOn"}
        Add-Finding -Category "System Hardening" -CheckTitle "DEP/NX" `
            -Status $(if($dep -ge 2){"Pass"}else{"Warning"}) -Expected "2+" -Actual "$dep ($($m[[int]$dep]))" -Severity "Medium"
    } catch {}

    # ASLR
    $aslr = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" 1
    Add-Finding -Category "System Hardening" -CheckTitle "ASLR" `
        -Status $(if($aslr -ne 0){"Pass"}else{"Fail"}) -Expected "Enabled" `
        -Actual $(if($null -eq $aslr){"Default"}else{$aslr}) -Severity "Medium"

    # Spectre
    $specCtrl = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
    Add-Finding -Category "System Hardening" -CheckTitle "Spectre mitigations" `
        -Status $(if($null -ne $specCtrl){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($null -eq $specCtrl){"Not set"}else{$specCtrl}) -Severity "Medium"

    # PS Execution Policy
    $ep = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    Add-Finding -Category "System Hardening" -CheckTitle "PS Execution Policy" `
        -Status $(if($ep -in @("Restricted","AllSigned")){"Pass"}else{"Warning"}) `
        -Expected "AllSigned" -Actual $ep -Severity "Medium" `
        -POCResult "$((Get-ExecutionPolicy -List|Out-String).Trim())"

    # WSL
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    Add-Finding -Category "System Hardening" -CheckTitle "WSL" `
        -Status $(if($wsl){"Warning"}else{"Pass"}) -Expected "Not installed" `
        -Actual $(if($wsl){"Installed"}else{"No"}) -Severity "Medium" `
        -ExploitCmd "WSL bypasses AppLocker/AMSI/AV"

    # LDAP signing
    $ldapSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" 1
    Add-Finding -Category "System Hardening" -CheckTitle "LDAP client signing" -CISRef "2.3.11.8" `
        -Status $(if($ldapSign -ge 1){"Pass"}else{"Fail"}) -Expected "1+" -Actual $ldapSign -Severity "High"

    # Machine inactivity
    $inactivity = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 0
    Add-Finding -Category "System Hardening" -CheckTitle "Machine inactivity limit" -CISRef "2.3.7.3" `
        -Status $(if($inactivity -gt 0 -and $inactivity -le 900){"Pass"}else{"Fail"}) `
        -Expected "900 sec" -Actual $(if($inactivity -eq 0){"Not set"}else{"$inactivity sec"}) -Severity "Medium"

    # WDAC (Windows Defender Application Control)
    try { $wdacPolicies = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction SilentlyContinue
        $ciPolicies = Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -ErrorAction SilentlyContinue
        $wdacActive = ($ciPolicies -and $ciPolicies.Count -gt 0) -or ($wdacPolicies -and $wdacPolicies.CodeIntegrityPolicyEnforcementStatus -gt 0)
        Add-Finding -Category "System Hardening" -CheckTitle "WDAC" `
            -Status $(if($wdacActive){"Pass"}else{"Warning"}) -Expected "Active" `
            -Actual $(if($wdacActive){"Policy deployed"}else{"Not deployed"}) -Severity "Medium" `
            -Remediation "Deploy WDAC base policy."
    } catch { Add-Finding -Category "System Hardening" -CheckTitle "WDAC" -Status "Warning" -Actual "Cannot query" -Severity "Medium" }

    # BITS persistence
    try { $bits = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -ne "Transferred" })
        Add-Finding -Category "System Hardening" -CheckTitle "BITS transfer jobs" `
            -Status $(if($bits.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None" `
            -Actual "$($bits.Count) active" -Severity "Medium"
    } catch {}

    # Credential files
    $credFiles = @()
    foreach ($d in @("$env:USERPROFILE","C:\Users\Public","C:\ProgramData")) {
        if (Test-Path $d) { try { Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue -Depth 3 |
            Where-Object { $_.Name -match "(password|cred|secret|\.rdp|\.vnc|web\.config)" -and $_.Length -lt 1MB } |
            Select-Object -First 10 | ForEach-Object {
            try { $c = Get-Content $_.FullName -TotalCount 50 -ErrorAction Stop
                if (($c -join "`n") -match '(?i)(password|passwd|pwd|credential)\s*[:=]') { $credFiles += $_.FullName }
            } catch {} }
        } catch {} } }
    Add-Finding -Category "System Hardening" -CheckTitle "Cleartext credential files" `
        -Status $(if($credFiles.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($credFiles.Count -eq 0){"None"}else{"$($credFiles.Count): $(($credFiles|Select-Object -First 3) -join '; ')"}) `
        -Severity "High"

    # Browser credential DBs
    $browsers = @()
    foreach ($db in @(
        @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data";B="Chrome"},
        @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data";B="Edge"}
    )) { if (Test-Path $db.P) { $browsers += "$($db.B) ($((Get-Item $db.P).Length)b)" } }
    Add-Finding -Category "System Hardening" -CheckTitle "Browser credential databases" `
        -Status $(if($browsers.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Awareness" `
        -Actual $(if($browsers.Count -eq 0){"None"}else{$browsers -join ', '}) -Severity "Medium"
}


# ============================================================================
# ATTACK PATH SUMMARY
# ============================================================================
function Test-AttackSummary {
    Write-Section "Attack Path Summary"
    $fails = $Script:Results | Where-Object Status -eq "Fail"
    $crits = ($fails | Where-Object Severity -eq "Critical").Count
    $highs = ($fails | Where-Object Severity -eq "High").Count
    $paths = $fails | ForEach-Object { "[$($_.Severity)] $($_.CheckTitle)" }
    if ($paths.Count -gt 0) {
        Add-Finding -Category "Attack Path Summary" -CheckTitle "FINDINGS: Critical=$crits High=$highs Total=$($paths.Count)" `
            -Status "Fail" -Expected "0" -Actual ($paths -join " | ") -Severity "Critical" -Remediation "Address Critical first."
    } else {
        Add-Finding -Category "Attack Path Summary" -CheckTitle "SUMMARY" -Status "Pass" -Actual "No critical findings" -Severity "Informational"
    }
}

# ============================================================================
# HTML REPORT
# ============================================================================
function Generate-Report {
    Write-Section "Generating Report"
    $end = Get-Date; $dur = $end - $Script:StartTime
    $total = $Script:Results.Count
    $pass = ($Script:Results|Where-Object Status -eq "Pass").Count
    $fail = ($Script:Results|Where-Object Status -eq "Fail").Count
    $warn = ($Script:Results|Where-Object Status -eq "Warning").Count
    $pocN = ($Script:Results|Where-Object{$_.POCResult -ne ""}).Count
    $comp = if(($pass+$fail) -gt 0){[math]::Round(($pass/($pass+$fail))*100,1)}else{0}
    $cats = $Script:Results | Group-Object Category | Sort-Object Name
    $ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $rp = Join-Path $OutputPath "Build_Review_${Script:ComputerName}_$ts.html"
    $compCol = if($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Build Review - $Script:ComputerName</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.ctr{max-width:1400px;margin:0 auto;padding:20px}
.hdr{background:linear-gradient(135deg,#0c1929,#1a0c29);border-radius:12px;padding:28px;margin-bottom:22px;border:1px solid #4c1d95}
.hdr h1{font-size:22px;color:#c4b5fd}.hdr .sub{color:#94a3b8;font-size:13px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:16px}
.mi{background:#1e293b;padding:9px 13px;border-radius:7px;border:1px solid #334155}
.mi .lb{font-size:10px;text-transform:uppercase;color:#64748b}.mi .vl{font-size:14px;color:#f1f5f9;font-weight:600}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:22px}
.sc{background:#1e293b;border-radius:9px;padding:16px;text-align:center;border:1px solid #334155}
.sc .n{font-size:28px;font-weight:700}.sc .l{font-size:10px;color:#94a3b8;text-transform:uppercase}
.sc.p .n{color:#4ade80}.sc.f .n{color:#f87171}.sc.w .n{color:#fbbf24}.sc.c .n{color:$compCol}.sc.poc .n{color:#a78bfa}
.cat{background:#1e293b;border-radius:9px;margin-bottom:12px;border:1px solid #334155;overflow:hidden}
.ch{padding:13px 17px;cursor:pointer;display:flex;justify-content:space-between;align-items:center}
.ch:hover{background:#253347}.ch h3{font-size:14px;color:#f1f5f9}
.cs span{font-size:10px;padding:2px 7px;border-radius:9px;font-weight:600;margin-left:3px}
.cp{background:#14532d;color:#4ade80}.cf{background:#7f1d1d;color:#f87171}.cw{background:#78350f;color:#fbbf24}
.cb{display:none}.cb.open{display:block}
table{width:100%;border-collapse:collapse;font-size:11px}
th{background:#0f172a;padding:7px 9px;text-align:left;color:#94a3b8;font-size:9px;text-transform:uppercase}
td{padding:7px 9px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover td{background:#162032}
.b{padding:2px 7px;border-radius:7px;font-size:9px;font-weight:700;display:inline-block;min-width:42px;text-align:center}
.sP{background:#14532d;color:#4ade80}.sF{background:#7f1d1d;color:#f87171}
.sW{background:#78350f;color:#fbbf24}.sI{background:#1e3a5f;color:#60a5fa}.sE{background:#581845;color:#e879f9}
.svC{color:#f87171;font-weight:700}.svH{color:#fb923c;font-weight:600}.svM{color:#fbbf24}.svL{color:#94a3b8}.svN{color:#64748b}
.desc{color:#64748b;font-size:10px;margin-top:2px}
.rem{color:#34d399;font-size:10px;margin-top:3px;padding:3px 7px;background:#052e16;border-radius:3px}
.rem::before{content:"FIX: ";font-weight:700}
.exp{color:#fb923c;font-size:10px;margin-top:3px;font-family:'Cascadia Code',Consolas,monospace;padding:3px 7px;background:#1c1306;border-radius:3px;white-space:pre-wrap;word-break:break-all}
.exp::before{content:"EXPLOIT: ";font-weight:700}
.poc{color:#c4b5fd;font-size:10px;margin-top:4px;padding:5px 8px;background:#1a1030;border:1px solid #6d28d9;border-radius:3px;white-space:pre-wrap;font-family:'Cascadia Code',Consolas,monospace;max-height:250px;overflow-y:auto}
.poc::before{content:"EVIDENCE ";font-weight:700;color:#a78bfa}
.crit-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:9px;padding:16px;margin-bottom:18px}
.crit-box h3{color:#f87171;margin-bottom:8px;font-size:14px}
.crit-box ul{list-style:none}.crit-box li{padding:4px 0;color:#fca5a5;font-size:11px;border-bottom:1px solid #2d1318}
.crit-box li:last-child{border-bottom:none}.crit-box li::before{content:"! ";font-weight:bold}
.tb{background:#334155;border:none;color:#94a3b8;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:10px;margin-bottom:8px}
.tb:hover{background:#475569;color:#f1f5f9}
.ftr{text-align:center;padding:16px;color:#475569;font-size:10px}
</style></head>
<body><div class="ctr">
<div class="hdr"><h1>Windows Build Review + CIS Benchmark</h1>
<div class="sub">All 13 assessment areas + CIS L1/L2 + POC evidence | Admin context</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:ComputerName</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OSVersion</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:OSBuild</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:CurrentUser</div></div>
<div class="mi"><div class="lb">Domain</div><div class="vl">$(if($Script:IsDomainJoined){'Joined'}else{'Standalone'})</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
<div class="mi"><div class="lb">Duration</div><div class="vl">$([math]::Round($dur.TotalSeconds,1))s</div></div>
<div class="mi"><div class="lb">Evidence</div><div class="vl" style="color:#a78bfa">$pocN items</div></div>
</div></div>
<div class="dash">
<div class="sc"><div class="n">$total</div><div class="l">Checks</div></div>
<div class="sc p"><div class="n">$pass</div><div class="l">Pass</div></div>
<div class="sc f"><div class="n">$fail</div><div class="l">Fail</div></div>
<div class="sc w"><div class="n">$warn</div><div class="l">Warn</div></div>
<div class="sc c"><div class="n">${comp}%</div><div class="l">Score</div></div>
<div class="sc poc"><div class="n">$pocN</div><div class="l">Evidence</div></div>
</div>
"@

    $cf = $Script:Results | Where-Object { $_.Status -eq "Fail" -and $_.Severity -in @("Critical","High") } | Sort-Object Severity
    if ($cf.Count -gt 0) {
        $html += "<div class=`"crit-box`"><h3>Critical/High Findings ($($cf.Count))</h3><ul>`n"
        foreach ($f in $cf) { $html += "        <li><strong>[$($f.Severity)]</strong> $($f.Category) - $(ConvertTo-HtmlSafe $f.CheckTitle)</li>`n" }
        $html += "    </ul></div>`n"
    }
    $html += "<button class=`"tb`" onclick=`"document.querySelectorAll('.cb').forEach(e=>e.classList.toggle('open'))`">Toggle All</button>`n"

    foreach ($cat in $cats) {
        $cP=($cat.Group|Where-Object Status -eq "Pass").Count;$cF=($cat.Group|Where-Object Status -eq "Fail").Count;$cW=($cat.Group|Where-Object Status -eq "Warning").Count
        $html += "<div class=`"cat`"><div class=`"ch`" onclick=`"this.nextElementSibling.classList.toggle('open')`">"
        $html += "<h3>$($cat.Name) ($($cat.Count))</h3><div class=`"cs`">"
        if($cP){$html+="<span class='cp'>$cP Pass</span>"};if($cF){$html+="<span class='cf'>$cF Fail</span>"};if($cW){$html+="<span class='cw'>$cW Warn</span>"}
        $html += "</div></div><div class=`"cb$(if($cF -gt 0){' open'})`"><table><thead><tr><th>Status</th><th>Sev</th><th>Check</th><th>Expected</th><th>Actual</th></tr></thead><tbody>`n"
        $sorted = $cat.Group | Sort-Object @{Expression={switch($_.Status){"Fail"{0}"Warning"{1}"Error"{2}"Info"{3}"Pass"{4}}};Ascending=$true}
        foreach ($f in $sorted) {
            $sc = switch($f.Severity){"Critical"{"svC"}"High"{"svH"}"Medium"{"svM"}"Low"{"svL"}default{"svN"}}
            $stc = switch($f.Status){"Pass"{"sP"}"Fail"{"sF"}"Warning"{"sW"}"Info"{"sI"}"Error"{"sE"}default{"sI"}}
            $cell = ConvertTo-HtmlSafe $f.CheckTitle
            if($f.Description){$cell+="<div class='desc'>$(ConvertTo-HtmlSafe $f.Description)</div>"}
            if($f.Remediation){$cell+="<div class='rem'>$(ConvertTo-HtmlSafe $f.Remediation)</div>"}
            if($f.ExploitCmd){$cell+="<div class='exp'>$(ConvertTo-HtmlSafe $f.ExploitCmd)</div>"}
            if($f.POCResult){$cell+="<div class='poc'>$(ConvertTo-HtmlSafe $f.POCResult)</div>"}
            $html += "<tr><td><span class=`"b $stc`">$($f.Status)</span></td><td><span class=`"$sc`">$($f.Severity)</span></td>"
            $html += "<td>$cell</td><td>$(ConvertTo-HtmlSafe $f.Expected)</td><td>$(ConvertTo-HtmlSafe $f.Actual)</td></tr>`n"
        }
        $html += "</tbody></table></div></div>`n"
    }

    $html += "<div class=`"ftr`"><p>Windows Build Review v1 | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $pocN evidence | Authorised use only.</p></div>"
    $html += "</div></body></html>"
    $html | Out-File -FilePath $rp -Encoding UTF8 -Force
    return $rp
}

# ============================================================================
# MAIN
# ============================================================================
function Invoke-BuildReview {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  Windows Build Review + CIS Benchmark v1" -ForegroundColor Magenta
    Write-Host "  Covers all 13 assessment areas" -ForegroundColor Cyan
    Write-Host "  $Script:ComputerName | $Script:CurrentUser | $(Get-Date)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor White

    @({ Test-BIOSConfiguration },{ Test-FullDiskEncryption },{ Test-Patching },
      { Test-LocalServices },{ Test-FileSystem },{ Test-SecurityConfig },
      { Test-RemovableMedia },{ Test-AccountConfig },{ Test-PrivilegeEscalation },
      { Test-NetworkAndLateral },{ Test-LoggingAuditing },{ Test-SystemHardening },
      { Test-AttackSummary }
    ) | ForEach-Object { try { & $_ } catch { Write-Host "  [!] $_" -ForegroundColor Red } }

    $rp = Generate-Report
    $fc = ($Script:Results|Where-Object Status -eq 'Fail').Count
    $pc = ($Script:Results|Where-Object{$_.POCResult -ne ""}).Count
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host "  DONE | Checks:$($Script:Results.Count) Fail:$fc Evidence:$pc" -ForegroundColor Green
    Write-Host "  Report: $rp" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White
    $cp = $rp -replace '\.html$','.csv'
    $Script:Results | Export-Csv -Path $cp -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV: $cp" -ForegroundColor Cyan
}

Invoke-BuildReview
