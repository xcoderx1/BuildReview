<#
.SYNOPSIS
    Comprehensive Windows Build Review - LOW PRIVILEGE (Standard User)
.DESCRIPTION
    Covers all 13 assessment areas WITHOUT requiring admin privileges.
    BIOS, FDE, Patching, Services, File System, Security Config, Removable Media,
    Accounts, Priv Esc, Lateral Movement, Network Config, Logging, System Hardening.
    Plus CIS L1/L2 checks (where readable from standard user context).
    POC evidence embedded automatically. Single HTML + CSV report.
.EXAMPLE
    .\LowPriv_Build_Review.ps1
    .\LowPriv_Build_Review.ps1 -OutputPath C:\Temp
#>
[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

# Validate output directory exists - fallback chain
if (-not (Test-Path $OutputPath)) {
    foreach ($fb in @(
        [Environment]::GetFolderPath('Desktop'),
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\OneDrive\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE",
        $env:TEMP
    )) { if ($fb -and (Test-Path $fb)) { $OutputPath = $fb; break } }
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$Script:OSBuild = try { (Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { "Unknown" }
$Script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Script:POCTag = "LP_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$Script:IsDomainJoined = try { (Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { $false }
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

if ($Script:IsAdmin) { Write-Host "  [i] Running as admin - consider using Build_Review.ps1 for full coverage." -ForegroundColor Yellow }

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
            -Remediation "Enable Secure Boot in UEFI firmware." `
            -ExploitCmd $(if(-not $sb){"Bootkit/rootkit installation possible"}else{""}) `
            -Description "Without Secure Boot, boot-level malware can persist."
    } catch { Add-Finding -Category "BIOS Configuration" -CheckTitle "Secure Boot" -Status "Warning" -Actual "Cannot query (legacy BIOS?)" -Severity "High" }

    # TPM
    try { $tpm = Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm -ErrorAction Stop
        $tpmVer = $tpm.SpecVersion -split ","
        $tpmMajor = if ($tpmVer) { $tpmVer[0].Trim() } else { "Unknown" }
        $poc = "TPM Present: $($tpm.IsEnabled_InitialValue)`nSpec: $($tpm.SpecVersion)`nManufacturer: $($tpm.ManufacturerIdTxt)"
        Add-Finding -Category "BIOS Configuration" -CheckTitle "TPM version" `
            -Status $(if($tpmMajor -ge "2"){"Pass"}elseif($tpm.IsEnabled_InitialValue){"Warning"}else{"Fail"}) `
            -Expected "TPM 2.0" -Actual "TPM $tpmMajor" -Severity "High" -POCResult $poc `
            -Remediation "Upgrade to TPM 2.0 hardware."
    } catch { Add-Finding -Category "BIOS Configuration" -CheckTitle "TPM" -Status "Warning" -Actual "Cannot query (access denied or not present)" -Severity "High" }

    # UEFI
    $isUEFI = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    Add-Finding -Category "BIOS Configuration" -CheckTitle "UEFI boot mode" `
        -Status $(if($isUEFI){"Pass"}else{"Warning"}) -Expected "UEFI" `
        -Actual $(if($isUEFI){"UEFI"}else{"Legacy BIOS or cannot determine"}) -Severity "High"

    # VBS
    $vbs = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    $hvci = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
    Add-Finding -Category "BIOS Configuration" -CheckTitle "Virtualization Based Security" `
        -Status $(if($vbs -eq 1){"Pass"}else{"Warning"}) -Expected "Enabled" `
        -Actual $(if($vbs -eq 1){"Enabled (HVCI=$hvci)"}else{"Not configured"}) -Severity "High" `
        -POCResult "VBS=$vbs HVCI=$hvci"

    # BIOS info
    try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        Add-Finding -Category "BIOS Configuration" -CheckTitle "BIOS/Firmware info" -Status "Info" `
            -Actual "$($bios.Manufacturer) v$($bios.SMBIOSBIOSVersion)" -Severity "Informational" `
            -POCResult "Manufacturer: $($bios.Manufacturer)`nVersion: $($bios.SMBIOSBIOSVersion)`nRelease: $($bios.ReleaseDate)"
    } catch {}

    Add-Finding -Category "BIOS Configuration" -CheckTitle "BIOS/UEFI password" -Status "Info" `
        -Actual "MANUAL CHECK REQUIRED" -Severity "High" `
        -Description "Cannot verify programmatically. Requires physical inspection." `
        -Remediation "Set a strong BIOS supervisor password."
}


# ============================================================================
# 2. FULL DISK ENCRYPTION
# ============================================================================
function Test-FullDiskEncryption {
    Write-Section "2. Full Disk Encryption"

    # Try BitLocker query (may fail without admin)
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($vol in $volumes) {
            $isOS = $vol.MountPoint -eq "C:"
            $keyTypes = ($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
            $poc = "Volume: $($vol.MountPoint)`nStatus: $($vol.ProtectionStatus)`nEncryption: $($vol.EncryptionMethod)`nKeys: $keyTypes"
            Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker $($vol.MountPoint)" -CISRef $(if($isOS){"18.10.9.1"}else{""}) `
                -Status $(if($vol.ProtectionStatus -eq "On"){"Pass"}else{"Fail"}) `
                -Expected "On with XtsAes256" -Actual "$($vol.ProtectionStatus) ($($vol.EncryptionMethod))" `
                -Severity $(if($isOS){"High"}else{"Medium"}) -POCResult $poc `
                -ExploitCmd $(if($vol.ProtectionStatus -ne "On"){"Physical access = full data theft"}else{""})
        }
    } catch {
        # Fallback: manage-bde or WMI
        try {
            $bdeOut = manage-bde -status C: 2>$null
            if ($bdeOut) {
                $prot = if ($bdeOut -match "Protection Status:\s+(.+)") { $Matches[1].Trim() } else { "Unknown" }
                $enc = if ($bdeOut -match "Encryption Method:\s+(.+)") { $Matches[1].Trim() } else { "Unknown" }
                $pct = if ($bdeOut -match "Percentage Encrypted:\s+(.+)") { $Matches[1].Trim() } else { "Unknown" }
                Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker C:" -CISRef "18.10.9.1" `
                    -Status $(if($prot -match "On"){"Pass"}else{"Fail"}) -Expected "On" `
                    -Actual "Protection=$prot, Method=$enc, Pct=$pct" -Severity "High" `
                    -POCResult "$(($bdeOut|Out-String).Trim())"
            } else { throw "manage-bde failed" }
        } catch {
            # Final fallback: check if volume is encrypted via WMI
            try { $ev = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -ErrorAction Stop |
                    Where-Object DriveLetter -eq "C:"
                $protStatus = switch($ev.ProtectionStatus){0{"Off"};1{"On"};2{"Unknown"};default{"$($ev.ProtectionStatus)"}}
                Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker C:" -CISRef "18.10.9.1" `
                    -Status $(if($ev.ProtectionStatus -eq 1){"Pass"}else{"Fail"}) -Expected "On" `
                    -Actual $protStatus -Severity "High"
            } catch {
                Add-Finding -Category "Full Disk Encryption" -CheckTitle "BitLocker C:" -CISRef "18.10.9.1" `
                    -Status "Warning" -Actual "Cannot query (needs admin)" -Severity "High" `
                    -Remediation "Run admin version for full BitLocker audit."
            }
        }
    }

    # Check other drives exist
    try { $otherDrives = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne 'C' -and $_.DriveType -eq 'Fixed' }
        if ($otherDrives) {
            Add-Finding -Category "Full Disk Encryption" -CheckTitle "Additional fixed drives" -Status "Warning" `
                -Actual "$(($otherDrives|ForEach-Object{"$($_.DriveLetter): ($([math]::Round($_.Size/1GB,1))GB)"}) -join ', ')" `
                -Severity "Medium" -Remediation "Verify all fixed drives are encrypted."
        }
    } catch {}
}


# ============================================================================
# 3. OS & THIRD-PARTY SOFTWARE PATCHING
# ============================================================================
function Test-Patching {
    Write-Section "3. OS & Third-Party Patching"

    try { $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
        $latest = $hf | Select-Object -First 1
        $days = if ($latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
        $poc = "Total: $($hf.Count) | Latest: $($latest.HotFixID) ($days days ago)`n$(($hf|Select-Object -First 5|ForEach-Object{"  $($_.HotFixID) $($_.InstalledOn) $($_.Description)"}) -join "`n")"
        Add-Finding -Category "OS Patching" -CheckTitle "Windows Update status" `
            -Status $(if($days -le 30){"Pass"}elseif($days -le 90){"Warning"}else{"Fail"}) `
            -Expected "Within 30 days" -Actual "$days days ($($latest.HotFixID))" `
            -Severity $(if($days -gt 90){"Critical"}else{"Medium"}) -POCResult $poc
    } catch {}

    # OS build
    $build = [System.Environment]::OSVersion.Version
    Add-Finding -Category "OS Patching" -CheckTitle "OS build version" -Status "Info" `
        -Actual "Build $($build.Build).$($build.Revision)" -Severity "Informational"

    # Third-party software
    try {
        $sw = @()
        foreach ($p in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
            if (Test-Path $p) { Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -and $props.DisplayName -notmatch "^(Update|Security Update|Hotfix)") {
                    $sw += [PSCustomObject]@{Name=$props.DisplayName;Version=$props.DisplayVersion;Publisher=$props.Publisher}
                } } } }
        $sw = $sw | Sort-Object Name -Unique
        $poc = "Installed ($($sw.Count)):`n$(($sw|Select-Object -First 40|ForEach-Object{"  $($_.Name) v$($_.Version) [$($_.Publisher)]"}) -join "`n")"
        Add-Finding -Category "OS Patching" -CheckTitle "Third-party software inventory" -Status "Info" `
            -Actual "$($sw.Count) packages" -Severity "Informational" -POCResult $poc

        $risky = $sw | Where-Object { $_.Name -match "(Java \d|Adobe Flash|Adobe Reader \d|Silverlight|Python 2\.|PHP [0-4]\.|OpenSSL 1\.0)" }
        if ($risky.Count -gt 0) {
            Add-Finding -Category "OS Patching" -CheckTitle "Potentially vulnerable software" -Status "Warning" `
                -Actual "$($risky.Count): $(($risky|ForEach-Object{$_.Name}) -join ', ')" -Severity "High"
        }
    } catch {}

    # WSUS
    $wuServer = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
    Add-Finding -Category "OS Patching" -CheckTitle "Update source (WSUS)" -Status "Info" `
        -Actual $(if($wuServer){"WSUS: $wuServer"}else{"Direct to Microsoft"}) -Severity "Informational"
}


# ============================================================================
# 4. LOCAL SERVICE CHECKS
# ============================================================================
function Test-LocalServices {
    Write-Section "4. Local Service Checks"
    $dq = [string][char]34

    # Writable service binaries
    try {
        $vuln = @(); $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.State -eq "Running" }
        foreach ($s in $svcs | Select-Object -First 80) {
            $p2 = $s.PathName -replace $dq,''
            if ($p2 -match '^([a-zA-Z]:\\.+?\.(exe|dll))') { $ep = $Matches[1]
                if (Test-Path $ep) { $a = Get-Acl $ep -ErrorAction SilentlyContinue
                    if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" }; if ($w) { $vuln += "$($s.Name): $ep" } } } } }
        $poc = "Scanned $($svcs.Count) running services.`n$(if($vuln.Count -gt 0){$vuln -join "`n"}else{'None writable.'})"
        Add-Finding -Category "Local Services" -CheckTitle "Writable service binaries" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None"}else{"$($vuln.Count): $(($vuln|Select-Object -First 5) -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -ExploitCmd "copy payload.exe BINARY; sc stop/start SVC"
    } catch {}

    # Unquoted paths
    try { $uq = Get-CimInstance Win32_Service | Where-Object {
            $_.PathName -and $_.PathName -notmatch ('^\s*' + $dq) -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\' }
        Add-Finding -Category "Local Services" -CheckTitle "Unquoted service paths" `
            -Status $(if($uq.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($uq.Count -eq 0){"None"}else{"$($uq.Count)"}) -Severity "High" `
            -POCResult $(if($uq.Count -gt 0){($uq|Select-Object -First 5|ForEach-Object{"$($_.Name): $($_.PathName)"}) -join "`n"}else{""}) `
            -ExploitCmd "copy payload.exe C:\Program.exe"
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
            -Actual $sp.Status -Severity "High" -ExploitCmd "PrintNightmare / PrintSpoofer.exe"
    } catch {}

    # Remote Registry
    try { $rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
        Add-Finding -Category "Local Services" -CheckTitle "Remote Registry" -CISRef "5.27" `
            -Status $(if($rr.Status -ne "Running" -and $rr.StartType -eq "Disabled"){"Pass"}else{"Fail"}) `
            -Expected "Disabled" -Actual "Status=$($rr.Status), Start=$($rr.StartType)" -Severity "Medium"
    } catch {}

    # Service account analysis
    try { $sysServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Running" }
        $asSystem = ($sysServices | Where-Object { $_.StartName -match "LocalSystem|SYSTEM" }).Count
        $asUser = $sysServices | Where-Object { $_.StartName -and $_.StartName -notmatch "(LocalSystem|SYSTEM|LocalService|NetworkService|LOCAL SERVICE|NETWORK SERVICE)" }
        $poc = "Running as SYSTEM: $asSystem`nUser accounts: $($asUser.Count)"
        if ($asUser.Count -gt 0) { $poc += "`n$(($asUser|Select-Object -First 10|ForEach-Object{"  $($_.Name) -> $($_.StartName)"}) -join "`n")" }
        Add-Finding -Category "Local Services" -CheckTitle "Service account analysis" `
            -Status $(if($asUser.Count -gt 5){"Warning"}else{"Info"}) -Actual "SYSTEM=$asSystem, User=$($asUser.Count)" `
            -Severity "Medium" -POCResult $poc
    } catch {}

    # RMM tools
    $rmmTools = @()
    foreach ($rp in @("AnyDesk","TeamViewer","TeamViewer_Service","vncserver","rustdesk","ScreenConnect","ConnectWise","LogMeIn")) {
        $px = Get-Process -Name $rp -ErrorAction SilentlyContinue; if ($px) { $rmmTools += "$rp (PID: $(($px|ForEach-Object{$_.Id}) -join ','))" } }
    $rmmSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(AnyDesk|TeamViewer|VNC|RustDesk|ScreenConnect)" -and $_.Status -eq "Running" }
    foreach ($rs in $rmmSvcs) { $rmmTools += "$($rs.DisplayName) (svc)" }
    Add-Finding -Category "Local Services" -CheckTitle "Remote access tools (RMM)" `
        -Status $(if($rmmTools.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None or approved" `
        -Actual $(if($rmmTools.Count -eq 0){"None"}else{"$($rmmTools.Count): $($rmmTools -join ', ')"}) `
        -Severity $(if($rmmTools.Count -gt 0){"High"}else{"Medium"}) `
        -POCResult "RMM: $(if($rmmTools.Count -gt 0){$rmmTools -join "`n"}else{'None'})"
}


# ============================================================================
# 5. FILE SYSTEM REVIEW
# ============================================================================
function Test-FileSystem {
    Write-Section "5. File System Review"

    # Startup folders
    foreach ($sf in @(
        @{Path="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp";Desc="All Users Startup";Sev="Critical"},
        @{Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup";Desc="Current User Startup";Sev="Medium"}
    )) { if (Test-Path $sf.Path) { try {
        $acl = Get-Acl $sf.Path -ErrorAction Stop
        $weak = $acl.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" }
        $items = Get-ChildItem $sf.Path -ErrorAction SilentlyContinue
        $poc = "icacls:`n$(Get-IcaclsOutput $sf.Path)"
        if ($weak) { $poc += "`n$(Test-POCWrite $sf.Path $sf.Desc)" }
        if ($items.Count -gt 0) { $poc += "`nItems: $(($items|ForEach-Object{$_.Name}) -join ', ')" }
        Add-Finding -Category "File System" -CheckTitle "$($sf.Desc) permissions" `
            -Status $(if($weak){"Fail"}elseif($items.Count -gt 0){"Info"}else{"Pass"}) -Expected "Not writable by Users" `
            -Actual "Writable=$(if($weak){'YES'}else{'No'}), Items=$($items.Count)" `
            -Severity $sf.Sev -POCResult $poc
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
        Add-Finding -Category "File System" -CheckTitle "Writable Program Files subdirs" `
            -Status $(if($writable.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writable.Count -eq 0){"None"}else{"$($writable.Count): $(($writable|Select-Object -First 5) -join '; ')"}) `
            -Severity "Critical" -POCResult $(if($writable.Count -gt 0){($writable|Select-Object -First 3|ForEach-Object{"$_`n$(Get-IcaclsOutput $_)"}) -join "`n"}else{""})
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
        $poc = "System PATH dirs: $($sp2.Count)"
        if ($writablePath.Count -gt 0) { foreach ($w in $writablePath|Select-Object -First 3) { $poc += "`n--- $w ---`n$(Get-IcaclsOutput $w)`n$(Test-POCWrite $w 'PATH')" } }
        Add-Finding -Category "File System" -CheckTitle "Writable system PATH dirs" `
            -Status $(if($writablePath.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writablePath.Count -eq 0){"None"}else{"$($writablePath.Count): $($writablePath -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -ExploitCmd "copy version.dll WRITABLE_PATH\ (DLL hijacking)"
    } catch {}

    # Writable C:\ root
    try { $cRootAcl = Get-Acl "C:\" -ErrorAction Stop
        $cWeak = $cRootAcl.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
            $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow" }
        Add-Finding -Category "File System" -CheckTitle "Writable C:\ root" `
            -Status $(if($cWeak){"Fail"}else{"Pass"}) -Expected "Not user-writable" `
            -Actual $(if($cWeak){"Users can write"}else{"Restricted"}) -Severity "High"
    } catch {}

    # Unattend/Sysprep
    $uf = @()
    foreach ($up in @("C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\unattend.xml","C:\Windows\Panther\Autounattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml","C:\Windows\system32\sysprep\Unattend.xml","C:\unattend.xml")) {
        if (Test-Path $up -ErrorAction SilentlyContinue) { try { $null = Get-Content $up -TotalCount 1 -ErrorAction Stop; $uf += $up } catch {} } }
    $poc = ""
    if ($uf.Count -gt 0) { foreach ($f in $uf) { $poc += "=== $f ===`n"; try { $c = Get-Content $f -Raw -ErrorAction Stop
        if ($c -match '(?i)password') { $poc += "!! PASSWORD keyword found`n" } } catch {} } }
    Add-Finding -Category "File System" -CheckTitle "Deployment files (Unattend/Sysprep)" `
        -Status $(if($uf.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($uf.Count -eq 0){"None"}else{"$($uf.Count): $($uf -join '; ')"}) `
        -Severity "Critical" -POCResult $poc -ExploitCmd "type FILE | findstr /i password"

    # SAM/SYSTEM backups
    $samPaths = @()
    foreach ($sp3 in @("C:\Windows\Repair\SAM","C:\Windows\Repair\SYSTEM","C:\Windows\System32\config\RegBack\SAM","C:\Windows\System32\config\RegBack\SYSTEM")) {
        if (Test-Path $sp3 -ErrorAction SilentlyContinue) { try { $null = Get-Content $sp3 -TotalCount 1 -ErrorAction Stop; $samPaths += "$sp3 (READABLE!)" } catch { $samPaths += "$sp3 (locked)" } } }
    Add-Finding -Category "File System" -CheckTitle "SAM/SYSTEM backup files" `
        -Status $(if(($samPaths|Where-Object{$_ -match "READABLE"}).Count -gt 0){"Fail"}elseif($samPaths.Count -gt 0){"Info"}else{"Pass"}) `
        -Expected "None accessible" -Actual $(if($samPaths.Count -eq 0){"None"}else{$samPaths -join '; '}) `
        -Severity "Critical" -ExploitCmd "impacket-secretsdump -sam SAM -system SYSTEM LOCAL"

    # Shadow copies
    try { $vss = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
        Add-Finding -Category "File System" -CheckTitle "Volume shadow copies" `
            -Status $(if($vss.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Reviewed" `
            -Actual "$($vss.Count) shadows" -Severity "High" `
            -ExploitCmd $(if($vss.Count -gt 0){"mklink /d C:\shadow \\?\GLOBALROOT\Device\... (access old SAM)"}else{""})
    } catch {}

    # GPP cpassword
    $gppFound = @()
    foreach ($gp in @("$env:ALLUSERSPROFILE\Microsoft\Group Policy\History")) { if (Test-Path $gp) {
        Get-ChildItem $gp -Recurse -Include "*.xml" -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
            try { $gc = Get-Content $_.FullName -Raw -ErrorAction Stop; if ($gc -match "cpassword") { $gppFound += $_.FullName } } catch {} } } }
    Add-Finding -Category "File System" -CheckTitle "GPP cpassword files" `
        -Status $(if($gppFound.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($gppFound.Count -eq 0){"None"}else{$gppFound -join '; '}) -Severity "Critical" -ExploitCmd "gpp-decrypt CPASSWORD"

    # Accessibility hijack
    $accessHijack = @()
    foreach ($tool in @("sethc.exe","utilman.exe","narrator.exe","magnify.exe","osk.exe")) {
        $ifeo = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tool" "Debugger"
        if ($ifeo) { $accessHijack += "$tool IFEO=$ifeo" }
        $fp = "C:\Windows\System32\$tool"; if (Test-Path $fp) { $fi = Get-Item $fp -ErrorAction SilentlyContinue
            if ($fi -and $fi.VersionInfo.CompanyName -notmatch "Microsoft") { $accessHijack += "$tool NOT Microsoft!" } } }
    Add-Finding -Category "File System" -CheckTitle "Accessibility tool hijacking" `
        -Status $(if($accessHijack.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($accessHijack.Count -eq 0){"Clean"}else{$accessHijack -join '; '}) -Severity "Critical"
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
            -Actual $(if($mp.IsTamperProtected){"On"}else{"OFF"}) -Severity "High"

        Add-Finding -Category "Security Config" -CheckTitle "Behavior monitoring" -CISRef "18.10.43.10.2" `
            -Status $(if($mp.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.BehaviorMonitorEnabled){"On"}else{"OFF"}) -Severity "High"

        Add-Finding -Category "Security Config" -CheckTitle "Signature age" `
            -Status $(if($mp.AntivirusSignatureAge -le 3){"Pass"}elseif($mp.AntivirusSignatureAge -le 7){"Warning"}else{"Fail"}) `
            -Expected "3 days" -Actual "$($mp.AntivirusSignatureAge) days" -Severity "Medium"

        Add-Finding -Category "Security Config" -CheckTitle "PUA protection" -CISRef "18.10.43.10" `
            -Status $(if($pref.PUAProtection -eq 1){"Pass"}else{"Warning"}) -Expected "1" -Actual $pref.PUAProtection -Severity "Medium"

        $maps = $pref.MAPSReporting
        Add-Finding -Category "Security Config" -CheckTitle "Cloud protection (MAPS)" -CISRef "18.10.43.5.1" `
            -Status $(if($maps -eq 2){"Pass"}elseif($maps -ge 1){"Warning"}else{"Fail"}) `
            -Expected "2 (Advanced)" -Actual $maps -Severity "Medium"

        # ASR
        Add-Finding -Category "Security Config" -CheckTitle "ASR rules" -CISRef "18.10.43.6" `
            -Status $(if(($pref.AttackSurfaceReductionRules_Actions|Where-Object{$_ -ge 1}).Count -ge 5){"Pass"}else{"Fail"}) `
            -Expected "5+ rules" -Actual "$(($pref.AttackSurfaceReductionRules_Actions|Where-Object{$_ -ge 1}).Count) active" -Severity "High"

        # Exclusions
        $allExc = @()
        if ($pref.ExclusionPath) { $pref.ExclusionPath | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Path: $_" } }
        if ($pref.ExclusionProcess) { $pref.ExclusionProcess | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Proc: $_" } }
        if ($pref.ExclusionExtension) { $pref.ExclusionExtension | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Ext: $_" } }
        Add-Finding -Category "Security Config" -CheckTitle "Defender exclusions" `
            -Status $(if($allExc.Count -eq 0){"Pass"}elseif($allExc.Count -le 3){"Warning"}else{"Fail"}) `
            -Expected "Minimal" -Actual $(if($allExc.Count -eq 0){"None visible"}else{"$($allExc.Count) exclusions"}) `
            -Severity "Medium" -POCResult "Exclusions:`n$(if($allExc.Count -gt 0){$allExc -join "`n"}else{'None'})" `
            -ExploitCmd $(if($allExc.Count -gt 0){"Drop payload in excluded path"}else{""})
    } catch { Add-Finding -Category "Security Config" -CheckTitle "Defender" -Status "Warning" -Actual "Cannot query: $_" -Severity "Critical" }

    # LSASS protection
    $runAsPPL = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $pplMap = @{0="Disabled";1="Enabled";2="Enabled+UEFI lock (strongest)"}
    $pplOK = $runAsPPL -eq 1 -or $runAsPPL -eq 2
    Add-Finding -Category "Security Config" -CheckTitle "LSASS RunAsPPL" -CISRef "18.4.7" `
        -Status $(if($pplOK){"Pass"}else{"Fail"}) -Expected "1 or 2" `
        -Actual $(if($pplOK){"Protected ($($pplMap[[int]$runAsPPL]))"}else{"Unprotected"}) `
        -Severity "Critical" -POCResult "RunAsPPL=$(if($null -eq $runAsPPL){'Not set'}else{"$runAsPPL ($($pplMap[[int]$runAsPPL]))"})" `
        -ExploitCmd $(if(-not $pplOK){"mimikatz sekurlsa::logonpasswords"}else{""})

    # Credential Guard
    $credGuard = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    Add-Finding -Category "Security Config" -CheckTitle "Credential Guard" -CISRef "18.4.1" `
        -Status $(if($credGuard -ge 1){"Pass"}else{"Fail"}) -Expected "1+" `
        -Actual $(if($credGuard -ge 1){"Enabled"}else{"Not configured"}) -Severity "High"

    # WDigest
    $wdigest = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-Finding -Category "Security Config" -CheckTitle "WDigest plaintext" -CISRef "18.4.8" `
        -Status $(if($wdigest -eq 1){"Fail"}else{"Pass"}) -Expected "0 or not set" `
        -Actual $(if($wdigest -eq 1){"ENABLED!"}else{"Disabled (default)"}) -Severity "Critical" `
        -ExploitCmd $(if($wdigest -eq 1){"mimikatz sekurlsa::wdigest"}else{""})

    # AMSI
    try { $amsi = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        Add-Finding -Category "Security Config" -CheckTitle "AMSI providers" `
            -Status $(if($amsi.Count -gt 0){"Pass"}else{"Warning"}) -Expected "1+" -Actual "$($amsi.Count) providers" -Severity "Medium"
    } catch {}

    # Sysmon
    try { $sysmon = Get-Service Sysmon* -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
        Add-Finding -Category "Security Config" -CheckTitle "Sysmon" `
            -Status $(if($sysmon){"Pass"}else{"Warning"}) -Expected "Running" `
            -Actual $(if($sysmon){$sysmon.Name}else{"Not installed"}) -Severity "Medium"
    } catch {}

    # 3rd party EDR
    $edrProcs = @("MsSense","CylanceSvc","CrowdStrike","csfalconservice","SentinelAgent","SentinelOne","CarbonBlack","TaniumClient","Elastic.Agent")
    $foundEDR = @(); foreach ($e in $edrProcs) { $px = Get-Process -Name $e -ErrorAction SilentlyContinue; if ($px) { $foundEDR += $e } }
    $edrSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(Defender for Endpoint|CrowdStrike|SentinelOne|Carbon Black|Cylance|Tanium)" -and $_.Status -eq "Running" }
    foreach ($es in $edrSvcs) { $foundEDR += $es.DisplayName }
    Add-Finding -Category "Security Config" -CheckTitle "EDR/XDR detection" -Status "Info" `
        -Actual $(if($foundEDR.Count -gt 0){$foundEDR -join ', '}else{"None detected"}) -Severity "Informational"
}


# ============================================================================
# 7. REMOVABLE MEDIA CHECKING
# ============================================================================
function Test-RemovableMedia {
    Write-Section "7. Removable Media"

    $usbStor = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" "Start" 3
    Add-Finding -Category "Removable Media" -CheckTitle "USB storage driver" `
        -Status $(if($usbStor -eq 4){"Pass"}else{"Fail"}) -Expected "4 (Disabled)" `
        -Actual $(if($usbStor -eq 4){"Disabled"}elseif($usbStor -eq 3){"Enabled (default)"}else{$usbStor}) `
        -Severity "High" -POCResult "USBSTOR Start = $usbStor" `
        -ExploitCmd $(if($usbStor -ne 4){"Insert USB = data exfiltration"}else{""})

    $denyAll = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyAll" 0
    $denyRemovable = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyRemovable" 0
    Add-Finding -Category "Removable Media" -CheckTitle "Device install restrictions" `
        -Status $(if($denyAll -eq 1 -or $denyRemovable -eq 1){"Pass"}else{"Fail"}) `
        -Expected "DenyAll or DenyRemovable = 1" -Actual "DenyAll=$denyAll, DenyRemovable=$denyRemovable" -Severity "High"

    $autorun = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 0
    $autoplay = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 0
    Add-Finding -Category "Removable Media" -CheckTitle "AutoRun disabled" -CISRef "18.10.25.1" `
        -Status $(if($autorun -eq 255 -or $autoplay -eq 1){"Pass"}else{"Fail"}) `
        -Expected "NoDriveTypeAutoRun=255" -Actual "NoDriveType=$autorun, NoAutorun=$autoplay" -Severity "High" `
        -ExploitCmd $(if($autorun -ne 255){"Autorun.inf on USB = auto-execute"}else{""})

    $dmaGuard = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
    Add-Finding -Category "Removable Media" -CheckTitle "DMA protection (Thunderbolt)" `
        -Status $(if($dmaGuard -eq 0){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($null -eq $dmaGuard){"Not set"}else{$dmaGuard}) -Severity "Medium"

    $removWrite = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_Write" 0
    Add-Finding -Category "Removable Media" -CheckTitle "Removable storage write access" `
        -Status $(if($removWrite -eq 1){"Pass"}else{"Fail"}) -Expected "Write denied" `
        -Actual "Deny_Write=$removWrite" -Severity "High"

    $btgRequire = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\FVE" "RDVDenyWriteAccess" 0
    Add-Finding -Category "Removable Media" -CheckTitle "BitLocker To Go enforcement" `
        -Status $(if($btgRequire -eq 1){"Pass"}else{"Warning"}) -Expected "Enforced" `
        -Actual $(if($btgRequire -eq 1){"Enforced"}else{"Not enforced"}) -Severity "Medium"
}


# ============================================================================
# 8. USER ACCOUNT & PASSWORD CONFIGURATION
# ============================================================================
function Test-AccountConfig {
    Write-Section "8. User Account & Password Config"

    # net accounts (may work as standard user)
    $naWorked = $false
    try {
        $na = net accounts 2>$null
        if ($na -and ($na -join "") -match "password") {
            $naWorked = $true
            $minLen = if ($na -match "Minimum password length:\s+(\d+)") { [int]$Matches[1] } else { 0 }
            $maxAge = if ($na -match "Maximum password age.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $minAge = if ($na -match "Minimum password age.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $history = if ($na -match "Length of password history.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $lockout = if ($na -match "Lockout threshold:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $poc = ($na | Out-String).Trim()

            Add-Finding -Category "Account Config" -CheckTitle "Minimum password length" -CISRef "1.1.4" `
                -Status $(if($minLen -ge 14){"Pass"}elseif($minLen -ge 8){"Warning"}else{"Fail"}) `
                -Expected "14" -Actual "$minLen chars" -Severity $(if($minLen -lt 8){"Critical"}else{"High"}) -POCResult $poc
            Add-Finding -Category "Account Config" -CheckTitle "Password max age" -CISRef "1.1.2" `
                -Status $(if($maxAge -match "Never"){"Fail"}elseif($maxAge -match "^\d+$" -and [int]$maxAge -le 365){"Pass"}else{"Warning"}) `
                -Expected "1-365 days" -Actual $maxAge -Severity "High"
            Add-Finding -Category "Account Config" -CheckTitle "Password min age" -CISRef "1.1.3" `
                -Status $(if($minAge -match "^\d+$" -and [int]$minAge -ge 1){"Pass"}else{"Fail"}) `
                -Expected "1+ days" -Actual $minAge -Severity "Medium"
            Add-Finding -Category "Account Config" -CheckTitle "Password history" -CISRef "1.1.1" `
                -Status $(if($history -match "^\d+$" -and [int]$history -ge 24){"Pass"}else{"Fail"}) `
                -Expected "24" -Actual $history -Severity "Medium"
            Add-Finding -Category "Account Config" -CheckTitle "Account lockout threshold" -CISRef "1.2.2" `
                -Status $(if($lockout -match "^\d+$" -and [int]$lockout -gt 0 -and [int]$lockout -le 5){"Pass"}else{"Fail"}) `
                -Expected "1-5" -Actual $lockout -Severity "High" `
                -ExploitCmd $(if($lockout -eq "Never"){"Unlimited brute force"}else{""})
        }
    } catch {}
    if (-not $naWorked) {
        # Registry fallback
        $minLen = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MinimumPasswordLength" -1
        Add-Finding -Category "Account Config" -CheckTitle "Account policy" -Status "Info" `
            -Actual "net accounts unavailable (standard user). Limited registry checks below." -Severity "Medium"
    }

    # Blank passwords
    try { $blankPw = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordRequired -eq $false }
        Add-Finding -Category "Account Config" -CheckTitle "Blank password accounts" `
            -Status $(if($blankPw.Count -eq 0){"Pass"}else{"Fail"}) -Expected "0" `
            -Actual $(if($blankPw.Count -eq 0){"None"}else{"$($blankPw.Count): $(($blankPw|ForEach-Object{$_.Name}) -join ', ')"}) `
            -Severity "Critical" -ExploitCmd $(if($blankPw.Count -gt 0){"runas /user:NAME cmd"}else{""})
    } catch {}

    # Stale accounts
    try { $locals = Get-LocalUser -ErrorAction SilentlyContinue
        $stale = $locals | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) }
        $neverLogon = $locals | Where-Object { $_.Enabled -and -not $_.LastLogon }
        Add-Finding -Category "Account Config" -CheckTitle "Stale/inactive accounts" `
            -Status $(if($stale.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None >90 days" `
            -Actual "$(if($stale){"$($stale.Count) stale"}else{'None'}), $(if($neverLogon){"$($neverLogon.Count) never logged on"}else{'all active'})" `
            -Severity "Medium" -POCResult "$(($locals|ForEach-Object{"$($_.Name) Enabled=$($_.Enabled) Last=$($_.LastLogon)"}) -join "`n")"
    } catch {}

    # Admin group
    try { $ag = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        Add-Finding -Category "Account Config" -CheckTitle "Local admin count" `
            -Status $(if($ag.Count -le 2){"Pass"}else{"Warning"}) -Expected "2 or fewer" `
            -Actual "$($ag.Count): $(($ag|ForEach-Object{$_.Name}) -join ', ')" -Severity "Medium" `
            -POCResult ((net localgroup Administrators 2>$null) -join "`n")
    } catch {}

    # UAC
    $uacEnable = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    $uacConsent = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    $uacSecure = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    Add-Finding -Category "Account Config" -CheckTitle "UAC configuration" -CISRef "2.3.17" `
        -Status $(if($uacEnable -eq 1 -and $uacConsent -le 2 -and $uacSecure -eq 1){"Pass"}elseif($uacEnable -eq 1){"Warning"}else{"Fail"}) `
        -Expected "Enabled+Consent+SecureDesktop" -Actual "UAC=$uacEnable Consent=$uacConsent Secure=$uacSecure" `
        -Severity $(if($uacEnable -ne 1){"Critical"}else{"High"}) -POCResult "EnableLUA=$uacEnable`nConsentPromptBehaviorAdmin=$uacConsent`nPromptOnSecureDesktop=$uacSecure"

    # AutoLogon
    $autoPass = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $autoLogon = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"
    Add-Finding -Category "Account Config" -CheckTitle "AutoLogon credentials" -CISRef "2.3.7.4" `
        -Status $(if($autoPass){"Fail"}elseif($autoLogon -ne "0"){"Warning"}else{"Pass"}) `
        -Expected "No stored password" -Actual $(if($autoPass){"CLEARTEXT PASSWORD STORED"}else{"AutoLogon=$autoLogon"}) `
        -Severity "Critical" -POCResult "AutoAdminLogon=$autoLogon`nDefaultPassword=$(if($autoPass){'SET'}else{'Not set'})"

    # Cached logons
    $cached = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10"
    Add-Finding -Category "Account Config" -CheckTitle "Cached domain logons" -CISRef "2.3.7.5" `
        -Status $(if([int]$cached -le 4){"Pass"}else{"Warning"}) -Expected "4 or fewer" -Actual $cached -Severity "Medium"

    # Credential Manager
    try { $cm = cmdkey /list 2>$null
        $creds = ($cm | Select-String "Target:" | Measure-Object).Count
        Add-Finding -Category "Account Config" -CheckTitle "Credential Manager stored creds" `
            -Status $(if($creds -eq 0){"Pass"}else{"Warning"}) -Expected "Minimal" `
            -Actual "$creds stored credentials" -Severity "Medium" `
            -POCResult "$(($cm|Out-String).Trim())" `
            -ExploitCmd $(if($creds -gt 0){"mimikatz vault::cred"}else{""})
    } catch {}
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

    # Group memberships
    try { $groups = whoami /groups 2>$null
        Add-Finding -Category "Privilege Escalation" -CheckTitle "Group memberships" -Status "Info" `
            -Actual "$Script:CurrentUser" -Severity "Informational" -POCResult "$(($groups|Out-String).Trim())"
    } catch {}

    # SYSTEM tasks writable
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
        Add-Finding -Category "Privilege Escalation" -CheckTitle "SYSTEM tasks writable" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None (sampled 50)"}else{($vuln|Select-Object -First 5) -join '; '}) `
            -Severity "Critical" -POCResult "SYSTEM tasks: $($st.Count)`n$(if($vuln.Count -gt 0){$vuln -join "`n"}else{'None writable'})"
    } catch {}

    # HKLM Run / HKCU Run
    foreach ($regRun in @(
        @{Key="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";Desc="HKLM Run";Sev="Critical"},
        @{Key="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";Desc="HKCU Run";Sev="Medium"}
    )) { if (Test-Path $regRun.Key) { try {
        $a = Get-Acl $regRun.Key -ErrorAction Stop
        $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
            $_.RegistryRights -match "(WriteKey|SetValue|FullControl)" -and $_.AccessControlType -eq "Allow" }
        $entries = Get-ItemProperty $regRun.Key -ErrorAction SilentlyContinue
        $poc = "$(($entries.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}|ForEach-Object{"$($_.Name) = $($_.Value)"}) -join "`n")"
        Add-Finding -Category "Privilege Escalation" -CheckTitle "$($regRun.Desc) writable" `
            -Status $(if($w){"Fail"}else{"Pass"}) -Expected "Restricted" `
            -Actual $(if($w){"Writable by Users!"}else{"Properly restricted"}) -Severity $regRun.Sev -POCResult $poc
    } catch {} } }

    # IFEO + WMI
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
            -Actual "$($wmi.Count) consumers$(if($wmi.Count -gt 0){': '+($wmi|ForEach-Object{$_.Name}) -join ', '})" `
            -Severity "High"
    } catch {}

    # DLL hijacking / KnownDLLs
    try { $kd = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -ErrorAction Stop
        $kdList = $kd.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { $_.Value }
        $missing = @("version.dll","dbghelp.dll","wer.dll","profapi.dll","mswsock.dll") | Where-Object { $_ -notin $kdList }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "KnownDLLs hijackable" `
            -Status $(if($missing.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Common DLLs protected" `
            -Actual "$($missing.Count) not in KnownDLLs: $($missing -join ', ')" -Severity "Medium" `
            -ExploitCmd "copy malicious.dll PATH\version.dll (sideloading)"
    } catch {}

    # Named pipes
    try { $pipes = @([System.IO.Directory]::GetFiles("\\.\pipe\"))
        $spoolerPipe = $pipes | Where-Object { $_ -match "spoolss" }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "Named pipes (PrintSpoofer)" `
            -Status $(if($spoolerPipe){"Warning"}else{"Pass"}) -Expected "spoolss not exposed" `
            -Actual "$($pipes.Count) pipes $(if($spoolerPipe){'(spoolss PRESENT)'}else{'(no spoolss)'})" `
            -Severity "High" -POCResult "Pipes: $($pipes.Count)`n$(($pipes|Select-Object -First 15|ForEach-Object{[System.IO.Path]::GetFileName($_)}) -join "`n")" `
            -ExploitCmd $(if($spoolerPipe){"PrintSpoofer.exe -i -c cmd (SYSTEM)"}else{""})
    } catch {}

    # COM hijacking
    try { $comH = @()
        foreach ($clsid in @("{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}","{BCDE0395-E52F-467C-8E3D-C4579291692E}")) {
            $hkcu = Get-RegValue "HKCU\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" "(default)"
            if ($hkcu) { $comH += "$clsid -> $hkcu" } }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "COM object hijacking" `
            -Status $(if($comH.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($comH.Count -eq 0){"None"}else{$comH -join '; '}) -Severity "High"
    } catch {}

    # AppLocker
    try { $ap = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $rc = ($ap.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        Add-Finding -Category "Privilege Escalation" -CheckTitle "AppLocker" `
            -Status $(if($rc -gt 0){"Pass"}else{"Fail"}) -Actual $(if($rc -gt 0){"$rc rules"}else{"Not configured"}) `
            -Severity "High" -ExploitCmd $(if($rc -eq 0){"Run any binary from any writable path"}else{""})
    } catch { Add-Finding -Category "Privilege Escalation" -CheckTitle "AppLocker" -Status "Fail" -Actual "Not configured" -Severity "High" }

    # PSv2
    try { $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $psv2State = if ($psv2.State) { $psv2.State.ToString() } else { "Unknown" }
        Add-Finding -Category "Privilege Escalation" -CheckTitle "PowerShell v2" -CISRef "18.10.40.1" `
            -Status $(if($psv2State -match "Disabled"){"Pass"}else{"Fail"}) -Expected "Disabled" `
            -Actual $(if($psv2State -match "Disabled"){$psv2State}else{"Enabled"}) -Severity "High" `
            -ExploitCmd "powershell -version 2 (bypass AMSI + logging)"
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
        -Actual "Client=$(if($smbv1Client -eq 4){'Off'}else{'On'}), Server=$(if($smbv1Server -eq 0){'Off'}else{'On/Default'})" `
        -Severity "Critical" -ExploitCmd $(if($smbv1On){"EternalBlue (MS17-010)"}else{""}) `
        -POCResult "mrxsmb10 Start=$smbv1Client (4=disabled), SMB1=$smbv1Server (0=disabled)"

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
            -Actual $(if($nbtOn){"Enabled"}else{"Disabled"}) -Severity "Medium" -ExploitCmd "Responder NBT-NS poisoning"
    } catch {}

    # NTLM level
    $lmLevel = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    Add-Finding -Category "Network Config" -CheckTitle "LAN Manager auth level" -CISRef "2.3.11.7" `
        -Status $(if($lmLevel -ge 5){"Pass"}elseif($lmLevel -ge 3){"Warning"}else{"Fail"}) `
        -Expected "5 (NTLMv2 only)" -Actual "Level $lmLevel" -Severity $(if($lmLevel -lt 3){"Critical"}else{"High"}) `
        -POCResult "LmCompatibilityLevel=$lmLevel (0=LM+NTLM...5=NTLMv2 only)"

    # WinRM / RDP
    try { $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        Add-Finding -Category "Network Config" -CheckTitle "WinRM" `
            -Status $(if($winrm.Status -ne "Running"){"Pass"}else{"Warning"}) -Expected "Stopped" -Actual $winrm.Status -Severity "Medium"
    } catch {}

    $rdpDeny = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    $rdpNLA = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    Add-Finding -Category "Network Config" -CheckTitle "RDP NLA" -CISRef "18.10.57.3.9.1" `
        -Status $(if($rdpDeny -eq 1 -or $rdpNLA -eq 1){"Pass"}else{"Fail"}) `
        -Expected "NLA required" -Actual "RDP=$(if($rdpDeny -eq 0){'On'}else{'Off'}), NLA=$rdpNLA" -Severity "High" `
        -POCResult "fDenyTSConnections=$rdpDeny UserAuthentication=$rdpNLA"

    # Wi-Fi stored passwords
    try { $profiles = (netsh wlan show profiles 2>$null) | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
        $wifiCreds = @()
        foreach ($pn in $profiles | Select-Object -First 10) {
            $detail = netsh wlan show profile name="$pn" key=clear 2>$null
            $keyLine = $detail | Select-String "Key Content\s*:\s*(.+)"
            if ($keyLine) { $wifiCreds += "$pn = $($keyLine.Matches[0].Groups[1].Value.Trim())" } }
        Add-Finding -Category "Lateral Movement" -CheckTitle "Wi-Fi stored passwords" `
            -Status $(if($wifiCreds.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None extractable" `
            -Actual "$($wifiCreds.Count) passwords recovered" -Severity "High" `
            -POCResult "$(if($wifiCreds.Count -gt 0){$wifiCreds -join "`n"}else{'No cleartext keys'})" `
            -ExploitCmd "netsh wlan show profile name=SSID key=clear"
    } catch {}

    # DPAPI
    $dpapiCount = 0
    foreach ($dp in @("$env:APPDATA\Microsoft\Protect","$env:APPDATA\Microsoft\Credentials")) {
        if (Test-Path $dp) { try { $dpapiCount += (Get-ChildItem $dp -Recurse -File -ErrorAction SilentlyContinue).Count } catch {} } }
    Add-Finding -Category "Lateral Movement" -CheckTitle "DPAPI credential files" `
        -Status $(if($dpapiCount -eq 0){"Pass"}else{"Info"}) -Actual "$dpapiCount files" -Severity "Medium" `
        -ExploitCmd "mimikatz dpapi::masterkey"

    # RDP saved connections
    $rdpReg = Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
    $rdpFiles = @(); try { Get-ChildItem "$env:USERPROFILE" -Filter "*.rdp" -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object { $rdpFiles += $_.FullName } } catch {}
    Add-Finding -Category "Lateral Movement" -CheckTitle "RDP saved connections" `
        -Status $(if(-not $rdpReg -and $rdpFiles.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None" `
        -Actual "Registry=$(if($rdpReg){$rdpReg.Count}else{0}), Files=$($rdpFiles.Count)" -Severity "Medium" `
        -POCResult "Servers: $(if($rdpReg){($rdpReg|ForEach-Object{$_.PSChildName}) -join ', '}else{'None'})`nFiles: $(if($rdpFiles.Count -gt 0){$rdpFiles -join "`n"}else{'None'})"

    # PuTTY / WinSCP
    $putty = Get-ChildItem "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue
    Add-Finding -Category "Lateral Movement" -CheckTitle "PuTTY saved sessions" `
        -Status $(if(-not $putty){"Pass"}else{"Warning"}) -Expected "None" `
        -Actual $(if($putty){"$($putty.Count) sessions"}else{"None"}) -Severity "Medium"

    $winscp = Get-ChildItem "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions" -ErrorAction SilentlyContinue
    Add-Finding -Category "Lateral Movement" -CheckTitle "WinSCP saved sessions" `
        -Status $(if(-not $winscp){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($winscp){"$($winscp.Count) sessions"}else{"None"}) -Severity "High" `
        -ExploitCmd $(if($winscp){"winscppasswd (weak encryption)"}else{""})

    # Shares
    try { $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^\$' }
        if ($shares) {
            Add-Finding -Category "Network Config" -CheckTitle "Non-default shares" -Status "Warning" `
                -Actual "$(($shares|ForEach-Object{$_.Name}) -join ', ')" -Severity "Medium" }
    } catch {}

    # DNS
    try { $dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 }
        Add-Finding -Category "Network Config" -CheckTitle "DNS configuration" -Status "Info" `
            -Actual "$(($dns|Select-Object -First 4|ForEach-Object{"$($_.InterfaceAlias):$($_.ServerAddresses -join ',')"}) -join '; ')" -Severity "Informational"
    } catch {}

    # Proxy/WPAD
    $wpad = Get-RegValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoConfigURL"
    $proxy = Get-RegValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
    Add-Finding -Category "Network Config" -CheckTitle "Proxy/WPAD settings" `
        -Status $(if($wpad){"Warning"}else{"Info"}) `
        -Actual "WPAD=$(if($wpad){$wpad}else{'None'}), Proxy=$(if($proxy){$proxy}else{'None'})" `
        -Severity $(if($wpad){"Medium"}else{"Low"}) -ExploitCmd $(if($wpad){"WPAD poisoning via Responder"}else{""})

    # Anonymous / null session
    $restrictAnon = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    $restrictSAM = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1
    $nullPipes = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    Add-Finding -Category "Network Config" -CheckTitle "Anonymous/null session restrictions" -CISRef "2.3.10" `
        -Status $(if($restrictAnon -ge 1 -and $restrictSAM -eq 1){"Pass"}else{"Warning"}) `
        -Expected "Restricted" -Actual "Anon=$restrictAnon, SAM=$restrictSAM, NullPipes=$(if($nullPipes){$nullPipes -join ','}else{'Empty'})" `
        -Severity "Medium"

    # IPv6
    try { $ipv6 = Get-NetAdapterBinding -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object Enabled
        Add-Finding -Category "Network Config" -CheckTitle "IPv6" `
            -Status $(if($ipv6.Count -eq 0){"Pass"}else{"Info"}) -Expected "Disabled if not needed" `
            -Actual "$($ipv6.Count) adapters" -Severity "Low"
    } catch {}

    # Listening ports
    try { $l = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" } | Sort-Object LocalPort -Unique
        $poc = ($l|Select-Object -First 20|ForEach-Object{ $px=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "$($_.LocalAddress):$($_.LocalPort) $($px.ProcessName)" }) -join "`n"
        Add-Finding -Category "Network Config" -CheckTitle "Exposed listening ports" -Status "Info" `
            -Actual "$($l.Count) ports" -Severity "Informational" -POCResult $poc
    } catch {}
}


# ============================================================================
# 12. LOGGING & AUDITING
# ============================================================================
function Test-LoggingAuditing {
    Write-Section "12. Logging & Auditing"

    # Audit policy (may need admin for full output)
    try {
        $auditpol = auditpol /get /category:* 2>$null
        if ($auditpol -and ($auditpol -join "") -match "Logon") {
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
                @{Sub="Authentication Policy Change";CIS="17.7.2";Expect="Success";Sev="Medium"},
                @{Sub="Sensitive Privilege Use";CIS="17.8.1";Expect="Success and Failure";Sev="Medium"},
                @{Sub="Security State Change";CIS="17.9.3";Expect="Success";Sev="Medium"},
                @{Sub="Security System Extension";CIS="17.9.4";Expect="Success";Sev="Medium"},
                @{Sub="System Integrity";CIS="17.9.5";Expect="Success and Failure";Sev="Medium"}
            )
            foreach ($c in $checks) {
                $line = $auditpol | Select-String "^\s+$($c.Sub)\s" | Select-Object -First 1
                $actual = if ($line) { ($line -split "\s{2,}")[-1].Trim() } else { "Not found" }
                $pass = $actual -match "Success" -and ($c.Expect -notmatch "Failure" -or $actual -match "Failure")
                Add-Finding -Category "Logging & Auditing" -CheckTitle $c.Sub -CISRef $c.CIS `
                    -Status $(if($pass){"Pass"}else{"Fail"}) -Expected $c.Expect -Actual $actual -Severity $c.Sev `
                    -POCResult "auditpol: $($c.Sub) = $actual"
            }
        } else { Add-Finding -Category "Logging & Auditing" -CheckTitle "Audit policy" -Status "Info" `
            -Actual "Cannot query auditpol (standard user). Run admin version for full audit." -Severity "Medium" }
    } catch { Add-Finding -Category "Logging & Auditing" -CheckTitle "Audit policy" -Status "Info" -Actual "Access denied" -Severity "Medium" }

    # Command line logging
    $cmdLine = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-Finding -Category "Logging & Auditing" -CheckTitle "Command line in process events" -CISRef "18.9.3.1" `
        -Status $(if($cmdLine -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $cmdLine -Severity "High"

    # PS logging
    $sbLog = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    $trans = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    $modLog = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 0
    $score = ([int]($sbLog -eq 1)) + ([int]($trans -eq 1)) + ([int]($modLog -eq 1))
    Add-Finding -Category "Logging & Auditing" -CheckTitle "PowerShell logging" -CISRef "18.10.40.2" `
        -Status $(if($score -ge 2){"Pass"}elseif($score -eq 1){"Warning"}else{"Fail"}) `
        -Expected "All 3" -Actual "Score=$score/3 (SB=$sbLog Trans=$trans Mod=$modLog)" -Severity "High" -POCResult "ScriptBlock=$sbLog Transcription=$trans Module=$modLog"

    # Event log sizes
    foreach ($log in @(@{N="Application";Min=32768;CIS="18.9.27.1.1"},@{N="System";Min=32768;CIS="18.9.27.3.1"})) {
        try { $el = Get-WinEvent -ListLog $log.N -ErrorAction Stop
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

    try { $dep = (Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
        $m = @{0="Off";1="Essential";2="OptOut";3="AlwaysOn"}
        Add-Finding -Category "System Hardening" -CheckTitle "DEP/NX" `
            -Status $(if($dep -ge 2){"Pass"}else{"Warning"}) -Expected "2+" -Actual "$dep ($($m[[int]$dep]))" -Severity "Medium"
    } catch {}

    $aslr = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" 1
    Add-Finding -Category "System Hardening" -CheckTitle "ASLR" `
        -Status $(if($aslr -ne 0){"Pass"}else{"Fail"}) -Expected "Enabled" -Actual $(if($null -eq $aslr){"Default"}else{$aslr}) -Severity "Medium"

    $specCtrl = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
    Add-Finding -Category "System Hardening" -CheckTitle "Spectre mitigations" `
        -Status $(if($null -ne $specCtrl){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($null -eq $specCtrl){"Not set"}else{$specCtrl}) -Severity "Medium"

    $ep = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    Add-Finding -Category "System Hardening" -CheckTitle "PS Execution Policy" `
        -Status $(if($ep -in @("Restricted","AllSigned")){"Pass"}else{"Warning"}) `
        -Expected "AllSigned" -Actual $ep -Severity "Medium" `
        -POCResult "$((Get-ExecutionPolicy -List|Out-String).Trim())"

    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    Add-Finding -Category "System Hardening" -CheckTitle "WSL" `
        -Status $(if($wsl){"Warning"}else{"Pass"}) -Expected "Not installed" `
        -Actual $(if($wsl){"Installed"}else{"No"}) -Severity "Medium" -ExploitCmd "WSL bypasses AppLocker/AMSI/AV"

    $ldapSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" 1
    Add-Finding -Category "System Hardening" -CheckTitle "LDAP client signing" -CISRef "2.3.11.8" `
        -Status $(if($ldapSign -ge 1){"Pass"}else{"Fail"}) -Expected "1+" -Actual $ldapSign -Severity "High"

    $inactivity = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 0
    Add-Finding -Category "System Hardening" -CheckTitle "Machine inactivity limit" -CISRef "2.3.7.3" `
        -Status $(if($inactivity -gt 0 -and $inactivity -le 900){"Pass"}else{"Fail"}) `
        -Expected "900 sec" -Actual $(if($inactivity -eq 0){"Not set"}else{"$inactivity sec"}) -Severity "Medium"

    try { $bits = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -ne "Transferred" })
        Add-Finding -Category "System Hardening" -CheckTitle "BITS transfer jobs" `
            -Status $(if($bits.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None" -Actual "$($bits.Count) active" -Severity "Medium"
    } catch { Add-Finding -Category "System Hardening" -CheckTitle "BITS transfer jobs" -Status "Info" -Actual "Cannot query (may need admin)" -Severity "Medium" }

    # WDAC
    try { $ciPolicies = Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -ErrorAction SilentlyContinue
        Add-Finding -Category "System Hardening" -CheckTitle "WDAC" `
            -Status $(if($ciPolicies -and $ciPolicies.Count -gt 0){"Pass"}else{"Warning"}) `
            -Expected "Active" -Actual $(if($ciPolicies -and $ciPolicies.Count -gt 0){"Policy deployed"}else{"Not deployed"}) -Severity "Medium"
    } catch {}

    # Credential files
    $credFiles = @()
    foreach ($d in @("$env:USERPROFILE","C:\Users\Public")) { if (Test-Path $d) {
        try { Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue -Depth 3 |
            Where-Object { $_.Name -match "(password|cred|secret|\.rdp|\.vnc|web\.config)" -and $_.Length -lt 1MB } |
            Select-Object -First 10 | ForEach-Object {
            try { $c = Get-Content $_.FullName -TotalCount 50 -ErrorAction Stop
                if (($c -join "`n") -match '(?i)(password|passwd|pwd|credential)\s*[:=]') { $credFiles += $_.FullName }
            } catch {} } } catch {} } }
    Add-Finding -Category "System Hardening" -CheckTitle "Cleartext credential files" `
        -Status $(if($credFiles.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($credFiles.Count -eq 0){"None"}else{"$($credFiles.Count): $(($credFiles|Select-Object -First 3) -join '; ')"}) -Severity "High"

    # Browser DBs
    $browsers = @()
    foreach ($db in @(@{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data";B="Chrome"},
        @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data";B="Edge"})) {
        if (Test-Path $db.P) { $browsers += "$($db.B) ($((Get-Item $db.P).Length)b)" } }
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
    $rp = Join-Path $OutputPath "LowPriv_Build_Review_${Script:ComputerName}_$ts.html"
    $compCol = if($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Low-Priv Build Review - $Script:ComputerName</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.ctr{max-width:1400px;margin:0 auto;padding:20px}
.hdr{background:linear-gradient(135deg,#0c1929,#0c2918);border-radius:12px;padding:28px;margin-bottom:22px;border:1px solid #166534}
.hdr h1{font-size:22px;color:#86efac}.hdr .sub{color:#94a3b8;font-size:13px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:16px}
.mi{background:#1e293b;padding:9px 13px;border-radius:7px;border:1px solid #334155}
.mi .lb{font-size:10px;text-transform:uppercase;color:#64748b}.mi .vl{font-size:14px;color:#f1f5f9;font-weight:600}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:22px}
.sc{background:#1e293b;border-radius:9px;padding:16px;text-align:center;border:1px solid #334155}
.sc .n{font-size:28px;font-weight:700}.sc .l{font-size:10px;color:#94a3b8;text-transform:uppercase}
.sc.p .n{color:#4ade80}.sc.f .n{color:#f87171}.sc.w .n{color:#fbbf24}.sc.c .n{color:$compCol}.sc.poc .n{color:#86efac}
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
.poc{color:#86efac;font-size:10px;margin-top:4px;padding:5px 8px;background:#071a0e;border:1px solid #166534;border-radius:3px;white-space:pre-wrap;font-family:'Cascadia Code',Consolas,monospace;max-height:250px;overflow-y:auto}
.poc::before{content:"EVIDENCE ";font-weight:700;color:#4ade80}
.crit-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:9px;padding:16px;margin-bottom:18px}
.crit-box h3{color:#f87171;margin-bottom:8px;font-size:14px}
.crit-box ul{list-style:none}.crit-box li{padding:4px 0;color:#fca5a5;font-size:11px;border-bottom:1px solid #2d1318}
.crit-box li:last-child{border-bottom:none}.crit-box li::before{content:"! ";font-weight:bold}
.tb{background:#334155;border:none;color:#94a3b8;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:10px;margin-bottom:8px}
.tb:hover{background:#475569;color:#f1f5f9}
.ftr{text-align:center;padding:16px;color:#475569;font-size:10px}
</style></head>
<body><div class="ctr">
<div class="hdr"><h1>Low-Privilege Windows Build Review + CIS</h1>
<div class="sub">All 13 assessment areas (standard user context) + CIS L1/L2 + POC evidence</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:ComputerName</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OSVersion</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:OSBuild</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:CurrentUser</div></div>
<div class="mi"><div class="lb">Privilege</div><div class="vl" style="color:#fbbf24">$(if($Script:IsAdmin){'ADMIN'}else{'Standard User'})</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
<div class="mi"><div class="lb">Duration</div><div class="vl">$([math]::Round($dur.TotalSeconds,1))s</div></div>
<div class="mi"><div class="lb">Evidence</div><div class="vl" style="color:#86efac">$pocN items</div></div>
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

    $html += "<div class=`"ftr`"><p>Low-Priv Build Review v1 | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $pocN evidence | Authorised use only.</p></div>"
    $html += "</div></body></html>"
    $html | Out-File -FilePath $rp -Encoding UTF8 -Force
    return $rp
}

# ============================================================================
# MAIN
# ============================================================================
function Invoke-BuildReview {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  Low-Privilege Windows Build Review + CIS v1" -ForegroundColor Green
    Write-Host "  Standard user context - all 13 assessment areas" -ForegroundColor Cyan
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
