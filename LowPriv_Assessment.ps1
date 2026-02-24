<#
.SYNOPSIS
    Comprehensive Low-Privilege Security Assessment with POC Evidence
.DESCRIPTION
    90+ checks covering attack vectors, CIS benchmarks, and defense posture.
    Run as STANDARD USER for accurate results. POC runs automatically.
    Single self-contained HTML report with all evidence embedded.
.EXAMPLE
    .\LowPriv_Assessment.ps1
    .\LowPriv_Assessment.ps1 -OutputPath C:\Temp
#>
[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if ($isAdmin) {
    Write-Host "`n  +============================================================+" -ForegroundColor Yellow
    Write-Host "  |  WARNING: Running as Administrator - results are skewed!   |" -ForegroundColor Yellow
    Write-Host "  +============================================================+`n" -ForegroundColor Yellow
    $c = Read-Host "Continue? (y/N)"; if ($c -ne "y") { exit }
}

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$Script:OSBuild = try { (Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { "Unknown" }
$Script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Script:POCTag = "LPAv4_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$Script:IsDomainJoined = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$CheckTitle,
        [Parameter(Mandatory)][ValidateSet("Pass","Fail","Warning","Info","Error")][string]$Status,
        [string]$Expected = "", [string]$Actual = "", [string]$Description = "",
        [ValidateSet("Critical","High","Medium","Low","Informational")][string]$Severity = "Medium",
        [string]$Remediation = "", [string]$ExploitCmd = "", [string]$POCResult = ""
    )
    $null = $Script:Results.Add([PSCustomObject]@{
        Category=$Category; CheckTitle=$CheckTitle; Status=$Status; Expected=$Expected
        Actual=$Actual; Description=$Description; Severity=$Severity
        Remediation=$Remediation; ExploitCmd=$ExploitCmd; POCResult=$POCResult
    })
}

function Get-RegValue { param([string]$Path, [string]$Name, $Default=$null)
    try { $v = Get-ItemProperty -Path "Registry::$Path" -Name $Name -ErrorAction Stop; return $v.$Name } catch { return $Default }
}

function ConvertTo-HtmlSafe { param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $a = [string][char]38
    $dq = [string][char]34
    $Text = $Text -replace $a, ($a + 'amp;')
    $Text = $Text -replace '<', ($a + 'lt;')
    $Text = $Text -replace '>', ($a + 'gt;')
    $Text = $Text -replace $dq, ($a + 'quot;')
    return $Text
}

function Test-POCWrite { param([string]$Path, [string]$Label)
    $f = Join-Path $Path "$Script:POCTag.txt"
    try { "POC write test $(Get-Date)" | Out-File $f -Force -ErrorAction Stop
        $r = "WRITE CONFIRMED: $f as $Script:CurrentUser"
        Remove-Item $f -Force -ErrorAction SilentlyContinue; $r += " [cleaned]"
        Write-Host "    [POC] $Label - WRITE OK" -ForegroundColor Red; return $r
    } catch { return "Write blocked: $($_.Exception.Message)" }
}

function Get-IcaclsOutput { param([string]$Path)
    try { return (icacls $Path 2>$null) -join "`n" } catch { return "icacls failed" }
}

function Write-Section { param([string]$Name)
    Write-Host "`n[+] $Name" -ForegroundColor Green
}


# ============================================================================
# 1. USER & GROUP ENUMERATION
# ============================================================================
function Test-UserEnumeration {
    Write-Section "User & Group Enumeration"

    try {
        $ag = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $poc = "net localgroup Administrators:`n$((net localgroup Administrators 2>$null) -join "`n")"
        Add-Finding -Category "User Enumeration" -CheckTitle "Local Administrators" -Status "Info" `
            -Expected "Minimal" -Actual "$($ag.Count): $(($ag|ForEach-Object{$_.Name}) -join ', ')" `
            -Severity "Informational" -POCResult $poc -Remediation "Review membership. Use LAPS." `
            -Description "Any user can enumerate admin group."
        $xs = if($ag.Count -le 2){"Pass"}elseif($ag.Count -le 4){"Warning"}else{"Fail"}
        Add-Finding -Category "User Enumeration" -CheckTitle "Excessive admin accounts" `
            -Status $xs -Expected "2 or fewer" -Actual "$($ag.Count) admins" `
            -Severity $(if($ag.Count -gt 4){"High"}else{"Medium"}) `
            -Remediation "Remove unnecessary admins. Use PAM/JIT."
    } catch { Add-Finding -Category "User Enumeration" -CheckTitle "Admin enum" -Status "Error" -Actual "$_" -Severity "Medium" }

    try {
        $au = Get-LocalUser -ErrorAction Stop
        $en = $au | Where-Object Enabled
        $np = $en | Where-Object { $_.PasswordRequired -eq $false }
        $poc = "Get-LocalUser details:`n"
        foreach ($u in $au) { $poc += "  $($u.Name) | Enabled=$($u.Enabled) | PwdReq=$($u.PasswordRequired) | LastLogon=$($u.LastLogon)`n" }
        Add-Finding -Category "User Enumeration" -CheckTitle "User inventory" -Status "Info" `
            -Expected "Minimal enabled" -Actual "Total=$($au.Count), Enabled=$($en.Count)" `
            -Severity "Informational" -POCResult $poc -Remediation "Disable unused accounts."
        if ($np.Count -gt 0) {
            $names = ($np|ForEach-Object{$_.Name}) -join ", "
            Add-Finding -Category "User Enumeration" -CheckTitle "PasswordRequired=False" -Status "Fail" `
                -Expected "0" -Actual "$($np.Count): $names" -Severity "Critical" `
                -POCResult "Blank password accounts: $names" `
                -Remediation "Set-LocalUser -Name USER -PasswordNotRequired `$false" `
                -ExploitCmd "runas /user:$names cmd (blank password)" `
                -Description "Anyone can logon with empty password."
        } else {
            Add-Finding -Category "User Enumeration" -CheckTitle "PasswordRequired=False" -Status "Pass" `
                -Expected "0" -Actual "None" -Severity "Critical"
        }
        $stale = $en | Where-Object { $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) -and $_.Name -notin @("DefaultAccount","WDAGUtilityAccount") }
        Add-Finding -Category "User Enumeration" -CheckTitle "Stale accounts (90+ days)" `
            -Status $(if($stale.Count -eq 0){"Pass"}else{"Warning"}) -Expected "0" `
            -Actual $(if($stale.Count -eq 0){"None"}else{"$($stale.Count): $(($stale|ForEach-Object{$_.Name}) -join ', ')"}) `
            -Severity "Medium" -Remediation "Disable inactive accounts."
    } catch { Add-Finding -Category "User Enumeration" -CheckTitle "User inventory" -Status "Error" -Actual "$_" -Severity "Medium" }

    # AutoLogon credentials
    $alUser = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUserName"
    $alPass = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $poc = "Winlogon DefaultUserName: $(if($alUser){$alUser}else{'Not set'})`nWinlogon DefaultPassword: $(if($alPass){'SET (cleartext!)'}else{'Not set'})"
    Add-Finding -Category "User Enumeration" -CheckTitle "AutoLogon credentials in registry" `
        -Status $(if($alPass){"Fail"}else{"Pass"}) -Expected "No stored password" `
        -Actual $(if($alPass){"Cleartext password for $alUser"}else{"Not configured"}) `
        -Severity "Critical" -POCResult $poc `
        -Remediation "Remove: reg delete `"HKLM\...\Winlogon`" /v DefaultPassword /f" `
        -ExploitCmd "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" (plaintext creds)" `
        -Description "AutoLogon stores plaintext password readable by all users."
}


# ============================================================================
# 2. WRITABLE LOCATIONS
# ============================================================================
function Test-WritableLocations {
    Write-Section "Writable Locations"

    # Startup folders
    foreach ($sp in @(
        @{ Path="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Desc="All Users Startup"; Sev="Critical" },
        @{ Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Desc="Current User Startup"; Sev="Medium" }
    )) {
        if (Test-Path $sp.Path) {
            try {
                $acl = Get-Acl $sp.Path -ErrorAction Stop
                $weak = $acl.Access | Where-Object {
                    $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" }
                $items = Get-ChildItem $sp.Path -ErrorAction SilentlyContinue
                $poc = "icacls:`n$(Get-IcaclsOutput $sp.Path)"
                if ($weak) { $poc += "`n$(Test-POCWrite $sp.Path $sp.Desc)" }
                if ($items.Count -gt 0) { $poc += "`nItems: $(($items|ForEach-Object{$_.Name}) -join ', ')" }
                $st = if ($weak -and $sp.Desc -like "All*") {"Fail"} elseif ($weak) {"Warning"} elseif ($items.Count -gt 0) {"Info"} else {"Pass"}
                Add-Finding -Category "Writable Locations" -CheckTitle "$($sp.Desc) writable" `
                    -Status $st -Expected "Not writable by Users" `
                    -Actual "Writable=$(if($weak){'YES'}else{'No'}), Items=$($items.Count)" `
                    -Severity $sp.Sev -POCResult $poc `
                    -Remediation "icacls `"$($sp.Path)`" /remove:g `"BUILTIN\Users`"" `
                    -ExploitCmd "copy payload.exe `"$($sp.Path)\update.exe`"" `
                    -Description "Startup folder = persistence at logon."
            } catch {}
        }
    }

    # Program Files
    try {
        $writable = @()
        foreach ($pd in @("C:\Program Files","C:\Program Files (x86)")) {
            if (Test-Path $pd) {
                Get-ChildItem $pd -Directory -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
                    $da = Get-Acl $_.FullName -ErrorAction SilentlyContinue
                    if ($da) { $w = $da.Access | Where-Object {
                        $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" -and $_.AccessControlType -eq "Allow" }
                        if ($w) { $writable += $_.FullName } }
                }
            }
        }
        $poc = ""
        if ($writable.Count -gt 0) { foreach ($w in $writable|Select-Object -First 3) { $poc += "--- $w ---`n$(Get-IcaclsOutput $w)`n$(Test-POCWrite $w 'ProgFiles')`n" } }
        Add-Finding -Category "Writable Locations" -CheckTitle "Writable Program Files subdirs" `
            -Status $(if($writable.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writable.Count -eq 0){"None (sampled 30/root)"}else{"$($writable.Count): $(($writable|Select-Object -First 5) -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "icacls DIR /reset /T" `
            -ExploitCmd "copy malicious.dll TARGET\version.dll" -Description "DLL planting or binary replacement."
    } catch {}

    # C:\ root
    try {
        $ra = Get-Acl "C:\" -ErrorAction Stop
        $rw = $ra.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
            $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow" }
        $poc = "icacls C:\`n$(Get-IcaclsOutput 'C:\')"
        if ($rw) { $poc += "`n$(Test-POCWrite 'C:\' 'Root')" }
        Add-Finding -Category "Writable Locations" -CheckTitle "C:\ root writable" `
            -Status $(if($rw){"Fail"}else{"Pass"}) -Expected "Restricted" `
            -Actual $(if($rw){"YES - Users can write"}else{"Properly restricted"}) `
            -Severity "High" -POCResult $poc -Remediation "icacls C:\ /remove:g `"BUILTIN\Users`"" `
            -ExploitCmd "echo test > C:\poc.txt" -Description "DLL planting in search paths."
    } catch {}

    # Windows\Temp world-writable
    try {
        $wtAcl = Get-Acl "C:\Windows\Temp" -ErrorAction SilentlyContinue
        $poc = "icacls C:\Windows\Temp`n$(Get-IcaclsOutput 'C:\Windows\Temp')"
        Add-Finding -Category "Writable Locations" -CheckTitle "Windows\Temp permissions" -Status "Info" `
            -Expected "Restricted create-only" -Actual "Standard temp directory" `
            -Severity "Informational" -POCResult $poc `
            -Description "Shared temp = token impersonation staging area."
    } catch {}
}


# ============================================================================
# 3. CREDENTIAL HARVESTING
# ============================================================================
function Test-CredentialHarvesting {
    Write-Section "Credential Harvesting"

    # Wi-Fi
    try {
        $wo = netsh wlan show profiles 2>$null
        $pc = ($wo | Select-String "All User Profile" | Measure-Object).Count
        Add-Finding -Category "Credential Harvesting" -CheckTitle "Wi-Fi profiles" `
            -Status $(if($pc -eq 0){"Pass"}else{"Warning"}) -Expected "0" -Actual "$pc profiles" `
            -Severity "Medium" -POCResult "netsh wlan show profiles:`n$($wo -join "`n")" `
            -Remediation "Remove unused. Use 802.1X." -ExploitCmd "netsh wlan show profile name=SSID key=clear" `
            -Description "Admin can export PSK in cleartext."
    } catch {}

    # Credential Manager
    try {
        $co = cmdkey /list 2>$null
        $cc = ($co | Select-String "Target:" | Measure-Object).Count
        Add-Finding -Category "Credential Harvesting" -CheckTitle "Credential Manager" `
            -Status $(if($cc -eq 0){"Pass"}else{"Warning"}) -Expected "Minimal" -Actual "$cc stored" `
            -Severity $(if($cc -gt 3){"High"}else{"Medium"}) -POCResult "cmdkey /list:`n$(($co|Out-String).Trim())" `
            -Remediation "cmdkey /delete:TARGET" -ExploitCmd "mimikatz # vault::cred /patch" `
            -Description "Extractable via Mimikatz/SharpDPAPI."
    } catch {}

    # Unattend/Sysprep
    $sf = @(); foreach ($p in @(
        "C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\unattend.xml","C:\Windows\Panther\Autounattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml","C:\Windows\system32\sysprep\Unattend.xml",
        "C:\unattend.xml","C:\Windows\Panther\setupinfo","C:\Windows\inf\setupapi.dev.log"
    )) { if (Test-Path $p -ErrorAction SilentlyContinue) { try { $null = Get-Content $p -TotalCount 1 -ErrorAction Stop; $sf += $p } catch {} } }
    $poc = ""
    if ($sf.Count -gt 0) { foreach ($f in $sf) {
        $poc += "=== $f ($((Get-Item $f -ErrorAction SilentlyContinue).Length) bytes) ===`n"
        try { $c = Get-Content $f -Raw -ErrorAction Stop
            if ($c -match '(?i)password') { $poc += "!! PASSWORD keyword found`n" }
            $poc += "First 10 lines:`n$((Get-Content $f -TotalCount 10 -ErrorAction Stop) -join "`n")`n"
        } catch { $poc += "Could not read`n" }
    }}
    Add-Finding -Category "Credential Harvesting" -CheckTitle "Unattend/Sysprep files" `
        -Status $(if($sf.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None accessible" `
        -Actual $(if($sf.Count -eq 0){"None"}else{"$($sf.Count): $($sf -join '; ')"}) `
        -Severity "Critical" -POCResult $poc -Remediation "Delete deployment files." `
        -ExploitCmd "type FILE | findstr /i password then base64 decode" `
        -Description "Often contain base64 admin passwords."

    # SAM/SYSTEM backups
    $ab = @(); foreach ($p in @("C:\Windows\repair\SAM","C:\Windows\repair\SYSTEM",
        "C:\Windows\System32\config\RegBack\SAM","C:\Windows\System32\config\RegBack\SYSTEM")) {
        if (Test-Path $p -ErrorAction SilentlyContinue) { try { $null = [System.IO.File]::OpenRead($p); $ab += $p } catch {} }
    }
    $poc = if ($ab.Count -gt 0) { ($ab | ForEach-Object { "$_ | $((Get-Item $_ -ErrorAction SilentlyContinue).Length) bytes" }) -join "`n" } else { "None accessible" }
    Add-Finding -Category "Credential Harvesting" -CheckTitle "SAM/SYSTEM backups" `
        -Status $(if($ab.Count -eq 0){"Pass"}else{"Fail"}) -Expected "Not readable" `
        -Actual $(if($ab.Count -eq 0){"None"}else{"$($ab.Count): $($ab -join '; ')"}) `
        -Severity "Critical" -POCResult $poc -Remediation "Delete repair files. Restrict RegBack ACLs." `
        -ExploitCmd "impacket-secretsdump -sam SAM -system SYSTEM LOCAL"

    # Shadow copies
    try { $sh = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        $poc = "Count: $($sh.Count)"
        if ($sh.Count -gt 0) { $poc += "`n$(($sh|ForEach-Object{"  ID=$($_.ID) Vol=$($_.VolumeName)"}) -join "`n")" }
        Add-Finding -Category "Credential Harvesting" -CheckTitle "Volume Shadow Copies" `
            -Status $(if($sh.Count -eq 0){"Pass"}else{"Warning"}) -Expected "0" -Actual "$($sh.Count) shadows" `
            -Severity "Medium" -POCResult $poc -Remediation "vssadmin delete shadows /all" `
            -Description "May contain old SAM/SYSTEM hashes."
    } catch {}

    # Cleartext password files
    $pf = @(); foreach ($d in @("$env:USERPROFILE","C:\Users\Public","C:\ProgramData")) {
        if (Test-Path $d) { try {
            Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue -Depth 3 |
                Where-Object { $_.Name -match "(password|cred|secret|\.rdp|\.vnc|web\.config)" -and $_.Length -lt 1MB } |
                Select-Object -First 15 | ForEach-Object {
                try { $c = Get-Content $_.FullName -TotalCount 50 -ErrorAction Stop
                    if (($c -join "`n") -match '(?i)(password|passwd|pwd|credential|secret|connectionstring)\s*[:=]') { $pf += $_.FullName }
                } catch {} }
        } catch {} } }
    $poc = ""; if ($pf.Count -gt 0) { foreach ($f in $pf|Select-Object -First 5) {
        $poc += "=== $f ===`n"
        try { Get-Content $f -TotalCount 10 -ErrorAction Stop | ForEach-Object {
            if ($_ -match '(?i)(password|passwd|pwd|credential)') { $poc += "  $($_ -replace '(?i)([:=]\s*).+','$1[REDACTED]')`n" }
        }} catch {} }}
    Add-Finding -Category "Credential Harvesting" -CheckTitle "Cleartext password files" `
        -Status $(if($pf.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($pf.Count -eq 0){"None found"}else{"$($pf.Count): $(($pf|Select-Object -First 3) -join '; ')"}) `
        -Severity "High" -POCResult $poc -Remediation "Remove creds from files. Use Key Vault." `
        -ExploitCmd "findstr /si password *.txt *.xml *.config"

    # GPP cpassword
    $gpp = @(); foreach ($gp in @("$env:ALLUSERSPROFILE\Microsoft\Group Policy\History","C:\Windows\SYSVOL")) {
        if (Test-Path $gp -ErrorAction SilentlyContinue) { try {
            Get-ChildItem $gp -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue -Depth 5 | ForEach-Object {
                try { if ((Get-Content $_.FullName -Raw -ErrorAction Stop) -match "cpassword") { $gpp += $_.FullName } } catch {} }
        } catch {} } }
    Add-Finding -Category "Credential Harvesting" -CheckTitle "GPP cpassword files" `
        -Status $(if($gpp.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($gpp.Count -eq 0){"None"}else{"$($gpp.Count): $($gpp -join '; ')"}) `
        -Severity "Critical" -POCResult $(if($gpp.Count -gt 0){"GPP with cpassword: $($gpp -join "`n")"}else{""}) `
        -Remediation "Delete GPP XMLs. Rotate passwords." -ExploitCmd "gpp-decrypt CPASSWORD" `
        -Description "Trivially decryptable (MS14-025)."

    # DPAPI master keys
    $dpapiPath = "$env:APPDATA\Microsoft\Protect"
    $dpCount = 0
    if (Test-Path $dpapiPath) { try { $dpCount = (Get-ChildItem $dpapiPath -Recurse -File -ErrorAction SilentlyContinue).Count } catch {} }
    Add-Finding -Category "Credential Harvesting" -CheckTitle "DPAPI master keys" -Status "Info" `
        -Expected "Awareness" -Actual "$dpCount master key files in user profile" `
        -Severity "Informational" -POCResult "DPAPI path: $dpapiPath`nFiles: $dpCount`nThese protect browser passwords, WiFi keys, and credential manager entries." `
        -Remediation "Use Credential Guard to protect DPAPI." -Description "DPAPI keys protect all user secrets."

    # Cached logon count
    $cachedLogons = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10"
    Add-Finding -Category "Credential Harvesting" -CheckTitle "Cached domain logon count" `
        -Status $(if([int]$cachedLogons -le 2){"Pass"}elseif([int]$cachedLogons -le 4){"Warning"}else{"Warning"}) `
        -Expected "2 or fewer" -Actual "$cachedLogons cached logons" -Severity "Medium" `
        -POCResult "HKLM\...\Winlogon\CachedLogonsCount = $cachedLogons`nCached creds can be extracted offline for cracking." `
        -Remediation "GPO: Interactive logon: Number of previous logons to cache = 2" `
        -Description "Cached domain creds extractable for offline cracking."

    # WDigest plaintext
    $wdigest = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-Finding -Category "Credential Harvesting" -CheckTitle "WDigest plaintext credentials" `
        -Status $(if($wdigest -eq 1){"Fail"}else{"Pass"}) -Expected "Disabled (0 or not set)" `
        -Actual $(if($wdigest -eq 1){"ENABLED - plaintext in LSASS"}elseif($null -eq $wdigest){"Not set (disabled by default)"}else{$wdigest}) `
        -Severity "Critical" -POCResult "WDigest UseLogonCredential = $(if($null -eq $wdigest){'Not set (default=disabled)'}else{$wdigest})" `
        -Remediation "reg add HKLM\SYSTEM\...\WDigest /v UseLogonCredential /t REG_DWORD /d 0" `
        -ExploitCmd "mimikatz # sekurlsa::wdigest (dumps plaintext passwords)" `
        -Description "WDigest stores plaintext passwords in LSASS memory."
}


# ============================================================================
# 4. REGISTRY PERSISTENCE
# ============================================================================
function Test-RegistryPersistence {
    Write-Section "Registry Persistence"

    # HKCU autoruns
    $autoruns = @()
    foreach ($ar in @(
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";Desc="HKCU Run"},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";Desc="HKCU RunOnce"}
    )) { if (Test-Path $ar.Path) { try {
        $props = Get-ItemProperty $ar.Path -ErrorAction SilentlyContinue
        $entries = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
        foreach ($e in $entries) { if ($e.Value -and $e.Value -match "\.(exe|bat|cmd|ps1|vbs|dll)") { $autoruns += "$($ar.Desc)\$($e.Name) = $($e.Value)" } }
    } catch {} } }

    $poc = ""
    try { $tk = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $tk -Name $Script:POCTag -Value "C:\Windows\System32\calc.exe" -ErrorAction Stop
        $poc = "POC: Created HKCU Run entry: $Script:POCTag = calc.exe`n"
        Remove-ItemProperty -Path $tk -Name $Script:POCTag -ErrorAction SilentlyContinue
        $poc += "CONFIRMED WRITABLE [cleaned]`nAny user can persist via HKCU Run."
        Write-Host "    [POC] HKCU persistence - CONFIRMED" -ForegroundColor Red
    } catch { $poc = "HKCU write test: $($_.Exception.Message)" }
    Add-Finding -Category "Registry Persistence" -CheckTitle "HKCU autorun entries" `
        -Status $(if($autoruns.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Minimal" `
        -Actual $(if($autoruns.Count -eq 0){"None"}else{"$($autoruns.Count): $(($autoruns|Select-Object -First 3) -join '; ')"}) `
        -Severity "Medium" -POCResult $poc `
        -Remediation "Monitor via Sysmon EventID 12/13." `
        -ExploitCmd "reg add HKCU\...\Run /v Backdoor /d payload.exe"

    # HKLM Run writable
    $writableHKLM = @()
    foreach ($sa in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $sa) { try { $ra = Get-Acl $sa -ErrorAction Stop
            $w = $ra.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                $_.RegistryRights -match "(WriteKey|SetValue|FullControl)" -and $_.AccessControlType -eq "Allow" }
            if ($w) { $writableHKLM += $sa }
        } catch {} } }
    $poc = if ($writableHKLM.Count -gt 0) { "CRITICAL: HKLM Run writable by Users: $($writableHKLM -join ', ')" } else { "HKLM Run properly restricted." }
    Add-Finding -Category "Registry Persistence" -CheckTitle "HKLM autorun writable" `
        -Status $(if($writableHKLM.Count -eq 0){"Pass"}else{"Fail"}) -Expected "Not writable" `
        -Actual $(if($writableHKLM.Count -eq 0){"Restricted"}else{"$($writableHKLM.Count) writable"}) `
        -Severity "Critical" -POCResult $poc `
        -Remediation "Remove Users write from HKLM Run." -ExploitCmd "reg add HKLM\...\Run /v Backdoor /d payload.exe"

    # IFEO debugger hijacking
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $ifeoHijacks = @()
    if (Test-Path $ifeoPath) {
        Get-ChildItem $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($dbg.Debugger) { $ifeoHijacks += "$($_.PSChildName): $($dbg.Debugger)" }
        }
    }
    Add-Finding -Category "Registry Persistence" -CheckTitle "IFEO Debugger hijacking" `
        -Status $(if($ifeoHijacks.Count -eq 0){"Pass"}else{"Fail"}) -Expected "No debuggers set" `
        -Actual $(if($ifeoHijacks.Count -eq 0){"None"}else{"$($ifeoHijacks.Count): $(($ifeoHijacks|Select-Object -First 3) -join '; ')"}) `
        -Severity "High" -POCResult "IFEO entries with Debugger: $(if($ifeoHijacks.Count -gt 0){$ifeoHijacks -join "`n"}else{'None'})" `
        -Remediation "Remove: reg delete HKLM\...\IFEO\target.exe /v Debugger" `
        -ExploitCmd "reg add `"HKLM\...\IFEO\sethc.exe`" /v Debugger /d cmd.exe" `
        -Description "IFEO debugger replaces target binary execution."

    # WMI event subscriptions
    try {
        $wmiSubs = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
        $wmiCount = $wmiSubs.Count
        $poc = "WMI event consumers: $wmiCount"
        if ($wmiCount -gt 0) { foreach ($w in $wmiSubs) { $poc += "`n  $($w.__CLASS): $($w.Name)" } }
        Add-Finding -Category "Registry Persistence" -CheckTitle "WMI event subscriptions" `
            -Status $(if($wmiCount -eq 0){"Pass"}else{"Warning"}) -Expected "None or known" `
            -Actual "$wmiCount event consumers" -Severity "High" -POCResult $poc `
            -Remediation "Remove: Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Remove-CimInstance" `
            -Description "WMI persistence survives reboots and is hard to detect."
    } catch { Add-Finding -Category "Registry Persistence" -CheckTitle "WMI subscriptions" -Status "Info" -Actual "Cannot query (may need admin)" -Severity "Medium" }
}


# ============================================================================
# 5. TOKEN PRIVILEGES
# ============================================================================
function Test-TokenPrivileges {
    Write-Section "Token Privileges"

    try {
        $wp = whoami /priv 2>$null
        $dangerous = @(
            @{N="SeImpersonatePrivilege";E="GodPotato/PrintSpoofer -> SYSTEM"},
            @{N="SeAssignPrimaryTokenPrivilege";E="Token manipulation -> SYSTEM"},
            @{N="SeDebugPrivilege";E="procdump lsass.exe -> cred dump"},
            @{N="SeBackupPrivilege";E="robocopy /B -> read SAM/SYSTEM"},
            @{N="SeRestorePrivilege";E="Write any file -> DLL hijack"},
            @{N="SeTakeOwnershipPrivilege";E="Own SAM -> hash dump"},
            @{N="SeLoadDriverPrivilege";E="Load vuln driver -> kernel exploit"},
            @{N="SeTcbPrivilege";E="Act as OS -> full SYSTEM"}
        )
        $found = @(); $exploits = @()
        foreach ($d in $dangerous) { if ($wp -match $d.N) { $found += $d.N; $exploits += "$($d.N): $($d.E)" } }
        Add-Finding -Category "Token Privileges" -CheckTitle "Dangerous token privileges" `
            -Status $(if($found.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($found.Count -eq 0){"None"}else{"$($found.Count): $($found -join ', ')"}) `
            -Severity "Critical" -POCResult "whoami /priv:`n$(($wp|Out-String).Trim())" `
            -Remediation "secpol.msc > User Rights Assignment" -ExploitCmd ($exploits -join "`n")

        $gr = whoami /groups /fo csv 2>$null
        $groups = $gr | ConvertFrom-Csv -ErrorAction SilentlyContinue
        $gnp = ($groups | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -match "Group" }).Name
        if ($gnp) {
            $interesting = $groups | Where-Object { $_.$gnp -match "(Admin|Remote Desktop|Remote Management|Backup|Power Users|Hyper-V|Network Config)" -and $_.$gnp -notmatch "Mandatory Label" }
            Add-Finding -Category "Token Privileges" -CheckTitle "Interesting group memberships" `
                -Status $(if($interesting.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Standard only" `
                -Actual $(if($interesting.Count -eq 0){"Standard"}else{"$($interesting.Count): $(($interesting|ForEach-Object{$_.$gnp}) -join ', ')"}) `
                -Severity "High" -POCResult "whoami /groups:`n$(($gr|Out-String).Trim())" `
                -Remediation "net localgroup GROUP USER /delete"
        }
    } catch { Add-Finding -Category "Token Privileges" -CheckTitle "Token check" -Status "Error" -Actual "$_" -Severity "High" }
}


# ============================================================================
# 6. APPLICATION CONTROL
# ============================================================================
function Test-ApplicationControl {
    Write-Section "Application Control"

    # Execution Policy
    try {
        $ep = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        $epu = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
        Add-Finding -Category "Application Control" -CheckTitle "PS Execution Policy" `
            -Status $(if($ep -in @("Restricted","AllSigned")){"Pass"}else{"Warning"}) `
            -Expected "Restricted/AllSigned" -Actual "Machine=$ep, User=$epu" -Severity "Medium" `
            -POCResult "Get-ExecutionPolicy -List:`n$((Get-ExecutionPolicy -List|Out-String).Trim())" `
            -Remediation "Set-ExecutionPolicy AllSigned -Scope LocalMachine" `
            -ExploitCmd "powershell -ep bypass -file script.ps1"
    } catch {}

    # Language mode
    $lm = $ExecutionContext.SessionState.LanguageMode
    $poc = "Mode: $lm"
    if ($lm -eq "FullLanguage") { try { $poc += "`n.NET: [System.Net.Dns]::GetHostName() = $([System.Net.Dns]::GetHostName())" } catch {} }
    Add-Finding -Category "Application Control" -CheckTitle "PS Language Mode" `
        -Status $(if($lm -eq "ConstrainedLanguage"){"Pass"}else{"Warning"}) `
        -Expected "ConstrainedLanguage" -Actual $lm.ToString() -Severity "Medium" -POCResult $poc `
        -Remediation "Deploy WDAC/AppLocker for ConstrainedLanguage."

    # AppLocker
    try {
        $ap = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $rc = ($ap.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        Add-Finding -Category "Application Control" -CheckTitle "AppLocker" `
            -Status $(if($rc -gt 0){"Pass"}else{"Fail"}) -Expected "Rules configured" `
            -Actual $(if($rc -gt 0){"$rc rules"}else{"None"}) -Severity "High" `
            -Remediation "Deploy AppLocker via GPO." -ExploitCmd "Run any EXE from any writable path."
    } catch {
        $poc = ""; $tb = Join-Path $env:TEMP "$Script:POCTag.bat"
        try { "@echo POC: Arbitrary exec as $Script:CurrentUser" | Out-File $tb -Force -Encoding ASCII
            $o = cmd /c $tb 2>$null; $poc = "POC: Executed $tb`nOutput: $o`n[cleaned]"
            Remove-Item $tb -Force -ErrorAction SilentlyContinue
        } catch {}
        Add-Finding -Category "Application Control" -CheckTitle "AppLocker" -Status "Fail" `
            -Expected "Rules in effect" -Actual "Not configured" -Severity "High" -POCResult $poc `
            -Remediation "Deploy AppLocker default rules." -ExploitCmd "Any binary from %TEMP%." `
            -Description "No application whitelisting."
    }

    # WDAC
    try {
        $wdac = Get-CimInstance -Namespace root/Microsoft/Windows/CI -ClassName MSFT_SIPolicy -ErrorAction SilentlyContinue
        Add-Finding -Category "Application Control" -CheckTitle "WDAC policy" `
            -Status $(if($wdac){"Pass"}else{"Warning"}) -Expected "Enforced" `
            -Actual $(if($wdac){"Policy active"}else{"Not configured"}) `
            -Severity "Medium" -POCResult "WDAC: $(if($wdac){'Active'}else{'Not deployed'})" `
            -Remediation "Deploy WDAC base policy via Intune/GPO." `
            -Description "WDAC provides kernel-level code integrity."
    } catch { Add-Finding -Category "Application Control" -CheckTitle "WDAC" -Status "Info" -Actual "Cannot query" -Severity "Medium" }
}


# ============================================================================
# 7. SERVICE SECURITY
# ============================================================================
function Test-ServiceSecurity {
    Write-Section "Service Security"
    $dq = [string][char]34

    # Writable binaries
    try {
        $vuln = @(); $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.State -eq "Running" }
        foreach ($s in $svcs | Select-Object -First 50) {
            $p = $s.PathName -replace $dq, ''
            if ($p -match '^([a-zA-Z]:\\.+?\.(exe|dll))') { $ep = $Matches[1]
                if (Test-Path $ep) { $a = Get-Acl $ep -ErrorAction SilentlyContinue
                    if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" }
                        if ($w) { $vuln += "$($s.Name): $ep" } } } } }
        $poc = "Scanned $($svcs.Count) running services.`n"
        if ($vuln.Count -gt 0) { foreach ($v in $vuln|Select-Object -First 3) { $poc += "--- $v ---`n$(Get-IcaclsOutput ($v -split ': ')[1])`n" } }
        else { $poc += "No writable binaries found." }
        Add-Finding -Category "Service Security" -CheckTitle "Writable service binaries" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None (sampled 50)"}else{($vuln|Select-Object -First 5) -join "; "}) `
            -Severity "Critical" -POCResult $poc -Remediation "icacls BINARY /reset" `
            -ExploitCmd "copy payload.exe BINARY; sc stop/start SVC"
    } catch {}

    # Unquoted paths
    try {
        $uq = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            $_.PathName -and $_.PathName -notmatch ('^\s*' + $dq) -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\' }
        $poc = if ($uq.Count -gt 0) { ($uq|Select-Object -First 5|ForEach-Object{"$($_.Name): $($_.PathName)"}) -join "`n" } else { "" }
        Add-Finding -Category "Service Security" -CheckTitle "Unquoted service paths" `
            -Status $(if($uq.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($uq.Count -eq 0){"None"}else{"$($uq.Count)"}) -Severity "High" -POCResult $poc `
            -Remediation "sc config SVC binPath= `"quoted path`"" -ExploitCmd "copy payload.exe C:\Program.exe"
    } catch {}

    # Service permissions (sc sdshow)
    try {
        $weakSvcPerms = @()
        foreach ($s in $svcs | Select-Object -First 20) {
            $sd = sc.exe sdshow $s.Name 2>$null | Where-Object { $_ -match "D:" }
            if ($sd -match "A;.*?(BU|AU|WD);.*?(WP|WD|GA|GW)") { $weakSvcPerms += "$($s.Name): weak DACL" }
        }
        Add-Finding -Category "Service Security" -CheckTitle "Services with weak DACLs" `
            -Status $(if($weakSvcPerms.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($weakSvcPerms.Count -eq 0){"None (sampled 20)"}else{"$($weakSvcPerms.Count): $($weakSvcPerms -join '; ')"}) `
            -Severity "High" -Remediation "sc sdset SVC to restrict permissions." `
            -ExploitCmd "sc config SVCNAME binPath= payload.exe" `
            -Description "Weak service DACLs allow config modification."
    } catch {}

    # AlwaysInstallElevated
    $aieHKCU = Get-RegValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieHKLM = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieVuln = $aieHKCU -eq 1 -and $aieHKLM -eq 1
    Add-Finding -Category "Service Security" -CheckTitle "AlwaysInstallElevated" `
        -Status $(if($aieVuln){"Fail"}else{"Pass"}) -Expected "Not 1 in both" `
        -Actual "HKLM=$(if($null -eq $aieHKLM){'Not Set'}else{$aieHKLM}), HKCU=$(if($null -eq $aieHKCU){'Not Set'}else{$aieHKCU})" `
        -Severity "Critical" -POCResult "HKLM=$aieHKLM HKCU=$aieHKCU$(if($aieVuln){' -> ANY MSI RUNS AS SYSTEM!'})" `
        -Remediation "Set both to 0 via GPO." -ExploitCmd $(if($aieVuln){"msfvenom -f msi > evil.msi; msiexec /quiet /i evil.msi"}else{""})
}


# ============================================================================
# 8. NETWORK & LATERAL MOVEMENT
# ============================================================================
function Test-NetworkExposure {
    Write-Section "Network & Lateral Movement"

    # Listening ports
    try {
        $l = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" } | Sort-Object LocalPort -Unique
        $poc = ($l|Select-Object -First 20|ForEach-Object{ $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "  $($_.LocalAddress):$($_.LocalPort) PID=$($_.OwningProcess) $($p.ProcessName)" }) -join "`n"
        $ports = ($l|ForEach-Object{ $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "$($_.LocalPort)/$($p.ProcessName)" }) -join ", "
        Add-Finding -Category "Network Exposure" -CheckTitle "Listening services" -Status "Info" `
            -Expected "Minimal" -Actual $(if($l.Count -eq 0){"None"}else{"$($l.Count) ports: $ports"}) `
            -Severity "Informational" -POCResult "Exposed ports:`n$poc" -Remediation "Disable unnecessary services."
    } catch {}

    # Open shares
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("ADMIN$","C$","IPC$","print$") -and $_.ShareType -eq "FileSystemDirectory" }
        $open = @()
        foreach ($s in $shares) { $sa = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
            if ($sa | Where-Object { $_.AccountName -match "(Everyone|BUILTIN\\Users)" }) { $open += "$($s.Name) ($($s.Path))" } }
        Add-Finding -Category "Network Exposure" -CheckTitle "Shares accessible to Everyone" `
            -Status $(if($open.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($open.Count -eq 0){"None"}else{"$($open.Count): $($open -join '; ')"}) `
            -Severity "High" -Remediation "Remove Everyone from share ACLs." -ExploitCmd "dir \\HOST\SHARE"
    } catch {}

    # SMB signing
    $smbSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    Add-Finding -Category "Network Exposure" -CheckTitle "SMB signing required (server)" `
        -Status $(if($smbSign -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Required)" `
        -Actual $(if($smbSign -eq 1){"Enabled"}else{"Disabled ($smbSign)"}) -Severity "High" `
        -POCResult "RequireSecuritySignature = $smbSign" `
        -Remediation "GPO: Digitally sign communications (always) = Enabled" `
        -ExploitCmd "ntlmrelayx.py -t smb://TARGET (relay without signing)" `
        -Description "Without SMB signing, NTLM relay attacks are possible."

    $smbSignClient = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 0
    Add-Finding -Category "Network Exposure" -CheckTitle "SMB signing required (client)" `
        -Status $(if($smbSignClient -eq 1){"Pass"}else{"Warning"}) -Expected "1" `
        -Actual $(if($smbSignClient -eq 1){"Enabled"}else{"Disabled ($smbSignClient)"}) -Severity "Medium" `
        -POCResult "Client RequireSecuritySignature = $smbSignClient" `
        -Remediation "GPO: Network client: Digitally sign communications (always) = Enabled"

    # LLMNR
    $llmnr = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
    Add-Finding -Category "Network Exposure" -CheckTitle "LLMNR enabled" `
        -Status $(if($llmnr -eq 0){"Pass"}else{"Fail"}) -Expected "0 (Disabled)" `
        -Actual $(if($llmnr -eq 0){"Disabled"}else{"Enabled ($llmnr)"}) -Severity "High" `
        -POCResult "EnableMulticast = $llmnr" `
        -Remediation "GPO: Turn off multicast name resolution = Enabled" `
        -ExploitCmd "Responder -I eth0 (poison LLMNR/capture NTLMv2 hashes)" `
        -Description "LLMNR poisoning captures NTLMv2 hashes on the network."

    # NBT-NS
    try {
        $nbtns = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" "NetbiosOptions"
        $nics = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
        $nbtEnabled = $false
        foreach ($n in $nics) { $v = Get-ItemProperty $n.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
            if ($null -eq $v -or $v.NetbiosOptions -ne 2) { $nbtEnabled = $true; break } }
        Add-Finding -Category "Network Exposure" -CheckTitle "NetBIOS over TCP/IP" `
            -Status $(if(-not $nbtEnabled){"Pass"}else{"Warning"}) -Expected "Disabled (2)" `
            -Actual $(if($nbtEnabled){"Enabled on at least one NIC"}else{"Disabled on all NICs"}) `
            -Severity "Medium" -Remediation "Set NetBIOS to Disabled on all NICs." `
            -ExploitCmd "Responder -I eth0 (NBT-NS poisoning)" `
            -Description "NBT-NS poisoning for credential capture."
    } catch {}

    # WinRM
    try {
        $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        Add-Finding -Category "Network Exposure" -CheckTitle "WinRM service" `
            -Status $(if($winrm.Status -ne "Running"){"Pass"}else{"Warning"}) `
            -Expected "Stopped on workstations" -Actual "WinRM=$($winrm.Status)" `
            -Severity "Medium" -POCResult "WinRM: $($winrm.Status)" `
            -Remediation "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled" `
            -Description "WinRM enables remote command execution."
    } catch {}

    # RDP NLA
    $rdpNLA = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    $rdpEnabled = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    Add-Finding -Category "Network Exposure" -CheckTitle "RDP Network Level Authentication" `
        -Status $(if($rdpEnabled -eq 1){"Pass"}elseif($rdpNLA -eq 1){"Pass"}else{"Fail"}) `
        -Expected "NLA required or RDP disabled" `
        -Actual "RDP=$(if($rdpEnabled -eq 0){'Enabled'}else{'Disabled'}), NLA=$(if($rdpNLA -eq 1){'Required'}else{'Not required'})" `
        -Severity $(if($rdpEnabled -eq 0 -and $rdpNLA -ne 1){"High"}else{"Medium"}) `
        -POCResult "fDenyTSConnections=$rdpEnabled, UserAuthentication=$rdpNLA" `
        -Remediation "GPO: Require NLA for Remote Desktop connections" `
        -Description "Without NLA, pre-auth attacks are possible."

    # IPv6
    try {
        $ipv6 = Get-NetAdapterBinding -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object Enabled
        Add-Finding -Category "Network Exposure" -CheckTitle "IPv6 enabled" `
            -Status $(if($ipv6.Count -eq 0){"Pass"}else{"Info"}) -Expected "Disabled if not needed" `
            -Actual "$($ipv6.Count) adapters with IPv6" -Severity "Low" `
            -POCResult "IPv6 on: $(($ipv6|ForEach-Object{$_.Name}) -join ', ')" `
            -Remediation "Disable IPv6 if not required." -Description "IPv6 enables mitm6/DHCPv6 attacks."
    } catch {}
}


# ============================================================================
# 9. DLL HIJACKING
# ============================================================================
function Test-DLLHijacking {
    Write-Section "DLL Hijacking"

    try {
        $sp = [Environment]::GetEnvironmentVariable("PATH","Machine") -split ";"
        $writable = @()
        foreach ($d in $sp) { if ($d -and (Test-Path $d -ErrorAction SilentlyContinue)) {
            $a = Get-Acl $d -ErrorAction SilentlyContinue
            if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow" }
                if ($w) { $writable += $d } } } }
        $poc = "System PATH dirs: $($sp.Count)`n"
        if ($writable.Count -gt 0) { foreach ($w in $writable) { $poc += "--- $w ---`n$(Get-IcaclsOutput $w)`n$(Test-POCWrite $w 'PATH')`n" } }
        else { $poc += "All properly restricted." }
        Add-Finding -Category "DLL Hijacking" -CheckTitle "Writable system PATH dirs" `
            -Status $(if($writable.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writable.Count -eq 0){"None"}else{"$($writable.Count): $($writable -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "Remove writable dirs. icacls DIR /remove:g Users" `
            -ExploitCmd "copy version.dll WRITABLE_PATH\"
    } catch {}

    # User PATH injection
    try {
        $userPath = [Environment]::GetEnvironmentVariable("PATH","User")
        $poc = "User PATH: $(if($userPath){$userPath}else{'Empty'})"
        if ($userPath) {
            $userDirs = $userPath -split ";" | Where-Object { $_ }
            $writableUser = @()
            foreach ($d in $userDirs) { if (Test-Path $d -ErrorAction SilentlyContinue) {
                try { Test-POCWrite $d "UserPATH" | Out-Null; $writableUser += $d } catch {} } }
            $poc += "`nWritable user PATH dirs: $($writableUser.Count)"
        }
        Add-Finding -Category "DLL Hijacking" -CheckTitle "User PATH directories" -Status "Info" `
            -Expected "Awareness" -Actual $(if($userPath){"$(($userPath -split ';').Count) dirs"}else{"Empty"}) `
            -Severity "Informational" -POCResult $poc `
            -Description "User PATH searched before system PATH for some lookups."
    } catch {}

    # KnownDLLs
    try {
        $kd = Get-ItemProperty "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -ErrorAction SilentlyContinue
        $kc = ($kd.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
        Add-Finding -Category "DLL Hijacking" -CheckTitle "KnownDLLs protection" -Status "Info" `
            -Actual "$kc DLLs protected" -Severity "Informational" `
            -POCResult "KnownDLLs: $kc entries (loaded from System32 only)." `
            -Remediation "Add critical DLLs to KnownDLLs."
    } catch {}

    # COM hijacking potential
    $comHijack = @()
    foreach ($clsid in @("{BCDE0395-E52F-467C-8E3D-C4579291692E}","{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}")) {
        $hkcu = Get-RegValue "HKCU\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" "(default)"
        if ($hkcu) { $comHijack += "$clsid -> $hkcu" }
    }
    Add-Finding -Category "DLL Hijacking" -CheckTitle "COM object hijacking" `
        -Status $(if($comHijack.Count -eq 0){"Pass"}else{"Warning"}) -Expected "No HKCU COM overrides" `
        -Actual $(if($comHijack.Count -eq 0){"None found (sampled)"}else{"$($comHijack.Count) overrides"}) `
        -Severity "Medium" -POCResult "HKCU COM overrides: $(if($comHijack.Count -gt 0){$comHijack -join "`n"}else{'None'})" `
        -Remediation "Monitor HKCU CLSID changes via Sysmon." -Description "COM hijacking loads attacker DLLs in trusted processes."
}

# ============================================================================
# 10. SCHEDULED TASKS
# ============================================================================
function Test-ScheduledTaskAbuse {
    Write-Section "Scheduled Task Abuse"
    try {
        $st = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|LocalSystem|LOCAL SERVICE|NETWORK SERVICE" -and $_.State -ne "Disabled" }
        $vuln = @(); $dq = [string][char]34
        foreach ($t in $st | Select-Object -First 40) { foreach ($a in $t.Actions) {
            if ($a.Execute) { $te = $a.Execute -replace $dq,''
                if ($te -and (Test-Path $te -ErrorAction SilentlyContinue)) {
                    $ta = Get-Acl $te -ErrorAction SilentlyContinue
                    if ($ta) { $w = $ta.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl)" }
                        if ($w) { $vuln += "$($t.TaskName): $te" } }
                }
                $td = Split-Path $te -Parent -ErrorAction SilentlyContinue
                if ($td -and (Test-Path $td -ErrorAction SilentlyContinue)) {
                    $da = Get-Acl $td -ErrorAction SilentlyContinue
                    if ($da) { $wd = $da.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" }
                        if ($wd) { $vuln += "$($t.TaskName): DIR $td" } } }
            } } }
        $vuln = $vuln | Select-Object -Unique
        $poc = "Scanned $($st.Count) SYSTEM tasks.`n$(if($vuln.Count -gt 0){$vuln -join "`n"}else{'No writable binaries/dirs.'})"
        Add-Finding -Category "Scheduled Task Abuse" -CheckTitle "SYSTEM tasks writable" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None (sampled 40)"}else{"$($vuln.Count): $(($vuln|Select-Object -First 3) -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "icacls BINARY /remove:g Users" `
            -ExploitCmd "copy payload.exe TASK_BINARY_PATH"
    } catch { Add-Finding -Category "Scheduled Task Abuse" -CheckTitle "Task audit" -Status "Error" -Actual "$_" -Severity "High" }
}

# ============================================================================
# 11. NAMED PIPES
# ============================================================================
function Test-NamedPipeVectors {
    Write-Section "Named Pipe Vectors"
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Select-Object -First 30
        Add-Finding -Category "Named Pipe Vectors" -CheckTitle "Named pipes" -Status "Info" `
            -Actual "$($pipes.Count)+ pipes" -Severity "Informational" `
            -POCResult "Pipes:`n$(($pipes|ForEach-Object{Split-Path $_ -Leaf}) -join "`n")"
    } catch {}

    try {
        $sp = Get-Service Spooler -ErrorAction SilentlyContinue
        $hi = whoami /priv 2>$null | Select-String "SeImpersonatePrivilege"
        $exploitable = $sp.Status -eq "Running" -and $hi
        $poc = "Spooler: $($sp.Status)`nSeImpersonate: $(if($hi){'YES'}else{'No'})"
        if ($exploitable) { $poc += "`nALL CONDITIONS MET -> SYSTEM" }
        Add-Finding -Category "Named Pipe Vectors" -CheckTitle "PrintSpoofer vector" `
            -Status $(if($sp.Status -eq "Running"){"Fail"}else{"Pass"}) `
            -Expected "Spooler stopped" `
            -Actual "Spooler=$($sp.Status), SeImpersonate=$(if($hi){'YES'}else{'No'})" `
            -Severity $(if($exploitable){"Critical"}else{"High"}) -POCResult $poc `
            -Remediation "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled" `
            -ExploitCmd "PrintSpoofer.exe -i -c cmd.exe"
    } catch {}
}


# ============================================================================
# 12. DEFENSE & AV POSTURE
# ============================================================================
function Test-DefensePosture {
    Write-Section "Defense & AV Posture"

    # Windows Defender
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $rtOn = $mpStatus.RealTimeProtectionEnabled
        $tamper = $mpStatus.IsTamperProtected
        $sigAge = $mpStatus.AntivirusSignatureAge
        $poc = "RealTimeProtection: $rtOn`nTamperProtection: $tamper`nSignatureAge: $sigAge days`nAMEngine: $($mpStatus.AMEngineVersion)`nAMProduct: $($mpStatus.AMProductVersion)"

        Add-Finding -Category "Defense Posture" -CheckTitle "Defender Real-Time Protection" `
            -Status $(if($rtOn){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($rtOn){"Enabled"}else{"DISABLED"}) -Severity "Critical" -POCResult $poc `
            -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -Description "Without RT protection, malware runs undetected."

        Add-Finding -Category "Defense Posture" -CheckTitle "Defender Tamper Protection" `
            -Status $(if($tamper){"Pass"}else{"Warning"}) -Expected "Enabled" `
            -Actual $(if($tamper){"Enabled"}else{"Disabled"}) -Severity "High" `
            -POCResult "TamperProtected: $tamper" `
            -Remediation "Enable via Windows Security > Virus & Threat Protection > Tamper Protection"

        Add-Finding -Category "Defense Posture" -CheckTitle "Signature freshness" `
            -Status $(if($sigAge -le 3){"Pass"}elseif($sigAge -le 7){"Warning"}else{"Fail"}) `
            -Expected "3 days or less" -Actual "$sigAge days old" -Severity $(if($sigAge -gt 7){"High"}else{"Medium"}) `
            -POCResult "Sig age: $sigAge days" -Remediation "Update-MpSignature"

        # Exclusions
        try {
            $exc = Get-MpPreference -ErrorAction Stop
            $allExc = @()
            if ($exc.ExclusionPath) { $exc.ExclusionPath | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Path: $_" } }
            if ($exc.ExclusionProcess) { $exc.ExclusionProcess | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Process: $_" } }
            if ($exc.ExclusionExtension) { $exc.ExclusionExtension | Where-Object { $_ -and $_ -notmatch "^N/A" } | ForEach-Object { $allExc += "Ext: $_" } }
            $excDisplay = if ($allExc.Count -gt 0) { $allExc -join "`n" } else { "None (or requires admin to view)" }
            Add-Finding -Category "Defense Posture" -CheckTitle "Defender exclusions" `
                -Status $(if($allExc.Count -eq 0){"Pass"}elseif($allExc.Count -le 3){"Warning"}else{"Fail"}) `
                -Expected "Minimal" -Actual $(if($allExc.Count -eq 0){"None visible"}else{"$($allExc.Count) exclusions"}) `
                -Severity $(if($allExc.Count -gt 5){"High"}else{"Medium"}) `
                -POCResult "Exclusions:`n$excDisplay" `
                -Remediation "Remove unnecessary: Remove-MpPreference -ExclusionPath PATH" `
                -Description "Attackers drop payloads in excluded paths."
        } catch {}
    } catch {
        Add-Finding -Category "Defense Posture" -CheckTitle "Defender status" -Status "Warning" `
            -Actual "Cannot query (may be 3rd party AV)" -Severity "High" `
            -POCResult "Get-MpComputerStatus failed: $($_.Exception.Message)"
    }

    # LSASS protection
    $runAsPPL = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $pplMap = @{0="Disabled";1="Enabled";2="Enabled with UEFI lock (strongest)"}
    $pplOK = $runAsPPL -eq 1 -or $runAsPPL -eq 2
    Add-Finding -Category "Defense Posture" -CheckTitle "LSASS RunAsPPL protection" `
        -Status $(if($pplOK){"Pass"}else{"Fail"}) -Expected "1 or 2 (Enabled)" `
        -Actual $(if($pplOK){"Protected ($($pplMap[[int]$runAsPPL]))"}elseif($null -eq $runAsPPL){"Not configured"}else{"$runAsPPL"}) `
        -Severity "Critical" -POCResult "RunAsPPL = $(if($null -eq $runAsPPL){'Not set'}else{"$runAsPPL ($($pplMap[[int]$runAsPPL]))"}) `nValues: 0=Off, 1=On, 2=On+UEFI lock" `
        -Remediation "reg add HKLM\SYSTEM\...\Lsa /v RunAsPPL /t REG_DWORD /d 2" `
        -ExploitCmd $(if(-not $pplOK){"mimikatz # sekurlsa::logonpasswords (dumps all creds without PPL)"}else{""}) `
        -Description "Without PPL, any admin can dump LSASS for all credentials."

    # AMSI providers
    try {
        $amsi = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        Add-Finding -Category "Defense Posture" -CheckTitle "AMSI providers" `
            -Status $(if($amsi.Count -gt 0){"Pass"}else{"Warning"}) -Expected "1+" `
            -Actual "$($amsi.Count) providers" -Severity "Medium" `
            -POCResult "AMSI providers: $($amsi.Count)" -Remediation "Ensure Defender AMSI integration active." `
            -Description "AMSI scans PowerShell, VBScript, and .NET in memory."
    } catch {}

    # PowerShell logging
    $sbLogging = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    $transcription = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    $moduleLogging = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 0
    $poc = "ScriptBlockLogging: $sbLogging`nTranscription: $transcription`nModuleLogging: $moduleLogging"
    $logScore = ([int]($sbLogging -eq 1)) + ([int]($transcription -eq 1)) + ([int]($moduleLogging -eq 1))
    Add-Finding -Category "Defense Posture" -CheckTitle "PowerShell logging" `
        -Status $(if($logScore -ge 2){"Pass"}elseif($logScore -eq 1){"Warning"}else{"Fail"}) `
        -Expected "All 3 enabled" -Actual "Score: $logScore/3" -Severity "High" -POCResult $poc `
        -Remediation "GPO: Enable ScriptBlock Logging + Transcription + Module Logging" `
        -Description "Without PS logging, attacker scripts are invisible."

    # Sysmon
    try {
        $sysmon = Get-Service Sysmon* -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
        Add-Finding -Category "Defense Posture" -CheckTitle "Sysmon installed" `
            -Status $(if($sysmon){"Pass"}else{"Warning"}) -Expected "Running" `
            -Actual $(if($sysmon){"Running: $($sysmon.Name)"}else{"Not installed"}) `
            -Severity "Medium" -POCResult "Sysmon: $(if($sysmon){$sysmon.Name}else{'Not found'})" `
            -Remediation "Install Sysmon with SwiftOnSecurity config." `
            -Description "Sysmon provides detailed process/network/file telemetry."
    } catch {}

    # Audit policy
    try {
        $auditpol = auditpol /get /category:* 2>$null
        $poc = ($auditpol | Out-String).Trim()
        $noAudit = ($auditpol | Select-String "No Auditing" | Measure-Object).Count
        $total = ($auditpol | Select-String "(Success|Failure|No Auditing)" | Measure-Object).Count
        $coverage = if ($total -gt 0) { [math]::Round((($total - $noAudit) / $total) * 100, 0) } else { 0 }
        Add-Finding -Category "Defense Posture" -CheckTitle "Audit policy coverage" `
            -Status $(if($coverage -ge 80){"Pass"}elseif($coverage -ge 50){"Warning"}else{"Fail"}) `
            -Expected "80%+" -Actual "$coverage% categories audited" -Severity "High" -POCResult $poc `
            -Remediation "GPO: Enable Logon, Privilege Use, Object Access, Policy Change auditing." `
            -Description "Low audit coverage = attacker actions go unlogged."
    } catch {}

    # Command line logging
    $cmdLine = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-Finding -Category "Defense Posture" -CheckTitle "Process command line logging" `
        -Status $(if($cmdLine -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Enabled)" `
        -Actual $(if($cmdLine -eq 1){"Enabled"}else{"Disabled"}) -Severity "Medium" `
        -POCResult "ProcessCreationIncludeCmdLine_Enabled = $cmdLine" `
        -Remediation "GPO: Include command line in process creation events = Enabled"
}


# ============================================================================
# 13. SYSTEM HARDENING
# ============================================================================
function Test-SystemHardening {
    Write-Section "System Hardening"

    # UAC level
    $uacEnable = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    $uacConsent = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    $uacSecure = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    $poc = "EnableLUA=$uacEnable`nConsentPromptBehaviorAdmin=$uacConsent`nPromptOnSecureDesktop=$uacSecure"
    Add-Finding -Category "System Hardening" -CheckTitle "UAC configuration" `
        -Status $(if($uacEnable -eq 1 -and $uacConsent -le 2 -and $uacSecure -eq 1){"Pass"}elseif($uacEnable -eq 1){"Warning"}else{"Fail"}) `
        -Expected "Enabled + Prompt + SecureDesktop" `
        -Actual "UAC=$(if($uacEnable){'On'}else{'OFF'}), Consent=$uacConsent, SecureDesktop=$uacSecure" `
        -Severity $(if($uacEnable -ne 1){"Critical"}else{"High"}) -POCResult $poc `
        -Remediation "GPO: UAC to highest level. ConsentPromptBehaviorAdmin=2." `
        -ExploitCmd $(if($uacEnable -ne 1){"Any process auto-elevates without UAC prompt"}else{""}) `
        -Description "UAC bypasses are easier at lower consent levels."

    # NTLM restrictions
    $ntlmLevel = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    Add-Finding -Category "System Hardening" -CheckTitle "LAN Manager auth level" `
        -Status $(if($ntlmLevel -ge 5){"Pass"}elseif($ntlmLevel -ge 3){"Warning"}else{"Fail"}) `
        -Expected "5 (NTLMv2 only, refuse LM)" -Actual "Level $ntlmLevel" `
        -Severity $(if($ntlmLevel -lt 3){"Critical"}else{"High"}) `
        -POCResult "LmCompatibilityLevel = $ntlmLevel (0=LM+NTLM, 3=NTLMv2, 5=NTLMv2 only)" `
        -Remediation "GPO: Send NTLMv2 response only. Refuse LM & NTLM." `
        -Description "Lower levels allow weaker auth that is easily cracked."

    # Anonymous restrictions
    $restrictAnon = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    $restrictAnonSAM = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1
    Add-Finding -Category "System Hardening" -CheckTitle "Anonymous access restrictions" `
        -Status $(if($restrictAnon -ge 1 -and $restrictAnonSAM -eq 1){"Pass"}else{"Warning"}) `
        -Expected "RestrictAnonymous=1+, RestrictAnonymousSAM=1" `
        -Actual "Anon=$restrictAnon, AnonSAM=$restrictAnonSAM" -Severity "Medium" `
        -POCResult "RestrictAnonymous=$restrictAnon`nRestrictAnonymousSAM=$restrictAnonSAM" `
        -Remediation "GPO: Restrict anonymous enumeration of SAM accounts"

    # Firewall
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $poc = ($fwProfiles | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled) InboundDefault=$($_.DefaultInboundAction) OutboundDefault=$($_.DefaultOutboundAction)" }) -join "`n"
        $allEnabled = ($fwProfiles | Where-Object Enabled -eq $false).Count -eq 0
        Add-Finding -Category "System Hardening" -CheckTitle "Windows Firewall" `
            -Status $(if($allEnabled){"Pass"}else{"Fail"}) -Expected "All profiles enabled" `
            -Actual "$(($fwProfiles|Where-Object{$_.Enabled}).Count)/$(($fwProfiles).Count) enabled" `
            -Severity "High" -POCResult $poc -Remediation "Enable firewall for all profiles." `
            -Description "Disabled firewall exposes all services."
    } catch {}

    # Firewall logging
    try {
        $fwLog = $fwProfiles | Where-Object { $_.LogAllowed -eq $true -or $_.LogBlocked -eq $true }
        Add-Finding -Category "System Hardening" -CheckTitle "Firewall logging" `
            -Status $(if($fwLog.Count -ge 3){"Pass"}elseif($fwLog.Count -gt 0){"Warning"}else{"Fail"}) `
            -Expected "All profiles logging" -Actual "$($fwLog.Count) profiles logging" `
            -Severity "Medium" -Remediation "Enable logging for all firewall profiles."
    } catch {}

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Add-Finding -Category "System Hardening" -CheckTitle "Secure Boot" `
            -Status $(if($sb){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($sb){"Enabled"}else{"Disabled or unsupported"}) -Severity "High" `
            -POCResult "SecureBoot: $sb" -Remediation "Enable in UEFI/BIOS firmware settings." `
            -Description "Without Secure Boot, bootkit/rootkit attacks are possible."
    } catch { Add-Finding -Category "System Hardening" -CheckTitle "Secure Boot" -Status "Info" -Actual "Cannot query" -Severity "High" }

    # BitLocker
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        Add-Finding -Category "System Hardening" -CheckTitle "BitLocker (C:)" `
            -Status $(if($bl.ProtectionStatus -eq "On"){"Pass"}else{"Fail"}) `
            -Expected "On" -Actual $(if($bl){"$($bl.ProtectionStatus) ($($bl.EncryptionMethod))"}else{"Not available"}) `
            -Severity "High" -POCResult "Status: $(if($bl){$bl.ProtectionStatus}else{'N/A'})" `
            -Remediation "Enable BitLocker with TPM." -Description "Unencrypted disk = offline data theft."
    } catch { Add-Finding -Category "System Hardening" -CheckTitle "BitLocker" -Status "Warning" -Actual "Cannot query (may need admin)" -Severity "High" }

    # Credential Guard
    $credGuard = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    $vbs = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    Add-Finding -Category "System Hardening" -CheckTitle "Credential Guard" `
        -Status $(if($credGuard -ge 1){"Pass"}else{"Warning"}) -Expected "Enabled" `
        -Actual $(if($credGuard -ge 1){"Enabled (LsaCfgFlags=$credGuard)"}elseif($null -eq $credGuard){"Not configured"}else{$credGuard}) `
        -Severity "High" -POCResult "LsaCfgFlags=$credGuard`nVBS=$vbs" `
        -Remediation "GPO: Enable Credential Guard with UEFI lock." `
        -Description "Credential Guard isolates LSASS secrets in a hypervisor."

    Add-Finding -Category "System Hardening" -CheckTitle "Virtualization Based Security" `
        -Status $(if($vbs -eq 1){"Pass"}else{"Warning"}) -Expected "1 (Enabled)" `
        -Actual $(if($null -eq $vbs){"Not configured"}else{$vbs}) -Severity "Medium" `
        -POCResult "EnableVirtualizationBasedSecurity = $(if($null -eq $vbs){'Not set'}else{$vbs})" `
        -Remediation "GPO: Enable VBS."

    # DEP/NX
    try {
        $dep = (Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
        $depMap = @{0="Off";1="Essential only";2="All except opt-out";3="Always On"}
        Add-Finding -Category "System Hardening" -CheckTitle "DEP/NX policy" `
            -Status $(if($dep -ge 2){"Pass"}else{"Warning"}) -Expected "2+ (OptOut/AlwaysOn)" `
            -Actual "$dep ($($depMap[[int]$dep]))" -Severity "Medium" `
            -POCResult "DEP policy: $dep = $($depMap[[int]$dep])" `
            -Remediation "bcdedit /set nx AlwaysOn"
    } catch {}

    # Spectre/Meltdown mitigations
    $specCtrl = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
    $specCtrlMask = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask"
    Add-Finding -Category "System Hardening" -CheckTitle "Speculative execution mitigations" `
        -Status $(if($null -ne $specCtrl -and $null -ne $specCtrlMask){"Pass"}else{"Warning"}) `
        -Expected "Configured" -Actual "Override=$(if($null -eq $specCtrl){'Not set'}else{$specCtrl}), Mask=$(if($null -eq $specCtrlMask){'Not set'}else{$specCtrlMask})" `
        -Severity "Medium" -POCResult "FeatureSettingsOverride=$specCtrl`nFeatureSettingsOverrideMask=$specCtrlMask" `
        -Remediation "Apply all Windows updates. Configure via registry per MS guidance."
}


# ============================================================================
# 14. ACCOUNT & PASSWORD POLICY
# ============================================================================
function Test-AccountPolicy {
    Write-Section "Account & Password Policy"

    $poc = ""
    $minLen = $null; $maxAge = $null; $lockThresh = $null; $history = $null
    try {
        $netAccounts = net accounts 2>$null
        if ($LASTEXITCODE -eq 0 -and $netAccounts) {
            $poc = ($netAccounts | Out-String).Trim()
            $minLen = if ($netAccounts -match "Minimum password length:\s+(\d+)") { [int]$Matches[1] } else { $null }
            $maxAge = if ($netAccounts -match "Maximum password age \(days\):\s+(\d+|Unlimited)") { $Matches[1] } else { $null }
            $lockThresh = if ($netAccounts -match "Lockout threshold:\s+(\w+)") { $Matches[1] } else { $null }
            $history = if ($netAccounts -match "Length of password history maintained:\s+(\d+|None)") { $Matches[1] } else { $null }
        }
    } catch {}

    # Fallback: registry-based checks always work for standard users
    if ($null -eq $minLen) {
        $poc = "net accounts unavailable (standard user). Using registry/policy checks."
    }

    # MinPwdLength from SAM (may not be readable) - report what we can
    if ($null -ne $minLen) {
        Add-Finding -Category "Account Policy" -CheckTitle "Minimum password length" `
            -Status $(if($minLen -ge 14){"Pass"}elseif($minLen -ge 8){"Warning"}else{"Fail"}) `
            -Expected "14+ chars (CIS)" -Actual "$minLen characters" -Severity $(if($minLen -lt 8){"Critical"}else{"High"}) `
            -POCResult $poc -Remediation "GPO: Minimum password length = 14"
    }

    if ($null -ne $maxAge) {
        Add-Finding -Category "Account Policy" -CheckTitle "Maximum password age" `
            -Status $(if($maxAge -eq "Unlimited"){"Warning"}elseif([int]$maxAge -le 365){"Pass"}else{"Warning"}) `
            -Expected "365 days or less" -Actual "$maxAge days" -Severity "Medium" `
            -Remediation "GPO: Maximum password age = 365"
    }

    if ($null -ne $lockThresh) {
        Add-Finding -Category "Account Policy" -CheckTitle "Account lockout threshold" `
            -Status $(if($lockThresh -eq "Never"){"Fail"}elseif([int]$lockThresh -le 5){"Pass"}else{"Warning"}) `
            -Expected "5 or fewer (CIS)" -Actual $lockThresh -Severity "High" -POCResult $poc `
            -Remediation "GPO: Account lockout threshold = 5" `
            -ExploitCmd $(if($lockThresh -eq "Never"){"Unlimited password guessing without lockout"}else{""}) `
            -Description "No lockout = unlimited password guessing."
    }

    # Always check blank-password users (works for standard users)
    try {
        $users = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.PasswordRequired -eq $false }
        $poc2 = "PasswordRequired=False: $(if($users){($users|ForEach-Object{$_.Name}) -join ', '}else{'None'})"
        Add-Finding -Category "Account Policy" -CheckTitle "Accounts without password required" `
            -Status $(if($users.Count -eq 0){"Pass"}else{"Fail"}) -Expected "0" `
            -Actual $(if($users.Count -eq 0){"None"}else{"$($users.Count): $(($users|ForEach-Object{$_.Name}) -join ', ')"}) `
            -Severity "Critical" -POCResult $poc2 `
            -Remediation "Set-LocalUser -Name USER -PasswordNotRequired `$false"
    } catch {}

    if ($null -eq $minLen -and $null -eq $lockThresh) {
        Add-Finding -Category "Account Policy" -CheckTitle "Password policy details" -Status "Info" `
            -Expected "Queryable" -Actual "Requires admin or domain membership for full details" `
            -Severity "Informational" -POCResult "net accounts returned error. Run admin script for full password policy." `
            -Remediation "Run CIS_Win11_Admin_BuildReview.ps1 as admin for full policy audit."
    }
}


# ============================================================================
# 15. BROWSER CREDENTIALS
# ============================================================================
function Test-BrowserCredentials {
    Write-Section "Browser Credentials"
    $acc = @(); $det = @()
    foreach ($db in @(
        @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data";B="Chrome"},
        @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data";B="Edge"},
        @{P="$env:APPDATA\Mozilla\Firefox\Profiles";B="Firefox"}
    )) { if ($db.B -eq "Firefox") {
            if (Test-Path $db.P) { Get-ChildItem $db.P -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $lj = "$($_.FullName)\logins.json"
                if (Test-Path $lj) { $acc += "Firefox"; $fi = Get-Item $lj; $det += "$lj ($($fi.Length)b)" } } }
        } else { if (Test-Path $db.P) { $acc += "$($db.B) Login Data"; $fi = Get-Item $db.P; $det += "$($db.P) ($($fi.Length)b)" } } }
    $poc = if ($acc.Count -gt 0) { "Browser DBs:`n$($det -join "`n")" } else { "" }
    Add-Finding -Category "Browser Credentials" -CheckTitle "Browser credential databases" `
        -Status $(if($acc.Count -eq 0){"Pass"}else{"Warning"}) -Expected "Awareness" `
        -Actual $(if($acc.Count -eq 0){"None"}else{"$($acc.Count): $($acc -join ', ')"}) `
        -Severity "Medium" -POCResult $poc `
        -Remediation "Deploy Chrome/Edge policies: disable password saving." `
        -ExploitCmd "SharpChromium.exe logins" -Description "Copy + decrypt offline."
}

# ============================================================================
# 16. MISCELLANEOUS
# ============================================================================
function Test-MiscChecks {
    Write-Section "Miscellaneous"

    # Remote access tools (RMM)
    $rmmTools = @()
    $rmmProcs = @("AnyDesk","TeamViewer","TeamViewer_Service","vncserver","rustdesk","ScreenConnect","ConnectWise",
        "LogMeIn","BeyondTrust","Splashtop","GoToAssist","RemotePC","Atera","DWAgent","meshagent")
    foreach ($rp in $rmmProcs) {
        $p = Get-Process -Name $rp -ErrorAction SilentlyContinue
        if ($p) { $rmmTools += "$rp (PID: $(($p|ForEach-Object{$_.Id}) -join ','))" }
    }
    $rmmServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(AnyDesk|TeamViewer|VNC|RustDesk|ScreenConnect|ConnectWise|LogMeIn|Splashtop)" -and $_.Status -eq "Running" }
    foreach ($rs in $rmmServices) { if ($rmmTools -notmatch $rs.DisplayName) { $rmmTools += "$($rs.DisplayName) (service: $($rs.Name))" } }
    $poc = "Running RMM tools: $(if($rmmTools.Count -gt 0){$rmmTools -join "`n"}else{'None detected'})"
    Add-Finding -Category "Miscellaneous" -CheckTitle "Remote access tools (RMM)" `
        -Status $(if($rmmTools.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None or approved only" `
        -Actual $(if($rmmTools.Count -eq 0){"None detected"}else{"$($rmmTools.Count): $($rmmTools -join ', ')"}) `
        -Severity $(if($rmmTools.Count -gt 0){"High"}else{"Medium"}) -POCResult $poc `
        -Remediation "Remove unapproved remote access tools. Whitelist approved ones." `
        -ExploitCmd $(if($rmmTools.Count -gt 0){"Attackers abuse RMM for persistent remote access"}else{""}) `
        -Description "RMM tools provide full remote control and bypass many security controls."

    # SMBv1 protocol
    $smbv1Client = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4
    $smbv1Server = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 1
    $smbv1Enabled = $smbv1Client -ne 4 -or $smbv1Server -eq 1
    Add-Finding -Category "Miscellaneous" -CheckTitle "SMBv1 protocol" `
        -Status $(if(-not $smbv1Enabled){"Pass"}else{"Fail"}) -Expected "Disabled" `
        -Actual "Client=$(if($smbv1Client -eq 4){'Disabled'}else{'Enabled'}), Server=$(if($smbv1Server -eq 0){'Disabled'}else{'Enabled/Default'})" `
        -Severity "High" -POCResult "mrxsmb10 Start=$smbv1Client (4=disabled)`nSMB1 value=$smbv1Server (0=disabled)" `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" `
        -ExploitCmd $(if($smbv1Enabled){"EternalBlue/WannaCry (MS17-010)"}else{""}) `
        -Description "SMBv1 is vulnerable to EternalBlue and other critical exploits."

    # BITS jobs persistence
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -ne "Transferred" }
        $bitsCount = if ($bitsJobs) { @($bitsJobs).Count } else { 0 }
        Add-Finding -Category "Miscellaneous" -CheckTitle "BITS transfer jobs" `
            -Status $(if($bitsCount -eq 0){"Pass"}else{"Warning"}) -Expected "None active" `
            -Actual "$bitsCount active jobs" -Severity "Medium" `
            -POCResult "Active BITS jobs: $bitsCount$(if($bitsCount -gt 0){"`n$(($bitsJobs|ForEach-Object{"  $($_.DisplayName) State=$($_.JobState)"}) -join "`n")"})" `
            -Remediation "Get-BitsTransfer -AllUsers | Remove-BitsTransfer" `
            -Description "BITS jobs can be used for persistence and data exfiltration."
    } catch { Add-Finding -Category "Miscellaneous" -CheckTitle "BITS jobs" -Status "Info" -Actual "Cannot query (may need admin)" -Severity "Medium" }

    # Accessibility tool hijacking
    $accessHijack = @()
    foreach ($tool in @(
        @{F="C:\Windows\System32\sethc.exe";N="Sticky Keys"},
        @{F="C:\Windows\System32\utilman.exe";N="Utility Manager"},
        @{F="C:\Windows\System32\narrator.exe";N="Narrator"},
        @{F="C:\Windows\System32\magnify.exe";N="Magnifier"},
        @{F="C:\Windows\System32\osk.exe";N="On-Screen Keyboard"}
    )) {
        if (Test-Path $tool.F) {
            $fi = Get-Item $tool.F -ErrorAction SilentlyContinue
            if ($fi -and $fi.VersionInfo.CompanyName -notmatch "Microsoft") {
                $accessHijack += "$($tool.N): NOT Microsoft signed! ($($fi.VersionInfo.CompanyName))"
            }
            $ifeo = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$(Split-Path $tool.F -Leaf)" "Debugger"
            if ($ifeo) { $accessHijack += "$($tool.N): IFEO debugger = $ifeo" }
        }
    }
    Add-Finding -Category "Miscellaneous" -CheckTitle "Accessibility tool hijacking" `
        -Status $(if($accessHijack.Count -eq 0){"Pass"}else{"Fail"}) -Expected "No hijacks" `
        -Actual $(if($accessHijack.Count -eq 0){"All legitimate"}else{"$($accessHijack.Count) suspicious: $($accessHijack -join '; ')"}) `
        -Severity "Critical" -POCResult "Checked: sethc, utilman, narrator, magnify, osk`n$(if($accessHijack.Count -gt 0){$accessHijack -join "`n"}else{'All pass Microsoft signature/IFEO check'})" `
        -Remediation "Restore original binaries. Remove IFEO debuggers." `
        -ExploitCmd $(if($accessHijack.Count -gt 0){"Press Shift 5x at login for SYSTEM shell"}else{""}) `
        -Description "Replaced accessibility tools give SYSTEM shell at login screen."

    # WSL
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    $poc = ""; if ($wsl) { $poc = "WSL: $($wsl.Source)"; try { $d = wsl --list --quiet 2>$null; if ($d) { $poc += "`nDistros: $(($d|Out-String).Trim())" } } catch {} }
    Add-Finding -Category "Miscellaneous" -CheckTitle "WSL installed" `
        -Status $(if($wsl){"Warning"}else{"Pass"}) -Expected "Not installed" `
        -Actual $(if($wsl){"Installed"}else{"No"}) -Severity "Medium" -POCResult $poc `
        -Remediation "dism /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux" `
        -ExploitCmd "wsl -e bash -c 'cat /mnt/c/Windows/System32/config/SAM'" `
        -Description "Bypasses AppLocker, AMSI, most AV."

    # Clipboard
    $ch = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory"
    Add-Finding -Category "Miscellaneous" -CheckTitle "Clipboard history" `
        -Status $(if($ch -eq 0){"Pass"}else{"Warning"}) -Expected "Disabled" `
        -Actual $(if($null -eq $ch){"Not configured (enabled)"}else{$ch}) -Severity "Low" `
        -Remediation "GPO: Allow Clipboard History = Disabled"

    # RDP shadowing
    $rdpShadow = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "Shadow"
    Add-Finding -Category "Miscellaneous" -CheckTitle "RDP session shadowing" `
        -Status $(if($rdpShadow -eq 0){"Pass"}else{"Info"}) -Expected "Disabled" `
        -Actual $(if($null -eq $rdpShadow){"Not configured"}else{$rdpShadow}) -Severity "Low" `
        -Remediation "GPO: Shadow = Disabled"

    # Hotfixes / Update status
    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
        $latest = $hotfixes | Select-Object -First 1
        $daysSince = if ($latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
        $poc = "Total hotfixes: $($hotfixes.Count)`nLatest: $($latest.HotFixID) on $($latest.InstalledOn) ($daysSince days ago)`n"
        $poc += "Recent 5:`n$(($hotfixes|Select-Object -First 5|ForEach-Object{"  $($_.HotFixID) $($_.InstalledOn) $($_.Description)"}) -join "`n")"
        Add-Finding -Category "Miscellaneous" -CheckTitle "Windows Update status" `
            -Status $(if($daysSince -le 30){"Pass"}elseif($daysSince -le 90){"Warning"}else{"Fail"}) `
            -Expected "Updated within 30 days" -Actual "Last update: $daysSince days ago ($($latest.HotFixID))" `
            -Severity $(if($daysSince -gt 90){"Critical"}else{"Medium"}) -POCResult $poc `
            -Remediation "Apply all pending Windows Updates." `
            -Description "Missing patches = known CVE exploitation."
    } catch {}

    # Installed software (for CVE context)
    try {
        $sw = Get-CimInstance Win32_Product -ErrorAction SilentlyContinue | Select-Object -First 30 | Sort-Object Name
        $poc = "Installed software (first 30):`n$(($sw|ForEach-Object{"  $($_.Name) v$($_.Version)"}) -join "`n")"
        Add-Finding -Category "Miscellaneous" -CheckTitle "Software inventory" -Status "Info" `
            -Actual "$($sw.Count) packages inventoried" -Severity "Informational" -POCResult $poc `
            -Remediation "Remove unnecessary software. Keep all updated." `
            -Description "Each installed package is potential attack surface."
    } catch {}

    # Remote SAM enumeration
    $remoteSAM = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
    Add-Finding -Category "Miscellaneous" -CheckTitle "Remote SAM enumeration" `
        -Status $(if($remoteSAM){"Pass"}else{"Warning"}) -Expected "Restricted" `
        -Actual $(if($remoteSAM){"Restricted: $remoteSAM"}else{"Not configured (default allows)"}) `
        -Severity "Medium" -POCResult "RestrictRemoteSAM = $(if($null -eq $remoteSAM){'Not set'}else{$remoteSAM})" `
        -Remediation "GPO: Network access: Restrict clients allowed to make remote calls to SAM"
}


# ============================================================================
# 17. ATTACK PATH SUMMARY
# ============================================================================
function Test-AttackPathSummary {
    Write-Section "Attack Path Summary"
    $fails = $Script:Results | Where-Object Status -eq "Fail"
    $crits = ($fails | Where-Object Severity -eq "Critical").Count
    $highs = ($fails | Where-Object Severity -eq "High").Count
    $paths = $fails | ForEach-Object { "[$($_.Severity)] $($_.CheckTitle)" }
    if ($paths.Count -gt 0) {
        Add-Finding -Category "Attack Path Summary" -CheckTitle "ATTACK PATHS: Critical=$crits, High=$highs, Total=$($paths.Count)" `
            -Status "Fail" -Expected "0" -Actual ($paths -join " | ") -Severity "Critical" `
            -Remediation "Address Critical first."
    } else {
        Add-Finding -Category "Attack Path Summary" -CheckTitle "ATTACK PATH SUMMARY" -Status "Pass" `
            -Expected "Minimal" -Actual "No escalation vectors" -Severity "Informational"
    }
}

# ============================================================================
# HTML REPORT GENERATOR
# ============================================================================
function Generate-Report {
    Write-Section "Generating Report"
    $end = Get-Date; $dur = $end - $Script:StartTime
    $total = $Script:Results.Count
    $pass = ($Script:Results | Where-Object Status -eq "Pass").Count
    $fail = ($Script:Results | Where-Object Status -eq "Fail").Count
    $warn = ($Script:Results | Where-Object Status -eq "Warning").Count
    $pocN = ($Script:Results | Where-Object { $_.POCResult -ne "" }).Count
    $comp = if (($pass+$fail) -gt 0) { [math]::Round(($pass/($pass+$fail))*100,1) } else { 0 }
    $cats = $Script:Results | Group-Object Category | Sort-Object Name
    $ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $rp = Join-Path $OutputPath "LowPriv_Assessment_${Script:ComputerName}_$ts.html"
    $compCol = if ($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}
    $a = [string][char]38

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LowPriv Assessment - $Script:ComputerName</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.ctr{max-width:1400px;margin:0 auto;padding:20px}
.hdr{background:linear-gradient(135deg,#1a1020,#2d1b3d);border-radius:12px;padding:28px;margin-bottom:22px;border:1px solid #7f1d1d}
.hdr h1{font-size:22px;color:#fca5a5}.hdr .sub{color:#94a3b8;font-size:13px}
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
.poc::before{content:"POC EVIDENCE ";font-weight:700;color:#a78bfa}
.crit-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:9px;padding:16px;margin-bottom:18px}
.crit-box h3{color:#f87171;margin-bottom:8px;font-size:14px}
.crit-box ul{list-style:none}.crit-box li{padding:4px 0;color:#fca5a5;font-size:11px;border-bottom:1px solid #2d1318}
.crit-box li:last-child{border-bottom:none}.crit-box li::before{content:"! ";font-weight:bold}
.tb{background:#334155;border:none;color:#94a3b8;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:10px;margin-bottom:8px;margin-right:5px}
.tb:hover{background:#475569;color:#f1f5f9}
.ftr{text-align:center;padding:16px;color:#475569;font-size:10px}
</style></head>
<body><div class="ctr">
<div class="hdr"><h1>Low-Privilege Assessment + POC Evidence</h1>
<div class="sub">Comprehensive attack path + CIS benchmark assessment with live POC</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:ComputerName</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OSVersion</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:OSBuild</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:CurrentUser$(if($isAdmin){' (ADMIN!)'})</div></div>
<div class="mi"><div class="lb">Domain</div><div class="vl">$(if($Script:IsDomainJoined){'Joined'}else{'Standalone'})</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
<div class="mi"><div class="lb">Duration</div><div class="vl">$([math]::Round($dur.TotalSeconds,1))s</div></div>
<div class="mi"><div class="lb">POC Evidence</div><div class="vl" style="color:#a78bfa">$pocN findings</div></div>
</div></div>
<div class="dash">
<div class="sc"><div class="n">$total</div><div class="l">Checks</div></div>
<div class="sc p"><div class="n">$pass</div><div class="l">Pass</div></div>
<div class="sc f"><div class="n">$fail</div><div class="l">Fail</div></div>
<div class="sc w"><div class="n">$warn</div><div class="l">Warn</div></div>
<div class="sc c"><div class="n">${comp}%</div><div class="l">Score</div></div>
<div class="sc poc"><div class="n">$pocN</div><div class="l">POC</div></div>
</div>
"@

    # Critical box
    $cf = $Script:Results | Where-Object { $_.Status -eq "Fail" -and $_.Severity -in @("Critical","High") } | Sort-Object Severity
    if ($cf.Count -gt 0) {
        $html += "<div class=`"crit-box`"><h3>Critical/High Findings ($($cf.Count))</h3><ul>`n"
        foreach ($f in $cf) { $html += "        <li><strong>[$($f.Severity)]</strong> $($f.Category) - $(ConvertTo-HtmlSafe $f.CheckTitle)</li>`n" }
        $html += "    </ul></div>`n"
    }

    $html += "<button class=`"tb`" onclick=`"document.querySelectorAll('.cb').forEach(e=>e.classList.toggle('open'))`">Toggle All</button>`n"

    foreach ($cat in $cats) {
        $cP=($cat.Group|Where-Object Status -eq "Pass").Count; $cF=($cat.Group|Where-Object Status -eq "Fail").Count; $cW=($cat.Group|Where-Object Status -eq "Warning").Count
        $html += "<div class=`"cat`"><div class=`"ch`" onclick=`"this.nextElementSibling.classList.toggle('open')`">"
        $html += "<h3>$($cat.Name) ($($cat.Count))</h3><div class=`"cs`">"
        if($cP){$html+="<span class='cp'>$cP Pass</span>"}; if($cF){$html+="<span class='cf'>$cF Fail</span>"}; if($cW){$html+="<span class='cw'>$cW Warn</span>"}
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

    $html += "<div class=`"ftr`"><p>LowPriv Assessment v4 | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $pocN POC | Authorised use only.</p></div>"
    $html += "</div></body></html>"
    $html | Out-File -FilePath $rp -Encoding UTF8 -Force
    return $rp
}

# ============================================================================
# MAIN
# ============================================================================
function Invoke-Assessment {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  Low-Privilege Assessment v4 + POC" -ForegroundColor Magenta
    Write-Host "  $Script:ComputerName | $Script:CurrentUser | $(Get-Date)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor White

    @({ Test-UserEnumeration },{ Test-WritableLocations },{ Test-CredentialHarvesting },
      { Test-RegistryPersistence },{ Test-TokenPrivileges },{ Test-ApplicationControl },
      { Test-ServiceSecurity },{ Test-NetworkExposure },{ Test-DLLHijacking },
      { Test-ScheduledTaskAbuse },{ Test-NamedPipeVectors },{ Test-DefensePosture },
      { Test-SystemHardening },{ Test-AccountPolicy },{ Test-BrowserCredentials },
      { Test-MiscChecks },{ Test-AttackPathSummary }
    ) | ForEach-Object { try { & $_ } catch { Write-Host "  [!] $_" -ForegroundColor Red } }

    $rp = Generate-Report
    $fc = ($Script:Results|Where-Object Status -eq 'Fail').Count
    $pc = ($Script:Results|Where-Object{$_.POCResult -ne ""}).Count
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host "  DONE | Checks:$($Script:Results.Count) Fail:$fc POC:$pc" -ForegroundColor Green
    Write-Host "  Report: $rp" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White
    $cp = $rp -replace '\.html$','.csv'
    $Script:Results | Export-Csv -Path $cp -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV: $cp" -ForegroundColor Cyan
}

Invoke-Assessment
