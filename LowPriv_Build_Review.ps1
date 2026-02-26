<#
.SYNOPSIS
    Windows 11 Security Build Review - LOW PRIVILEGE (Comprehensive)
.DESCRIPTION
    Complete security assessment covering:
    - All 13 build review task areas (BIOS, FDE, Patching, Services, File System,
      Security Config, Removable Media, Accounts, PrivEsc, Lateral Movement,
      Network, Logging, System Hardening)
    - Full CIS Windows 11 Enterprise Benchmark v4.0 (L1 + L2)
    - Pentest-grade POC evidence with exploit references
    NO ADMIN REQUIRED. Graceful fallbacks where elevation needed. Outputs HTML + CSV.
.PARAMETER OutputPath
    Directory for report output. Defaults to Desktop with smart fallback.
.PARAMETER Level
    CIS benchmark level: 1 (L1 only) or 2 (L1+L2). Default: 2
.EXAMPLE
    .\LowPriv_Build_Review.ps1
    .\LowPriv_Build_Review.ps1 -Level 1 -OutputPath C:\Reports
.NOTES
    Author  : Security Build Tool
    Version : 5.0-LP
    Date    : 2026-02-26
    License : MIT
.LINK
    https://www.cisecurity.org/benchmark/microsoft_windows_desktop
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [ValidateSet(1,2)][int]$Level = 2
)

#region Init
if (-not (Test-Path $OutputPath)) {
    foreach ($fb in @([Environment]::GetFolderPath('Desktop'),"$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\OneDrive\Desktop","$env:USERPROFILE\Documents",$env:USERPROFILE,$env:TEMP)) {
        if ($fb -and (Test-Path $fb)) { $OutputPath = $fb; break } }
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $Script:IsAdmin) { Write-Host "`n  [i] Running as STANDARD USER - some checks will use fallbacks`n" -ForegroundColor Yellow }

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:CN = $env:COMPUTERNAME
$Script:OS = try{(Get-CimInstance Win32_OperatingSystem).Caption}catch{"Unknown"}
$Script:Build = try{(Get-CimInstance Win32_OperatingSystem).BuildNumber}catch{"Unknown"}
$Script:User = "$env:USERDOMAIN\$env:USERNAME"
$Script:Tag = "SBR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$Script:Domain = try{(Get-CimInstance Win32_ComputerSystem).PartOfDomain}catch{$false}
$Script:Level = $Level
#endregion

#region Helpers
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Cat,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet("Pass","Fail","Warning","Info","Error")][string]$Status,
        [string]$Exp="",[string]$Act="",[string]$Desc="",
        [ValidateSet("Critical","High","Medium","Low","Informational")][string]$Sev="Medium",
        [string]$Fix="",[string]$Exploit="",[string]$POC="",[string]$CIS="",[int]$CISLvl=1
    )
    if ($CISLvl -gt $Script:Level) { return }
    $t = if($CIS){"[$CIS] $Check"}else{$Check}
    $null = $Script:Results.Add([PSCustomObject]@{
        Category=$Cat;Check=$t;Status=$Status;Expected=$Exp;Actual=$Act;Description=$Desc
        Severity=$Sev;Remediation=$Fix;Exploit=$Exploit;POC=$POC;CISLevel="L$CISLvl"
    })
}

function Get-RV { param([string]$P,[string]$N,$D=$null)
    try{$v=Get-ItemProperty -Path "Registry::$P" -Name $N -ErrorAction Stop;return $v.$N}catch{return $D}
}

function Safe-Html { param([string]$T)
    if([string]::IsNullOrEmpty($T)){return ''}
    $a=[string][char]38;$dq=[string][char]34
    $T=$T-replace$a,($a+'amp;');$T=$T-replace'<',($a+'lt;');$T=$T-replace'>',($a+'gt;');$T=$T-replace$dq,($a+'quot;');$T
}

function Get-Icacls { param([string]$P) try{(icacls $P 2>$null)-join"`n"}catch{"error"} }

function Test-Write { param([string]$P,[string]$L)
    $f=Join-Path $P "$Script:Tag.txt"
    try{"POC $(Get-Date)"|Out-File $f -Force -EA Stop;$r="WRITE OK: $f"
        Remove-Item $f -Force -EA SilentlyContinue;$r+=" [cleaned]"
        Write-Host "    [POC] $L WRITABLE" -ForegroundColor Red;$r
    }catch{"Blocked: $($_.Exception.Message)"}
}

function WS { param([string]$N) Write-Host "`n[+] $N" -ForegroundColor Cyan }
#endregion


#region 1. BIOS Configuration
function Test-BIOS {
    WS "1. BIOS Configuration"

    try{$sb=Confirm-SecureBootUEFI -EA SilentlyContinue
        Add-Result -Cat "1. BIOS Configuration" -Check "Secure Boot" -Status $(if($sb){"Pass"}else{"Fail"}) `
            -Exp "Enabled" -Act $(if($sb){"Enabled"}else{"Disabled"}) -Sev "High" `
            -Desc "Prevents boot-level malware." -Fix "Enable in UEFI firmware." `
            -Exploit $(if(-not $sb){"Bootkit/rootkit installation"}else{""})
    }catch{Add-Result -Cat "1. BIOS Configuration" -Check "Secure Boot" -Status "Warning" -Act "Cannot query" -Sev "High"}

    try{$tpm=Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm -EA Stop
        $tv=($tpm.SpecVersion -split ",")[0].Trim()
        Add-Result -Cat "1. BIOS Configuration" -Check "TPM version" `
            -Status $(if($tv -ge "2"){"Pass"}elseif($tpm.IsEnabled_InitialValue){"Warning"}else{"Fail"}) `
            -Exp "TPM 2.0" -Act "TPM $tv" -Sev "High" `
            -POC "Enabled=$($tpm.IsEnabled_InitialValue) Activated=$($tpm.IsActivated_InitialValue) Spec=$($tpm.SpecVersion) Mfr=$($tpm.ManufacturerIdTxt)"
    }catch{Add-Result -Cat "1. BIOS Configuration" -Check "TPM" -Status "Fail" -Act "Not detected" -Sev "High" -Fix "Enable TPM in BIOS."}

    $isUEFI=Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    Add-Result -Cat "1. BIOS Configuration" -Check "UEFI boot mode" `
        -Status $(if($isUEFI){"Pass"}else{"Fail"}) -Exp "UEFI" -Act $(if($isUEFI){"UEFI"}else{"Legacy BIOS"}) -Sev "High"

    $vbs=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    $hvci=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
    $poc="VBS=$vbs HVCI=$hvci"
    try{$dg=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -EA SilentlyContinue
        if($dg){$poc+="`nVBSStatus=$($dg.VirtualizationBasedSecurityStatus) Services=$($dg.SecurityServicesRunning -join ',')"}}catch{}
    Add-Result -Cat "1. BIOS Configuration" -Check "Virtualization Based Security" `
        -Status $(if($vbs -eq 1){"Pass"}else{"Warning"}) -Exp "Enabled" -Act $(if($vbs -eq 1){"Enabled"}else{"Not configured"}) `
        -Sev "High" -POC $poc -Fix "GPO: Enable VBS + HVCI."

    try{$bios=Get-CimInstance Win32_BIOS -EA Stop
        Add-Result -Cat "1. BIOS Configuration" -Check "BIOS/Firmware info" -Status "Info" `
            -Act "$($bios.Manufacturer) v$($bios.SMBIOSBIOSVersion)" -Sev "Informational" `
            -POC "Manufacturer=$($bios.Manufacturer)`nVersion=$($bios.SMBIOSBIOSVersion)`nRelease=$($bios.ReleaseDate)`nSerial=$($bios.SerialNumber)"
    }catch{}

    Add-Result -Cat "1. BIOS Configuration" -Check "BIOS/UEFI password" -Status "Info" -Act "MANUAL CHECK" -Sev "High" `
        -Desc "Requires physical inspection." -Fix "Set BIOS supervisor password."
}
#endregion


#region 2. Full Disk Encryption
function Test-FDE {
    WS "2. Full Disk Encryption"
    try{
        $vols=$null;try{$vols=Get-BitLockerVolume -EA Stop}catch{}
        if(-not $vols){try{$bde=manage-bde -status C: 2>$null
            $blSt=if($bde -match "Protection Status:\s+(.+)"){$Matches[1].Trim()}else{"Unknown"}
            $blMt=if($bde -match "Encryption Method:\s+(.+)"){$Matches[1].Trim()}else{"Unknown"}
            Add-Result -Cat "2. Full Disk Encryption" -Check "BitLocker C: (manage-bde)" `
                -Status $(if($blSt -match "On"){"Pass"}else{"Fail"}) -Exp "Protection On" `
                -Act "$blSt ($blMt)" -Sev "High" -POC ($bde|Out-String).Trim()
            return}catch{}}
        if(-not $vols){try{$ev=Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -EA Stop|Where-Object DriveLetter -eq "C:"
            $blSt2=if($ev.ProtectionStatus -eq 1){"On"}else{"Off"}
            Add-Result -Cat "2. Full Disk Encryption" -Check "BitLocker C: (WMI)" `
                -Status $(if($blSt2 -eq "On"){"Pass"}else{"Fail"}) -Exp "On" -Act $blSt2 -Sev "High"
            return}catch{}}
        if(-not $vols){Add-Result -Cat "2. Full Disk Encryption" -Check "BitLocker" -Status "Info" `
            -Act "Cannot query (standard user). Run admin version." -Sev "High";return}
        $vols=Get-BitLockerVolume -EA Stop
        foreach($vol in $vols){
            $isOS=$vol.MountPoint -eq "C:";$keys=($vol.KeyProtector|ForEach-Object{$_.KeyProtectorType})-join ", "
            $hasRecPw=$vol.KeyProtector|Where-Object{$_.KeyProtectorType -eq "RecoveryPassword"}
            $poc="Volume=$($vol.MountPoint) Status=$($vol.ProtectionStatus) Method=$($vol.EncryptionMethod) Pct=$($vol.EncryptionPercentage)% Lock=$($vol.LockStatus) Keys=$keys"
            if($hasRecPw){$poc+="`nRecoveryIDs=$(($hasRecPw|ForEach-Object{$_.KeyProtectorId})-join ', ')"}
            Add-Result -Cat "2. Full Disk Encryption" -Check "BitLocker $($vol.MountPoint)" -CIS $(if($isOS){"18.10.9.1"}else{""}) `
                -Status $(if($vol.ProtectionStatus -eq "On"){"Pass"}else{"Fail"}) `
                -Exp "On (XtsAes256)" -Act "$($vol.ProtectionStatus) ($($vol.EncryptionMethod))" `
                -Sev $(if($isOS){"High"}else{"Medium"}) -POC $poc `
                -Exploit $(if($vol.ProtectionStatus -ne "On"){"Physical access = data theft"}else{""})
            if($isOS -and $vol.ProtectionStatus -eq "On"){
                $strong=$vol.EncryptionMethod -match "(XtsAes256|Aes256)"
                Add-Result -Cat "2. Full Disk Encryption" -Check "Encryption strength $($vol.MountPoint)" `
                    -Status $(if($strong){"Pass"}else{"Warning"}) -Exp "XtsAes256" -Act $vol.EncryptionMethod -Sev "Medium"
            }
        }
        $suspended=$vols|Where-Object{$_.ProtectionStatus -eq "Off" -and $_.VolumeStatus -ne "FullyDecrypted"}
        if($suspended){Add-Result -Cat "2. Full Disk Encryption" -Check "Suspended BitLocker" -Status "Fail" `
            -Act "$($suspended.Count): $(($suspended|ForEach-Object{$_.MountPoint})-join ', ')" -Sev "High" -Fix "Resume-BitLocker"}
    }catch{Add-Result -Cat "2. Full Disk Encryption" -Check "BitLocker" -Status "Fail" -Act "Cannot query: $_" -Sev "High"}
    Add-Result -Cat "2. Full Disk Encryption" -Check "Recovery key backup" -Status "Info" -Act "Verify escrow manually" -Sev "Medium"
}
#endregion


#region 3. OS & Third-Party Patching
function Test-Patching {
    WS "3. OS & Third-Party Patching"
    try{$hf=Get-HotFix -EA SilentlyContinue|Sort-Object InstalledOn -Descending
        $lat=$hf|Select-Object -First 1;$days=if($lat.InstalledOn){((Get-Date)-$lat.InstalledOn).Days}else{999}
        $poc="Total=$($hf.Count) Latest=$($lat.HotFixID) ($days days)`n$(($hf|Select-Object -First 5|ForEach-Object{"  $($_.HotFixID) $($_.InstalledOn)"}) -join "`n")"
        Add-Result -Cat "3. OS Patching" -Check "Windows Update status" -Status $(if($days -le 30){"Pass"}elseif($days -le 90){"Warning"}else{"Fail"}) `
            -Exp "Within 30 days" -Act "$days days ($($lat.HotFixID))" -Sev $(if($days -gt 90){"Critical"}else{"Medium"}) -POC $poc
    }catch{}
    $build=[System.Environment]::OSVersion.Version
    Add-Result -Cat "3. OS Patching" -Check "OS build" -Status "Info" -Act "$($build.Build).$($build.Revision)" -Sev "Informational"
    try{$sw=@()
        foreach($p in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")){
            if(Test-Path $p){Get-ChildItem $p -EA SilentlyContinue|ForEach-Object{$pr=Get-ItemProperty $_.PSPath -EA SilentlyContinue
                if($pr.DisplayName -and $pr.DisplayName -notmatch "^(Update|Security Update|Hotfix)"){$sw+=[PSCustomObject]@{N=$pr.DisplayName;V=$pr.DisplayVersion;P=$pr.Publisher}}}}}
        $sw=$sw|Sort-Object N -Unique
        Add-Result -Cat "3. OS Patching" -Check "Software inventory" -Status "Info" -Act "$($sw.Count) packages" -Sev "Informational" `
            -POC "$(($sw|Select-Object -First 40|ForEach-Object{"$($_.N) v$($_.V) [$($_.P)]"}) -join "`n")"
        $risky=$sw|Where-Object{$_.N -match "(Java \d|Adobe Flash|Adobe Reader \d|Silverlight|Python 2\.|PHP [0-4]\.|OpenSSL 1\.0)"}
        if($risky.Count -gt 0){Add-Result -Cat "3. OS Patching" -Check "Vulnerable/EOL software" -Status "Warning" `
            -Act "$(($risky|ForEach-Object{$_.N})-join ', ')" -Sev "High"}
    }catch{}
    try{$wu=Get-Service wuauserv -EA SilentlyContinue
        Add-Result -Cat "3. OS Patching" -Check "Windows Update service" `
            -Status $(if($wu.Status -eq "Running" -or $wu.StartType -ne "Disabled"){"Pass"}else{"Fail"}) `
            -Act "$($wu.Status)/$($wu.StartType)" -Sev "High"}catch{}
    $ws=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
    Add-Result -Cat "3. OS Patching" -Check "WSUS configuration" -Status "Info" -Act $(if($ws){"WSUS: $ws"}else{"Direct to Microsoft"}) -Sev "Informational"
}
#endregion


#region 4. Local Services + CIS 5.x
function Test-Services {
    WS "4. Local Services"
    $dq=[string][char]34

    # Writable service binaries
    try{$vuln=@();$svcs=Get-CimInstance Win32_Service -EA SilentlyContinue|Where-Object{$_.PathName -and $_.State -eq "Running"}
        foreach($s in $svcs|Select-Object -First 80){$p2=$s.PathName -replace $dq,''
            if($p2 -match '^([a-zA-Z]:\\.+?\.(exe|dll))'){$ep=$Matches[1]
                if(Test-Path $ep){$a=Get-Acl $ep -EA SilentlyContinue
                    if($a){$w=$a.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl)"}
                        if($w){$vuln+="$($s.Name): $ep"}}}}}
        Add-Result -Cat "4. Local Services" -Check "Writable service binaries" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" `
            -Act $(if($vuln.Count -eq 0){"None ($($svcs.Count) scanned)"}else{"$($vuln.Count): $(($vuln|Select-Object -First 3)-join '; ')"}) `
            -Sev "Critical" -POC "Scanned $($svcs.Count) services.`n$(if($vuln){$vuln -join "`n"}else{'None writable.'})" `
            -Exploit "copy payload.exe BINARY; sc stop/start SVC"
    }catch{}

    # Unquoted paths
    try{$uq=Get-CimInstance Win32_Service|Where-Object{$_.PathName -and $_.PathName -notmatch ('^\s*'+$dq) -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\'}
        Add-Result -Cat "4. Local Services" -Check "Unquoted service paths" `
            -Status $(if($uq.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($uq.Count -eq 0){"None"}else{$uq.Count}) -Sev "High" `
            -POC $(if($uq){($uq|Select-Object -First 5|ForEach-Object{"$($_.Name): $($_.PathName)"})-join "`n"}else{""}) `
            -Exploit "copy payload.exe C:\Program.exe"
    }catch{}

    # Weak DACLs
    try{$weakD=@()
        foreach($s in $svcs|Select-Object -First 30){$sd=sc.exe sdshow $s.Name 2>$null|Where-Object{$_ -match "D:"}
            if($sd -match "A;.*?(BU|AU|WD);.*?(WP|WD|GA|GW)"){$weakD+=$s.Name}}
        Add-Result -Cat "4. Local Services" -Check "Weak service DACLs" `
            -Status $(if($weakD.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($weakD.Count -eq 0){"None (30 sampled)"}else{$weakD -join ', '}) -Sev "High"
    }catch{}

    # AlwaysInstallElevated
    $aU=Get-RV "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aM=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aV=$aU -eq 1 -and $aM -eq 1
    Add-Result -Cat "4. Local Services" -Check "AlwaysInstallElevated" `
        -Status $(if($aV){"Fail"}else{"Pass"}) -Exp "Not 1 in both" `
        -Act "HKLM=$(if($null -eq $aM){'N/A'}else{$aM}), HKCU=$(if($null -eq $aU){'N/A'}else{$aU})" `
        -Sev "Critical" -Exploit $(if($aV){"msfvenom -f msi > evil.msi; msiexec /quiet /i evil.msi"}else{""})

    # Service account analysis
    try{$asS=($svcs|Where-Object{$_.StartName -match "LocalSystem|SYSTEM"}).Count
        $asU=$svcs|Where-Object{$_.StartName -and $_.StartName -notmatch "(LocalSystem|SYSTEM|LocalService|NetworkService|LOCAL SERVICE|NETWORK SERVICE)"}
        $poc="SYSTEM=$asS User=$($asU.Count)"
        if($asU.Count -gt 0){$poc+="`n$(($asU|Select-Object -First 10|ForEach-Object{"  $($_.Name) -> $($_.StartName)"})-join "`n")"}
        Add-Result -Cat "4. Local Services" -Check "Service account analysis" -Status $(if($asU.Count -gt 5){"Warning"}else{"Info"}) -Act "SYSTEM=$asS, User=$($asU.Count)" -Sev "Medium" -POC $poc
    }catch{}

    # RMM tools
    $rmm=@()
    foreach($rp in @("AnyDesk","TeamViewer","TeamViewer_Service","vncserver","rustdesk","ScreenConnect","ConnectWise","LogMeIn")){
        $px=Get-Process -Name $rp -EA SilentlyContinue;if($px){$rmm+="$rp (PID:$(($px|ForEach-Object{$_.Id})-join ','))"}}
    $rs2=Get-Service -EA SilentlyContinue|Where-Object{$_.DisplayName -match "(AnyDesk|TeamViewer|VNC|RustDesk|ScreenConnect)" -and $_.Status -eq "Running"}
    foreach($r in $rs2){$rmm+="$($r.DisplayName) (svc)"}
    Add-Result -Cat "4. Local Services" -Check "Remote access tools (RMM)" `
        -Status $(if($rmm.Count -eq 0){"Pass"}else{"Warning"}) -Exp "None or approved" `
        -Act $(if($rmm.Count -eq 0){"None"}else{"$($rmm.Count): $($rmm -join ', ')"}) `
        -Sev $(if($rmm.Count -gt 0){"High"}else{"Medium"}) -POC "RMM: $(if($rmm){$rmm -join "`n"}else{'None'})"

    # CIS 5.x - Disabled services
    $cisSvc=@(
        @{ID="5.2";N="BTAGService";T="Bluetooth Audio Gateway";L=1},@{ID="5.3";N="bthserv";T="Bluetooth Support";L=2},
        @{ID="5.6";N="Browser";T="Computer Browser";L=1},@{ID="5.9";N="MapsBroker";T="Downloaded Maps Manager";L=2},
        @{ID="5.11";N="lfsvc";T="Geolocation";L=2},@{ID="5.14";N="SharedAccess";T="ICS";L=1},
        @{ID="5.16";N="lltdsvc";T="Link-Layer Topology Discovery";L=2},@{ID="5.19";N="LxssManager";T="WSL";L=1},
        @{ID="5.22";N="SSDPSRV";T="SSDP Discovery";L=2},@{ID="5.27";N="RemoteRegistry";T="Remote Registry";L=1},
        @{ID="5.29";N="RpcLocator";T="RPC Locator";L=2},@{ID="5.33";N="SessionEnv";T="RD Configuration";L=2},
        @{ID="5.36";N="Spooler";T="Print Spooler";L=2},@{ID="5.40";N="WinRM";T="WinRM";L=2},
        @{ID="5.41";N="WMPNetworkSvc";T="WMP Network Sharing";L=2},@{ID="5.42";N="PushToInstall";T="PushToInstall";L=2},
        @{ID="5.44";N="WSearch";T="Windows Search";L=2},@{ID="5.45";N="XblAuthManager";T="Xbox Auth";L=2},
        @{ID="5.46";N="XblGameSave";T="Xbox Game Save";L=2}
    )
    foreach($sc in $cisSvc){$svc=Get-Service $sc.N -EA SilentlyContinue
        Add-Result -Cat "4. Local Services" -Check "Ensure '$($sc.T)' disabled" -CIS $sc.ID `
            -Status $(if(-not $svc -or $svc.StartType -eq "Disabled"){"Pass"}else{"Fail"}) -Exp "Disabled" `
            -Act $(if(-not $svc){"Not installed"}else{"$($svc.Status)/$($svc.StartType)"}) -Sev "Medium" `
            -CISLvl $sc.L -Fix "Set-Service $($sc.N) -StartupType Disabled"
    }
}
#endregion


#region 5. File System Review
function Test-FileSystem {
    WS "5. File System Review"

    foreach($sf in @(@{P="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp";D="All Users Startup";S="Critical"},
        @{P="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup";D="Current User Startup";S="Medium"})){
        if(Test-Path $sf.P){try{$acl=Get-Acl $sf.P -EA Stop
            $w=$acl.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)"}
            $items=Get-ChildItem $sf.P -EA SilentlyContinue;$poc="icacls:`n$(Get-Icacls $sf.P)"
            if($w){$poc+="`n$(Test-Write $sf.P $sf.D)"}
            if($items.Count -gt 0){$poc+="`nItems: $(($items|ForEach-Object{$_.Name})-join ', ')"}
            Add-Result -Cat "5. File System" -Check "$($sf.D) permissions" `
                -Status $(if($w){"Fail"}elseif($items.Count -gt 0){"Info"}else{"Pass"}) -Exp "Not writable" `
                -Act "Writable=$(if($w){'YES'}else{'No'}), Items=$($items.Count)" -Sev $sf.S -POC $poc
        }catch{}}}

    # Writable Program Files
    try{$wr=@()
        foreach($pd in @("C:\Program Files","C:\Program Files (x86)")){if(Test-Path $pd){
            Get-ChildItem $pd -Directory -EA SilentlyContinue|Select-Object -First 30|ForEach-Object{
                $da=Get-Acl $_.FullName -EA SilentlyContinue;if($da){$w=$da.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl)" -and $_.AccessControlType -eq "Allow"}
                    if($w){$wr+=$_.FullName}}}}}
        Add-Result -Cat "5. File System" -Check "Writable Program Files" -Status $(if($wr.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" `
            -Act $(if($wr.Count -eq 0){"None"}else{"$($wr.Count): $(($wr|Select-Object -First 5)-join '; ')"}) -Sev "Critical"
    }catch{}

    # Writable PATH dirs
    try{$sp=[Environment]::GetEnvironmentVariable("PATH","Machine")-split ";";$wp=@()
        foreach($d in $sp){if($d -and (Test-Path $d -EA SilentlyContinue)){$a=Get-Acl $d -EA SilentlyContinue
            if($a){$w=$a.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow"}
                if($w){$wp+=$d}}}}
        $poc="PATH dirs: $($sp.Count)"
        if($wp.Count -gt 0){foreach($w in $wp|Select-Object -First 3){$poc+="`n--- $w ---`n$(Get-Icacls $w)`n$(Test-Write $w 'PATH')"}}
        Add-Result -Cat "5. File System" -Check "Writable system PATH dirs" -Status $(if($wp.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" `
            -Act $(if($wp.Count -eq 0){"None"}else{"$($wp.Count): $($wp -join '; ')"}) -Sev "Critical" -POC $poc `
            -Exploit "copy version.dll WRITABLE_PATH\ (DLL hijacking)"
    }catch{}

    # Writable C:\ root
    try{$ca=Get-Acl "C:\" -EA Stop;$cw=$ca.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow"}
        Add-Result -Cat "5. File System" -Check "Writable C:\ root" -Status $(if($cw){"Fail"}else{"Pass"}) -Exp "Restricted" -Act $(if($cw){"Users can write"}else{"Restricted"}) -Sev "High"
    }catch{}

    # Unattend/Sysprep
    $uf=@();foreach($up in @("C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\unattend.xml","C:\Windows\Panther\Autounattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml","C:\Windows\system32\sysprep\Unattend.xml","C:\unattend.xml")){
        if(Test-Path $up -EA SilentlyContinue){try{$null=Get-Content $up -TotalCount 1 -EA Stop;$uf+=$up}catch{}}}
    $poc="";if($uf){foreach($f in $uf){$poc+="=== $f ===`n";try{$c=Get-Content $f -Raw -EA Stop;if($c -match '(?i)password'){$poc+="PASSWORD FOUND`n"}}catch{}}}
    Add-Result -Cat "5. File System" -Check "Deployment files (Unattend/Sysprep)" -Status $(if($uf.Count -eq 0){"Pass"}else{"Fail"}) `
        -Exp "None" -Act $(if($uf.Count -eq 0){"None"}else{$uf -join '; '}) -Sev "Critical" -POC $poc -Exploit "type FILE | findstr /i password"

    # SAM backups + Shadow copies + GPP + Accessibility hijack
    $sam=@();foreach($sp2 in @("C:\Windows\Repair\SAM","C:\Windows\Repair\SYSTEM","C:\Windows\System32\config\RegBack\SAM","C:\Windows\System32\config\RegBack\SYSTEM")){
        if(Test-Path $sp2 -EA SilentlyContinue){try{$null=Get-Content $sp2 -TotalCount 1 -EA Stop;$sam+="$sp2 (READABLE!)"}catch{$sam+="$sp2 (locked)"}}}
    Add-Result -Cat "5. File System" -Check "SAM/SYSTEM backups" -Status $(if(($sam|Where-Object{$_ -match "READABLE"}).Count -gt 0){"Fail"}elseif($sam.Count -gt 0){"Info"}else{"Pass"}) `
        -Exp "None readable" -Act $(if($sam.Count -eq 0){"None"}else{$sam -join '; '}) -Sev "Critical" -Exploit "impacket-secretsdump -sam SAM -system SYSTEM LOCAL"

    try{$vss=@(Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue)
        Add-Result -Cat "5. File System" -Check "Volume shadow copies" -Status $(if($vss.Count -eq 0){"Pass"}else{"Warning"}) `
            -Act "$($vss.Count) shadows" -Sev "High" -Exploit $(if($vss.Count -gt 0){"mklink /d C:\shadow \\?\GLOBALROOT\Device\..."}else{""})
    }catch{}

    $gpp=@();foreach($gp in @("$env:ALLUSERSPROFILE\Microsoft\Group Policy\History","C:\Windows\SYSVOL")){if(Test-Path $gp){
        Get-ChildItem $gp -Recurse -Include "*.xml" -EA SilentlyContinue|Select-Object -First 20|ForEach-Object{
            try{$gc=Get-Content $_.FullName -Raw -EA Stop;if($gc -match "cpassword"){$gpp+=$_.FullName}}catch{}}}}
    Add-Result -Cat "5. File System" -Check "GPP cpassword files" -Status $(if($gpp.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" `
        -Act $(if($gpp.Count -eq 0){"None"}else{$gpp -join '; '}) -Sev "Critical" -Exploit "gpp-decrypt CPASSWORD"

    $ah=@();foreach($tool in @("sethc.exe","utilman.exe","narrator.exe","magnify.exe","osk.exe")){
        $ifeo=Get-RV "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tool" "Debugger"
        if($ifeo){$ah+="$tool IFEO=$ifeo"}
        $fp="C:\Windows\System32\$tool";if(Test-Path $fp){$fi=Get-Item $fp -EA SilentlyContinue;if($fi -and $fi.VersionInfo.CompanyName -notmatch "Microsoft"){$ah+="$tool NOT Microsoft!"}}}
    Add-Result -Cat "5. File System" -Check "Accessibility hijacking" -Status $(if($ah.Count -eq 0){"Pass"}else{"Fail"}) `
        -Exp "None" -Act $(if($ah.Count -eq 0){"Clean"}else{$ah -join '; '}) -Sev "Critical" -Exploit $(if($ah){"Shift 5x at login = SYSTEM"}else{""})
}
#endregion


#region 6. Security Config
function Test-SecurityConfig {
    WS "6. Security Configuration"

    # Defender
    try{$mp=Get-MpComputerStatus -EA Stop;$pref=Get-MpPreference -EA Stop
        $dpoc="RT=$($mp.RealTimeProtectionEnabled) Behav=$($mp.BehaviorMonitorEnabled) IOAV=$($mp.IoavProtectionEnabled) Tamper=$($mp.IsTamperProtected) NIS=$($mp.NISEnabled) SigAge=$($mp.AntivirusSignatureAge)d Engine=$($mp.AMEngineVersion)"
        Add-Result -Cat "6. Security Config" -Check "Real-Time Protection" -CIS "18.10.43.10.1" -Status $(if($mp.RealTimeProtectionEnabled){"Pass"}else{"Fail"}) -Exp "Enabled" -Act $(if($mp.RealTimeProtectionEnabled){"On"}else{"OFF"}) -Sev "Critical" -POC $dpoc
        Add-Result -Cat "6. Security Config" -Check "Tamper Protection" -Status $(if($mp.IsTamperProtected){"Pass"}else{"Fail"}) -Exp "Enabled" -Act $(if($mp.IsTamperProtected){"On"}else{"OFF"}) -Sev "High"
        Add-Result -Cat "6. Security Config" -Check "Behavior Monitoring" -CIS "18.10.43.10.2" -Status $(if($mp.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -Exp "Enabled" -Act $(if($mp.BehaviorMonitorEnabled){"On"}else{"OFF"}) -Sev "High"
        Add-Result -Cat "6. Security Config" -Check "Signature age" -Status $(if($mp.AntivirusSignatureAge -le 3){"Pass"}elseif($mp.AntivirusSignatureAge -le 7){"Warning"}else{"Fail"}) -Exp "3 days" -Act "$($mp.AntivirusSignatureAge) days" -Sev "Medium"
        Add-Result -Cat "6. Security Config" -Check "PUA protection" -CIS "18.10.43.16" -Status $(if($pref.PUAProtection -eq 1){"Pass"}else{"Warning"}) -Exp "1" -Act $pref.PUAProtection -Sev "Medium"
        Add-Result -Cat "6. Security Config" -Check "MAPS cloud protection" -CIS "18.10.43.5.1" -Status $(if($pref.MAPSReporting -ge 1){"Pass"}else{"Fail"}) -Exp "1-2" -Act $pref.MAPSReporting -Sev "Medium"
        $asrA=($pref.AttackSurfaceReductionRules_Actions|Where-Object{$_ -ge 1}).Count
        Add-Result -Cat "6. Security Config" -Check "ASR rules" -CIS "18.10.43.6.1" -Status $(if($asrA -ge 5){"Pass"}else{"Fail"}) -Exp "5+ rules" -Act "$asrA active" -Sev "High"
        Add-Result -Cat "6. Security Config" -Check "Scan type" -CIS "18.10.43.13.1" -Status $(if($pref.ScanParameters -eq 2){"Pass"}else{"Warning"}) -Exp "2 (Full)" -Act $pref.ScanParameters -Sev "Medium" -CISLvl 2
        $allExc=@()
        if($pref.ExclusionPath){$pref.ExclusionPath|Where-Object{$_ -and $_ -notmatch "^N/A"}|ForEach-Object{$allExc+="Path: $_"}}
        if($pref.ExclusionProcess){$pref.ExclusionProcess|Where-Object{$_ -and $_ -notmatch "^N/A"}|ForEach-Object{$allExc+="Proc: $_"}}
        if($pref.ExclusionExtension){$pref.ExclusionExtension|Where-Object{$_ -and $_ -notmatch "^N/A"}|ForEach-Object{$allExc+="Ext: $_"}}
        Add-Result -Cat "6. Security Config" -Check "Defender exclusions" `
            -Status $(if($allExc.Count -eq 0){"Pass"}elseif($allExc.Count -le 3){"Warning"}else{"Fail"}) `
            -Exp "Minimal" -Act $(if($allExc.Count -eq 0){"None"}else{"$($allExc.Count)"}) -Sev "Medium" `
            -POC "Exclusions:`n$(if($allExc){$allExc -join "`n"}else{'None'})" -Exploit $(if($allExc){"Drop payload in excluded path"}else{""})
    }catch{Add-Result -Cat "6. Security Config" -Check "Defender" -Status "Warning" -Act "Cannot query: $_" -Sev "Critical"}

    # Firewall
    try{$fwp=Get-NetFirewallProfile -EA Stop
        foreach($p in $fwp){
            Add-Result -Cat "6. Security Config" -Check "$($p.Name) firewall" -CIS "9.$($p.Name)" -Status $(if($p.Enabled){"Pass"}else{"Fail"}) -Exp "Enabled+Block" `
                -Act "Enabled=$($p.Enabled) In=$($p.DefaultInboundAction)" -Sev "High" -POC "$($p.Name): Enabled=$($p.Enabled) In=$($p.DefaultInboundAction) Out=$($p.DefaultOutboundAction) LogBlocked=$($p.LogBlocked) LogMax=$($p.LogMaxSizeKilobytes)"
            Add-Result -Cat "6. Security Config" -Check "$($p.Name) inbound default" -Status $(if($p.DefaultInboundAction -eq "Block"){"Pass"}else{"Fail"}) -Exp "Block" -Act "$($p.DefaultInboundAction)" -Sev "High"
            Add-Result -Cat "6. Security Config" -Check "$($p.Name) logging" -Status $(if($p.LogBlocked -eq $true){"Pass"}else{"Fail"}) -Exp "LogBlocked=True" -Act "LogBlocked=$($p.LogBlocked) Size=$($p.LogMaxSizeKilobytes)KB" -Sev "Medium"
        }
    }catch{}

    # LSASS + Credential Guard + WDigest
    $ppl=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL";$pplOK=$ppl -eq 1 -or $ppl -eq 2
    $pplMap=@{0="Disabled";1="Enabled";2="Enabled+UEFI lock"}
    Add-Result -Cat "6. Security Config" -Check "LSASS RunAsPPL" -CIS "18.4.7" -Status $(if($pplOK){"Pass"}else{"Fail"}) -Exp "1 or 2" `
        -Act $(if($pplOK){"Protected ($($pplMap[[int]$ppl]))"}else{"Unprotected"}) -Sev "Critical" `
        -POC "RunAsPPL=$(if($null -eq $ppl){'Not set'}else{"$ppl ($($pplMap[[int]$ppl]))"})" -Exploit $(if(-not $pplOK){"mimikatz sekurlsa::logonpasswords"}else{""})
    $cg=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    Add-Result -Cat "6. Security Config" -Check "Credential Guard" -CIS "18.4.1" -Status $(if($cg -ge 1){"Pass"}else{"Fail"}) -Exp "1+" -Act $(if($cg -ge 1){"Enabled ($cg)"}else{"Not configured"}) -Sev "High"
    $wd=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-Result -Cat "6. Security Config" -Check "WDigest plaintext" -CIS "18.4.8" -Status $(if($wd -eq 1){"Fail"}else{"Pass"}) -Exp "0 or not set" -Act $(if($wd -eq 1){"ENABLED!"}else{"Disabled"}) -Sev "Critical" -Exploit $(if($wd -eq 1){"mimikatz sekurlsa::wdigest"}else{""})

    # AMSI + Sysmon + EDR
    try{$amsi=Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -EA SilentlyContinue
        Add-Result -Cat "6. Security Config" -Check "AMSI providers" -Status $(if($amsi.Count -gt 0){"Pass"}else{"Warning"}) -Exp "1+" -Act "$($amsi.Count) providers" -Sev "Medium"}catch{}
    try{$sym=Get-Service Sysmon* -EA SilentlyContinue|Where-Object Status -eq "Running"
        Add-Result -Cat "6. Security Config" -Check "Sysmon" -Status $(if($sym){"Pass"}else{"Warning"}) -Act $(if($sym){$sym.Name}else{"Not installed"}) -Sev "Medium"}catch{}
    $edr=@();foreach($e in @("MsSense","CylanceSvc","csfalconservice","SentinelAgent","CarbonBlack","TaniumClient","Elastic.Agent")){
        $px=Get-Process -Name $e -EA SilentlyContinue;if($px){$edr+=$e}}
    $edrS=Get-Service -EA SilentlyContinue|Where-Object{$_.DisplayName -match "(Defender for Endpoint|CrowdStrike|SentinelOne|Carbon Black|Cylance)" -and $_.Status -eq "Running"}
    foreach($es in $edrS){$edr+=$es.DisplayName}
    Add-Result -Cat "6. Security Config" -Check "EDR/XDR" -Status "Info" -Act $(if($edr){$edr -join ', '}else{"None detected"}) -Sev "Informational"

    # SmartScreen
    $ss=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
    Add-Result -Cat "6. Security Config" -Check "SmartScreen" -CIS "18.10.75.1" -Status $(if($ss -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $ss){"Not configured"}else{$ss}) -Sev "Medium" -CISLvl 1
}
#endregion

#region 7. Removable Media
function Test-RemovableMedia {
    WS "7. Removable Media"
    $usb=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" "Start" 3
    Add-Result -Cat "7. Removable Media" -Check "USB storage driver" -Status $(if($usb -eq 4){"Pass"}else{"Fail"}) -Exp "4 (Disabled)" -Act $(if($usb -eq 4){"Disabled"}else{"Enabled ($usb)"}) -Sev "High" -Exploit $(if($usb -ne 4){"USB data exfiltration"}else{""})
    $dA=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyAll" 0
    $dR=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyRemovable" 0
    Add-Result -Cat "7. Removable Media" -Check "Device install restrictions" -Status $(if($dA -eq 1 -or $dR -eq 1){"Pass"}else{"Fail"}) -Exp "DenyAll or DenyRemovable=1" -Act "DenyAll=$dA DenyRemovable=$dR" -Sev "High"
    $ar=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 0
    $ap=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 0
    Add-Result -Cat "7. Removable Media" -Check "AutoRun disabled" -CIS "18.10.25.1" -Status $(if($ar -eq 255 -or $ap -eq 1){"Pass"}else{"Fail"}) -Exp "255" -Act "NoDriveType=$ar NoAutorun=$ap" -Sev "High" -Exploit $(if($ar -ne 255){"Autorun.inf = auto-execute"}else{""})
    Add-Result -Cat "7. Removable Media" -Check "AutoRun default behavior" -CIS "18.10.25.2" -Status $(if($ap -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $ap -Sev "Medium"
    $dma=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
    Add-Result -Cat "7. Removable Media" -Check "DMA protection" -Status $(if($dma -eq 0){"Pass"}else{"Warning"}) -Act $(if($null -eq $dma){"Not set"}else{$dma}) -Sev "Medium"
    $rw=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_Write" 0
    Add-Result -Cat "7. Removable Media" -Check "Removable storage write" -Status $(if($rw -eq 1){"Pass"}else{"Fail"}) -Exp "Deny_Write=1" -Act $rw -Sev "High"
    $btg=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\FVE" "RDVDenyWriteAccess" 0
    Add-Result -Cat "7. Removable Media" -Check "BitLocker To Go" -Status $(if($btg -eq 1){"Pass"}else{"Warning"}) -Act $(if($btg -eq 1){"Enforced"}else{"Not enforced"}) -Sev "Medium"
}
#endregion


#region 8. Account Config + CIS 1.x/2.x
function Test-AccountConfig {
    WS "8. User Account & Password Config + CIS 1.x/2.x"

    # secedit
    $tmpI=Join-Path $env:TEMP "$Script:Tag.inf";$null=secedit /export /cfg $tmpI /areas SECURITYPOLICY 2>&1
    $sp=if((Test-Path $tmpI) -and (Get-Item $tmpI).Length -gt 100){Get-Content $tmpI}else{@()};Remove-Item $tmpI -Force -EA SilentlyContinue
    # Low-priv: secedit may fail, use net accounts as fallback
    if($sp.Count -eq 0){try{$na=net accounts 2>$null;if($na -and ($na -join "") -match "password"){
        $naPoc=($na|Out-String).Trim()
        $ml2=if($na -match "Minimum password length:\s+(\d+)"){[int]$Matches[1]}else{0}
        $lt2=if($na -match "Lockout threshold:\s+(\S+)"){$Matches[1]}else{"Unknown"}
        $ld2=if($na -match "Lockout duration.*?:\s+(\S+)"){$Matches[1]}else{"Unknown"}
        $hi2=if($na -match "Length of password history.*?:\s+(\S+)"){$Matches[1]}else{"Unknown"}
        Add-Result -Cat "8. Account Config" -Check "Min password length" -CIS "1.1.4" -Status $(if($ml2 -ge 14){"Pass"}elseif($ml2 -ge 8){"Warning"}else{"Fail"}) -Exp "14" -Act "$ml2 chars" -Sev "High" -POC $naPoc
        Add-Result -Cat "8. Account Config" -Check "Lockout threshold" -CIS "1.2.2" -Status $(if($lt2 -match "^\d+$" -and [int]$lt2 -ge 1 -and [int]$lt2 -le 5){"Pass"}else{"Fail"}) -Exp "1-5" -Act $(if($lt2 -eq "Never"){"Never (0)"}else{$lt2}) -Sev "High"
        Add-Result -Cat "8. Account Config" -Check "Lockout duration" -CIS "1.2.1" -Status $(if($ld2 -match "^\d+$" -and [int]$ld2 -ge 15){"Pass"}else{"Fail"}) -Exp "15+ min" -Act "$ld2 min" -Sev "High"
        Add-Result -Cat "8. Account Config" -Check "Password history" -CIS "1.1.1" -Status $(if($hi2 -match "^\d+$" -and [int]$hi2 -ge 24){"Pass"}else{"Fail"}) -Exp "24+" -Act $hi2
    }}catch{}}
    function GSP{param([string]$K);$m=$sp|Select-String "$K\s*=\s*(.+)"|Select-Object -First 1;if($m){$m.Matches[0].Groups[1].Value.Trim()}else{$null}}

    if($sp.Count -gt 0){
        $v=GSP "PasswordHistorySize";Add-Result -Cat "8. Account Config" -Check "Password history" -CIS "1.1.1" -Status $(if([int]$v -ge 24){"Pass"}else{"Fail"}) -Exp "24+" -Act "$v"
        $v=GSP "MaximumPasswordAge";Add-Result -Cat "8. Account Config" -Check "Max password age" -CIS "1.1.2" -Status $(if($v -and [int]$v -ge 1 -and [int]$v -le 365){"Pass"}else{"Fail"}) -Exp "1-365 days" -Act $(if($v -eq 0 -or $v -eq -1){"Never"}else{"$v days"}) -Sev "High"
        $v=GSP "MinimumPasswordAge";Add-Result -Cat "8. Account Config" -Check "Min password age" -CIS "1.1.3" -Status $(if([int]$v -ge 1){"Pass"}else{"Fail"}) -Exp "1+" -Act "$v days"
        $v=GSP "MinimumPasswordLength";Add-Result -Cat "8. Account Config" -Check "Min password length" -CIS "1.1.4" -Status $(if([int]$v -ge 14){"Pass"}elseif([int]$v -ge 8){"Warning"}else{"Fail"}) -Exp "14" -Act "$v chars" -Sev "High"
        $v=GSP "PasswordComplexity";Add-Result -Cat "8. Account Config" -Check "Password complexity" -CIS "1.1.5" -Status $(if([int]$v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $v -Sev "High"
        $v=GSP "ClearTextPassword";Add-Result -Cat "8. Account Config" -Check "Reversible encryption" -CIS "1.1.6" -Status $(if([int]$v -eq 0){"Pass"}else{"Fail"}) -Exp "0" -Act $v -Sev "Critical"
        $v=GSP "LockoutDuration";Add-Result -Cat "8. Account Config" -Check "Lockout duration" -CIS "1.2.1" -Status $(if([int]$v -ge 15){"Pass"}else{"Fail"}) -Exp "15+ min" -Act "$v min" -Sev "High"
        $v=GSP "LockoutBadCount";Add-Result -Cat "8. Account Config" -Check "Lockout threshold" -CIS "1.2.2" -Status $(if([int]$v -ge 1 -and [int]$v -le 5){"Pass"}else{"Fail"}) -Exp "1-5" -Act $(if($v -eq 0){"Never"}else{$v}) -Sev "High" -Exploit $(if($v -eq 0){"Unlimited brute force"}else{""})
        $v=GSP "ResetLockoutCount";Add-Result -Cat "8. Account Config" -Check "Lockout reset" -CIS "1.2.3" -Status $(if([int]$v -ge 15){"Pass"}else{"Fail"}) -Exp "15+ min" -Act "$v min"
    }else{Add-Result -Cat "8. Account Config" -Check "secedit export" -Status "Error" -Act "Failed (account policy checks skipped)" -Sev "High"}

    # Blank + stale + admin + Credential Manager
    try{$bp=Get-LocalUser|Where-Object{$_.Enabled -and $_.PasswordRequired -eq $false}
        Add-Result -Cat "8. Account Config" -Check "Blank password accounts" -Status $(if($bp.Count -eq 0){"Pass"}else{"Fail"}) -Exp "0" -Act $(if($bp.Count -eq 0){"None"}else{($bp|ForEach-Object{$_.Name})-join ', '}) -Sev "Critical" -Exploit $(if($bp){"runas /user:NAME cmd"}else{""})}catch{}
    try{$lu=Get-LocalUser -EA SilentlyContinue;$stale=$lu|Where-Object{$_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90)}
        Add-Result -Cat "8. Account Config" -Check "Stale accounts (90d)" -Status $(if($stale.Count -eq 0){"Pass"}else{"Warning"}) -Act $(if($stale){"$($stale.Count): $(($stale|ForEach-Object{$_.Name})-join ', ')"}else{"None"}) -Sev "Medium"}catch{}
    try{$ag=Get-LocalGroupMember -Group "Administrators" -EA Stop
        Add-Result -Cat "8. Account Config" -Check "Local admins" -Status $(if($ag.Count -le 2){"Pass"}else{"Warning"}) -Exp "2 or fewer" -Act "$($ag.Count): $(($ag|ForEach-Object{$_.Name})-join ', ')" -Sev "Medium" -POC ((net localgroup Administrators 2>$null)-join "`n")}catch{}
    try{$cm=cmdkey /list 2>$null;$cc=($cm|Select-String "Target:"|Measure-Object).Count
        Add-Result -Cat "8. Account Config" -Check "Credential Manager" -Status $(if($cc -eq 0){"Pass"}else{"Warning"}) -Act "$cc stored creds" -Sev "Medium" -POC (($cm|Out-String).Trim()) -Exploit $(if($cc -gt 0){"mimikatz vault::cred"}else{""})}catch{}

    # Guest account
    try{$guest=Get-LocalUser -Name "Guest" -EA Stop
        Add-Result -Cat "8. Account Config" -Check "Guest account" -CIS "2.3.1.2" -Status $(if(-not $guest.Enabled){"Pass"}else{"Fail"}) -Exp "Disabled" -Act $(if($guest.Enabled){"Enabled"}else{"Disabled"}) -Sev "Medium"}catch{}

    # CIS 2.x Security Options (those not already in other sections)
    $v=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser"
    Add-Result -Cat "8. Account Config" -Check "Block Microsoft accounts" -CIS "2.3.1.1" -Status $(if($v -eq 3){"Pass"}else{"Fail"}) -Exp "3" -Act $(if($null -eq $v){"Not configured"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" 1
    Add-Result -Cat "8. Account Config" -Check "Limit blank password to console" -CIS "2.3.1.5" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $v

    # UAC (comprehensive)
    $lua=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    $cab=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    $cbu=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 3
    $psd=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    $eid=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" 1
    $euia=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" 1
    $vacs=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ValidateAdminCodeSignatures" 0
    $ev=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1
    $fat=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" 0
    Add-Result -Cat "8. Account Config" -Check "UAC: Admin Approval Mode" -CIS "2.3.17.1" -Status $(if($lua -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $lua -Sev "Critical" `
        -POC "EnableLUA=$lua ConsentAdmin=$cab ConsentUser=$cbu SecureDesktop=$psd InstallerDetect=$eid UIAccess=$euia CodeSign=$vacs Virtualize=$ev FilterAdmin=$fat"
    Add-Result -Cat "8. Account Config" -Check "UAC: Admin consent prompt" -CIS "2.3.17.2" -Status $(if($cab -eq 2){"Pass"}elseif($cab -le 5){"Warning"}else{"Fail"}) -Exp "2 (consent on secure desktop)" -Act $cab -Sev "High"
    Add-Result -Cat "8. Account Config" -Check "UAC: Standard user prompt" -CIS "2.3.17.3" -Status $(if($cbu -eq 0){"Pass"}else{"Warning"}) -Exp "0 (auto deny)" -Act $cbu -CISLvl 1
    Add-Result -Cat "8. Account Config" -Check "UAC: Secure desktop" -CIS "2.3.17.7" -Status $(if($psd -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $psd -Sev "High"
    Add-Result -Cat "8. Account Config" -Check "UAC: Detect installations" -CIS "2.3.17.4" -Status $(if($eid -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $eid
    Add-Result -Cat "8. Account Config" -Check "UAC: UIAccess secure locations" -CIS "2.3.17.5" -Status $(if($euia -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $euia
    Add-Result -Cat "8. Account Config" -Check "UAC: Signed executables only" -CIS "2.3.17.6" -Status $(if($vacs -eq 1){"Pass"}else{"Warning"}) -Exp "1" -Act $(if($null -eq $vacs){"Not configured"}else{$vacs}) -CISLvl 2
    Add-Result -Cat "8. Account Config" -Check "UAC: Virtualize write failures" -CIS "2.3.17.8" -Status $(if($ev -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $ev

    # AutoLogon + cached logons
    $alp=Get-RV "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $alo=Get-RV "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"
    Add-Result -Cat "8. Account Config" -Check "AutoLogon credentials" -CIS "18.5.1" -Status $(if($alp){"Fail"}else{"Pass"}) -Exp "No password" -Act $(if($alp){"CLEARTEXT PASSWORD"}else{"AutoLogon=$alo"}) -Sev "Critical" -Exploit $(if($alp){"reg query Winlogon (plaintext)"}else{""})
    $cl=Get-RV "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10"
    Add-Result -Cat "8. Account Config" -Check "Cached domain logons" -CIS "2.3.7.5" -Status $(if([int]$cl -le 4){"Pass"}else{"Warning"}) -Exp "4 or fewer" -Act $cl -Sev "Medium"

    # Additional CIS 2.x
    $v=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
    Add-Result -Cat "8. Account Config" -Check "Force audit subcategory" -CIS "2.3.2.1" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
    Add-Result -Cat "8. Account Config" -Check "Don't display last user" -CIS "2.3.7.1" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
    Add-Result -Cat "8. Account Config" -Check "Require CTRL+ALT+DEL" -CIS "2.3.7.2" -Status $(if($v -eq 0 -or $null -eq $v){"Pass"}else{"Fail"}) -Exp "0" -Act $(if($null -eq $v){"Default"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 0
    Add-Result -Cat "8. Account Config" -Check "Machine inactivity limit" -CIS "2.3.7.3" -Status $(if($v -gt 0 -and $v -le 900){"Pass"}else{"Fail"}) -Exp "900 sec" -Act $(if($v -eq 0){"Not set"}else{"$v sec"})
    $mt=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
    Add-Result -Cat "8. Account Config" -Check "Logon message" -CIS "2.3.7.4" -Status $(if($mt){"Pass"}else{"Fail"}) -Exp "Configured" -Act $(if($mt){"Set ($($mt.Length) chars)"}else{"Not set"}) -CISLvl 1
    $sc=Get-RV "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption"
    Add-Result -Cat "8. Account Config" -Check "Smart card removal" -CIS "2.3.7.8" -Status $(if($sc -in @("1","2","3")){"Pass"}else{"Fail"}) -Exp "1-3" -Act $(if($null -eq $sc){"Not set"}else{$sc}) -CISLvl 2
}
#endregion


#region 9. Privilege Escalation
function Test-PrivEsc {
    WS "9. Privilege Escalation"
    try{$wp=whoami /priv 2>$null;$dang=@("SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege","SeDebugPrivilege","SeBackupPrivilege","SeRestorePrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege","SeTcbPrivilege")
        $found=@();foreach($d in $dang){if($wp -match $d){$found+=$d}}
        Add-Result -Cat "9. Privilege Escalation" -Check "Dangerous token privileges" -Status $(if($found.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($found.Count -eq 0){"None"}else{"$($found.Count): $($found -join ', ')"}) -Sev "Critical" -POC "whoami /priv:`n$(($wp|Out-String).Trim())"
    }catch{}
    try{$st=Get-ScheduledTask -EA SilentlyContinue|Where-Object{$_.Principal.UserId -match "SYSTEM|LocalSystem" -and $_.State -ne "Disabled"}
        $dq=[string][char]34;$vuln=@()
        foreach($t in $st|Select-Object -First 50){foreach($a in $t.Actions){if($a.Execute){$te=$a.Execute -replace $dq,''
            if($te -and (Test-Path $te -EA SilentlyContinue)){$ta=Get-Acl $te -EA SilentlyContinue
                if($ta){$w=$ta.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users)" -and $_.FileSystemRights -match "(Write|Modify|FullControl)"}
                    if($w){$vuln+="$($t.TaskName): $te"}}}}}}
        Add-Result -Cat "9. Privilege Escalation" -Check "SYSTEM tasks writable" -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($vuln.Count -eq 0){"None (50 sampled)"}else{$vuln -join '; '}) -Sev "Critical" -POC "SYSTEM tasks: $($st.Count)`n$(if($vuln){$vuln -join "`n"}else{'None writable'})"
    }catch{}
    foreach($rk in @(@{K="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";D="HKLM Run";S="Critical"},@{K="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";D="HKCU Run";S="Medium"})){
        if(Test-Path $rk.K){try{$a=Get-Acl $rk.K -EA Stop;$w=$a.Access|Where-Object{$_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and $_.RegistryRights -match "(WriteKey|SetValue|FullControl)" -and $_.AccessControlType -eq "Allow"}
            Add-Result -Cat "9. Privilege Escalation" -Check "$($rk.D) writable" -Status $(if($w){"Fail"}else{"Pass"}) -Exp "Restricted" -Act $(if($w){"Writable!"}else{"OK"}) -Sev $rk.S}catch{}}}
    $ifeo=@();$ip="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if(Test-Path $ip){Get-ChildItem $ip -EA SilentlyContinue|ForEach-Object{$db=Get-ItemProperty $_.PSPath -Name "Debugger" -EA SilentlyContinue;if($db.Debugger){$ifeo+="$($_.PSChildName): $($db.Debugger)"}}}
    Add-Result -Cat "9. Privilege Escalation" -Check "IFEO debugger hijacks" -Status $(if($ifeo.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($ifeo.Count -eq 0){"None"}else{$ifeo -join '; '}) -Sev "High"
    try{$wmi=@(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -EA SilentlyContinue)
        Add-Result -Cat "9. Privilege Escalation" -Check "WMI persistence" -Status $(if($wmi.Count -eq 0){"Pass"}else{"Warning"}) -Act "$($wmi.Count) consumers$(if($wmi.Count -gt 0){': '+($wmi|ForEach-Object{$_.Name})-join ', '})" -Sev "High"}catch{}
    try{$kd=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -EA Stop
        $kdL=$kd.PSObject.Properties|Where-Object{$_.Name -notmatch "^PS"}|ForEach-Object{$_.Value}
        $miss=@("version.dll","dbghelp.dll","wer.dll","profapi.dll","mswsock.dll")|Where-Object{$_ -notin $kdL}
        Add-Result -Cat "9. Privilege Escalation" -Check "KnownDLLs gaps" -Status $(if($miss.Count -eq 0){"Pass"}else{"Warning"}) -Act "$($miss.Count) not protected: $($miss -join ', ')" -Sev "Medium" -Exploit "copy malicious.dll PATH\version.dll"
    }catch{}
    try{$pipes=@([System.IO.Directory]::GetFiles("\\.\pipe\"));$spPipe=$pipes|Where-Object{$_ -match "spoolss"}
        Add-Result -Cat "9. Privilege Escalation" -Check "Named pipes (PrintSpoofer)" -Status $(if($spPipe){"Warning"}else{"Pass"}) -Act "$($pipes.Count) pipes $(if($spPipe){'(spoolss PRESENT)'}else{'(no spoolss)'})" -Sev "High" `
            -POC "Pipes: $($pipes.Count)`n$(($pipes|Select-Object -First 15|ForEach-Object{[System.IO.Path]::GetFileName($_)})-join "`n")" -Exploit $(if($spPipe){"PrintSpoofer.exe -i -c cmd (SYSTEM)"}else{""})
    }catch{}
    try{$comH=@();foreach($cl in @("{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}","{BCDE0395-E52F-467C-8E3D-C4579291692E}")){$hk=Get-RV "HKCU\SOFTWARE\Classes\CLSID\$cl\InProcServer32" "(default)";if($hk){$comH+="$cl -> $hk"}}
        Add-Result -Cat "9. Privilege Escalation" -Check "COM hijacking" -Status $(if($comH.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($comH.Count -eq 0){"None"}else{$comH -join '; '}) -Sev "High"}catch{}
    try{$alp=Get-AppLockerPolicy -Effective -EA Stop;$rc=($alp.RuleCollections|ForEach-Object{$_.Count}|Measure-Object -Sum).Sum
        Add-Result -Cat "9. Privilege Escalation" -Check "AppLocker" -Status $(if($rc -gt 0){"Pass"}else{"Fail"}) -Act $(if($rc -gt 0){"$rc rules"}else{"Not configured"}) -Sev "High"
    }catch{Add-Result -Cat "9. Privilege Escalation" -Check "AppLocker" -Status "Fail" -Act "Not configured" -Sev "High" -Exploit "Run any EXE from writable path"}
    try{$psv2=Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -EA Stop;$ps2s=if($psv2.State){$psv2.State.ToString()}else{"Unknown"}
        Add-Result -Cat "9. Privilege Escalation" -Check "PowerShell v2" -CIS "18.10.40.1" -Status $(if($ps2s -match "Disabled"){"Pass"}else{"Fail"}) -Exp "Disabled" -Act $ps2s -Sev "High" -Exploit "powershell -version 2 (bypass AMSI+logging)"}catch{}
}
#endregion

#region 10/11. Network & Lateral Movement
function Test-Network {
    WS "10/11. Network & Lateral Movement"
    # SMB signing
    $ss=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    $sc=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 0
    $se=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1
    $ce=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" 1
    $ep=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" 0
    Add-Result -Cat "10. Network Config" -Check "SMB server sign (always)" -CIS "2.3.9.1" -Status $(if($ss -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $ss -Sev "High" -Exploit "ntlmrelayx.py"
    Add-Result -Cat "10. Network Config" -Check "SMB client sign (always)" -CIS "2.3.8.1" -Status $(if($sc -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $sc -Sev "High"
    Add-Result -Cat "10. Network Config" -Check "SMB server sign (if client)" -CIS "2.3.9.2" -Status $(if($se -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $se
    Add-Result -Cat "10. Network Config" -Check "SMB client sign (if server)" -CIS "2.3.8.2" -Status $(if($ce -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $ce
    Add-Result -Cat "10. Network Config" -Check "SMB unencrypted password" -CIS "2.3.8.3" -Status $(if($ep -eq 0){"Pass"}else{"Fail"}) -Exp "0" -Act $ep
    # SMBv1
    $s1c=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4;$s1s=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 1
    Add-Result -Cat "10. Network Config" -Check "SMBv1 protocol" -CIS "18.4.4/18.4.5" -Status $(if($s1c -eq 4 -and $s1s -eq 0){"Pass"}else{"Fail"}) -Exp "Disabled" `
        -Act "Client=$(if($s1c -eq 4){'Off'}else{'On'}) Server=$(if($s1s -eq 0){'Off'}else{'On/Default'})" -Sev "Critical" -Exploit "EternalBlue (MS17-010)" -POC "mrxsmb10=$s1c SMB1=$s1s"
    # LLMNR + NetBIOS + NTLM
    $ll=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
    Add-Result -Cat "10. Network Config" -Check "LLMNR" -CIS "18.6.4.1" -Status $(if($ll -eq 0){"Pass"}else{"Fail"}) -Exp "0" -Act $ll -Sev "High" -Exploit "Responder -I eth0"
    try{$nics=Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -EA SilentlyContinue;$nbtOn=$false
        foreach($n in $nics){$nv=Get-ItemProperty $n.PSPath -Name "NetbiosOptions" -EA SilentlyContinue;if($null -eq $nv -or $nv.NetbiosOptions -ne 2){$nbtOn=$true;break}}
        Add-Result -Cat "10. Network Config" -Check "NetBIOS over TCP/IP" -Status $(if(-not $nbtOn){"Pass"}else{"Warning"}) -Exp "Disabled" -Act $(if($nbtOn){"Enabled"}else{"Disabled"}) -Sev "Medium" -Exploit "Responder NBT-NS"
    }catch{}
    $lm=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    $lmM=@{0="LM+NTLM";1="LM+NTLM,NTLMv2 neg";2="NTLM only";3="NTLMv2 only";4="NTLMv2,refuse LM";5="NTLMv2,refuse LM+NTLM"}
    Add-Result -Cat "10. Network Config" -Check "LAN Manager auth" -CIS "2.3.11.7" -Status $(if($lm -ge 5){"Pass"}elseif($lm -ge 3){"Warning"}else{"Fail"}) -Exp "5" -Act "$lm ($($lmM[[int]$lm]))" -Sev "High" -POC "LmCompatibilityLevel=$lm"
    $ldap=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" 1
    Add-Result -Cat "10. Network Config" -Check "LDAP client signing" -CIS "2.3.11.8" -Status $(if($ldap -ge 1){"Pass"}else{"Fail"}) -Exp "1+" -Act $ldap -Sev "High"
    $mc=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
    Add-Result -Cat "10. Network Config" -Check "NTLM SSP min client" -CIS "2.3.11.10" -Status $(if($mc -eq 537395200){"Pass"}else{"Fail"}) -Exp "537395200" -Act $(if($null -eq $mc){"Not set"}else{$mc}) -CISLvl 1
    $ms=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
    Add-Result -Cat "10. Network Config" -Check "NTLM SSP min server" -CIS "2.3.11.11" -Status $(if($ms -eq 537395200){"Pass"}else{"Fail"}) -Exp "537395200" -Act $(if($null -eq $ms){"Not set"}else{$ms}) -CISLvl 1
    # Anonymous
    $ra=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1;$rb=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    $ea=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0;$np=Get-RV "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    $rsam=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
    Add-Result -Cat "10. Network Config" -Check "Restrict anon SAM" -CIS "2.3.10.2" -Status $(if($ra -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $ra
    Add-Result -Cat "10. Network Config" -Check "Restrict anon SAM+shares" -CIS "2.3.10.3" -Status $(if($rb -ge 1){"Pass"}else{"Fail"}) -Exp "1+" -Act $rb
    Add-Result -Cat "10. Network Config" -Check "Everyone includes anon" -CIS "2.3.10.5" -Status $(if($ea -eq 0){"Pass"}else{"Fail"}) -Exp "0" -Act $ea
    Add-Result -Cat "10. Network Config" -Check "Null session pipes" -CIS "2.3.10.7" -Status $(if(-not $np -or $np.Count -eq 0){"Pass"}else{"Fail"}) -Exp "Empty" -Act $(if($np){$np -join ','}else{"Empty"})
    Add-Result -Cat "10. Network Config" -Check "Restrict remote SAM" -CIS "2.3.10.11" -Status $(if($rsam){"Pass"}else{"Fail"}) -Exp "Configured" -Act $(if($rsam){"Set"}else{"Not configured"})
    # WinRM + RDP
    try{$wr=Get-Service WinRM -EA SilentlyContinue;Add-Result -Cat "10. Network Config" -Check "WinRM" -Status $(if($wr.Status -ne "Running"){"Pass"}else{"Warning"}) -Act $wr.Status -Sev "Medium"}catch{}
    $rdD=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    $rdN=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    $rdE=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"
    Add-Result -Cat "10. Network Config" -Check "RDP NLA" -CIS "18.10.57.3.9.1" -Status $(if($rdD -eq 1 -or $rdN -eq 1){"Pass"}else{"Fail"}) -Exp "NLA required" -Act "RDP=$(if($rdD -eq 0){'On'}else{'Off'}) NLA=$rdN" -Sev "High"
    Add-Result -Cat "10. Network Config" -Check "RDP encryption" -CIS "18.10.57.3.9.2" -Status $(if($rdE -eq 3){"Pass"}else{"Fail"}) -Exp "3 (High)" -Act $(if($null -eq $rdE){"Not set"}else{$rdE})
    # Hardened UNC + CredSSP
    $hunc=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\netlogon"
    Add-Result -Cat "10. Network Config" -Check "Hardened UNC Paths" -CIS "18.6.14.1" -Status $(if($hunc){"Pass"}else{"Warning"}) -Act $(if($hunc){"Set"}else{"Not configured"}) -CISLvl 1
    $co=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle"
    Add-Result -Cat "10. Network Config" -Check "CredSSP Oracle Remediation" -CIS "18.9.4.1" -Status $(if($co -eq 0){"Pass"}else{"Fail"}) -Exp "0" -Act $(if($null -eq $co){"Not configured"}else{$co}) -CISLvl 1
    $apc=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"
    Add-Result -Cat "10. Network Config" -Check "Non-exportable cred delegation" -CIS "18.8.3.1" -Status $(if($apc -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $apc){"Not set"}else{$apc}) -CISLvl 1

    # Lateral Movement
    try{$wp2=(netsh wlan show profiles 2>$null)|Select-String "All User Profile\s*:\s*(.+)"|ForEach-Object{$_.Matches[0].Groups[1].Value.Trim()}
        $wc=@();foreach($pn in $wp2|Select-Object -First 10){$dt=netsh wlan show profile name="$pn" key=clear 2>$null;$kl=$dt|Select-String "Key Content\s*:\s*(.+)";if($kl){$wc+="$pn = $($kl.Matches[0].Groups[1].Value.Trim())"}}
        Add-Result -Cat "11. Lateral Movement" -Check "Wi-Fi stored passwords" -Status $(if($wc.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None extractable" -Act "$($wc.Count) recovered" -Sev "High" -POC $(if($wc){$wc -join "`n"}else{"None"}) -Exploit "netsh wlan show profile key=clear"
    }catch{}
    $dpc=0;foreach($dp in @("C:\Windows\System32\Microsoft\Protect","$env:APPDATA\Microsoft\Protect")){if(Test-Path $dp){try{$dpc+=(Get-ChildItem $dp -Recurse -File -EA SilentlyContinue).Count}catch{}}}
    Add-Result -Cat "11. Lateral Movement" -Check "DPAPI keys" -Status "Info" -Act "$dpc files" -Sev "Medium" -Exploit "mimikatz dpapi::masterkey"
    $rdpR=Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -EA SilentlyContinue
    Add-Result -Cat "11. Lateral Movement" -Check "RDP saved connections" -Status $(if(-not $rdpR){"Pass"}else{"Warning"}) -Act $(if($rdpR){"$($rdpR.Count): $(($rdpR|ForEach-Object{$_.PSChildName})-join ', ')"}else{"None"}) -Sev "Medium"
    $putty=Get-ChildItem "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions" -EA SilentlyContinue
    Add-Result -Cat "11. Lateral Movement" -Check "PuTTY sessions" -Status $(if(-not $putty){"Pass"}else{"Warning"}) -Act $(if($putty){"$($putty.Count) sessions"}else{"None"}) -Sev "Medium"
    $winscp=Get-ChildItem "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions" -EA SilentlyContinue
    Add-Result -Cat "11. Lateral Movement" -Check "WinSCP sessions" -Status $(if(-not $winscp){"Pass"}else{"Fail"}) -Act $(if($winscp){"$($winscp.Count) sessions"}else{"None"}) -Sev "High" -Exploit $(if($winscp){"winscppasswd (weak enc)"}else{""})

    # DNS + proxy + shares + IPv6 + ports
    try{$dns=Get-DnsClientServerAddress -EA SilentlyContinue|Where-Object{$_.ServerAddresses.Count -gt 0}
        Add-Result -Cat "10. Network Config" -Check "DNS config" -Status "Info" -Act "$(($dns|Select-Object -First 4|ForEach-Object{"$($_.InterfaceAlias):$($_.ServerAddresses -join ',')"}) -join '; ')" -Sev "Informational"}catch{}
    $wpad=Get-RV "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoConfigURL"
    $proxy=Get-RV "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
    Add-Result -Cat "10. Network Config" -Check "Proxy/WPAD" -Status $(if($wpad){"Warning"}else{"Info"}) -Act "WPAD=$(if($wpad){$wpad}else{'None'}) Proxy=$(if($proxy){$proxy}else{'None'})" -Exploit $(if($wpad){"WPAD poisoning via Responder"}else{""})
    try{$shares=Get-SmbShare -EA SilentlyContinue|Where-Object{$_.Name -notmatch '^\$|^(ADMIN|IPC|print)\$'};$open=@()
        foreach($sh in $shares){$sa=Get-SmbShareAccess -Name $sh.Name -EA SilentlyContinue;if($sa|Where-Object{$_.AccountName -match "Everyone"}){$open+=$sh.Name}}
        Add-Result -Cat "10. Network Config" -Check "Shares open to Everyone" -Status $(if($open.Count -eq 0){"Pass"}else{"Fail"}) -Act $(if($open.Count -eq 0){"None"}else{$open -join ', '}) -Sev "High"}catch{}
    try{$ip6=Get-NetAdapterBinding -ComponentId ms_tcpip6 -EA SilentlyContinue|Where-Object Enabled
        Add-Result -Cat "10. Network Config" -Check "IPv6" -Status $(if($ip6.Count -eq 0){"Pass"}else{"Info"}) -Act "$($ip6.Count) adapters" -Sev "Low"}catch{}
    try{$lp=Get-NetTCPConnection -State Listen -EA SilentlyContinue|Where-Object{$_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1"}|Sort-Object LocalPort -Unique
        $poc2=($lp|Select-Object -First 20|ForEach-Object{$px=Get-Process -Id $_.OwningProcess -EA SilentlyContinue;"$($_.LocalAddress):$($_.LocalPort) $($px.ProcessName)"})-join "`n"
        Add-Result -Cat "10. Network Config" -Check "Exposed ports" -Status "Info" -Act "$($lp.Count) ports" -Sev "Informational" -POC $poc2}catch{}
}
#endregion

#region 12. Logging & Auditing + CIS 17.x
function Test-Logging {
    WS "12. Logging & Auditing + CIS 17.x"
    $ap=$null;try{$ap=auditpol /get /category:* 2>$null;if(-not $ap -or ($ap -join "") -notmatch "Logon"){$ap=$null}}catch{}
    if(-not $ap){Add-Result -Cat "12. Logging" -Check "Audit policy" -Status "Info" -Act "Cannot query auditpol (standard user). Run admin version." -Sev "High";return}
    $checks=@(
        @{ID="17.1.1";S="Credential Validation";E="Success and Failure"},@{ID="17.2.1";S="Application Group Management";E="Success and Failure"},
        @{ID="17.2.5";S="Security Group Management";E="Success"},@{ID="17.2.6";S="User Account Management";E="Success and Failure"},
        @{ID="17.3.1";S="Process Creation";E="Success"},@{ID="17.5.1";S="Account Lockout";E="Failure"},
        @{ID="17.5.2";S="Logoff";E="Success"},@{ID="17.5.3";S="Logon";E="Success and Failure"},
        @{ID="17.5.4";S="Other Logon/Logoff Events";E="Success and Failure"},@{ID="17.5.6";S="Special Logon";E="Success"},
        @{ID="17.6.1";S="Detailed File Share";E="Failure"},@{ID="17.6.2";S="File Share";E="Success and Failure"},
        @{ID="17.6.3";S="Other Object Access Events";E="Success and Failure"},@{ID="17.6.4";S="Removable Storage";E="Success and Failure"},
        @{ID="17.7.1";S="Audit Policy Change";E="Success"},@{ID="17.7.2";S="Authentication Policy Change";E="Success"},
        @{ID="17.7.3";S="Authorization Policy Change";E="Success"},@{ID="17.7.4";S="MPSSVC Rule-Level Policy Change";E="Success and Failure"},
        @{ID="17.8.1";S="Sensitive Privilege Use";E="Success and Failure"},@{ID="17.9.1";S="IPsec Driver";E="Success and Failure"},
        @{ID="17.9.2";S="Other System Events";E="Success and Failure"},@{ID="17.9.3";S="Security State Change";E="Success"},
        @{ID="17.9.4";S="Security System Extension";E="Success"},@{ID="17.9.5";S="System Integrity";E="Success and Failure"}
    )
    foreach($c in $checks){$line=$ap|Select-String "^\s+$($c.S)\s"|Select-Object -First 1
        $act=if($line){($line -split "\s{2,}")[-1].Trim()}else{"Not found"}
        $pass=$act -match "Success" -and ($c.E -notmatch "Failure" -or $act -match "Failure")
        if($c.E -eq "Failure"){$pass=$act -match "Failure"}
        Add-Result -Cat "12. Logging" -Check $c.S -CIS $c.ID -Status $(if($pass){"Pass"}else{"Fail"}) -Exp $c.E -Act $act -POC "auditpol: $($c.S) = $act"
    }
    $cl=Get-RV "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-Result -Cat "12. Logging" -Check "Command line in events" -CIS "18.9.3.1" -Status $(if($cl -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $cl -Sev "High"
    $sb=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    $tr=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    $ml=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 0
    Add-Result -Cat "12. Logging" -Check "PS Script Block Logging" -CIS "18.10.40.2" -Status $(if($sb -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $sb -Sev "High"
    Add-Result -Cat "12. Logging" -Check "PS Transcription" -CIS "18.10.40.3" -Status $(if($tr -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $tr -Sev "High"
    Add-Result -Cat "12. Logging" -Check "PS Module Logging" -Status $(if($ml -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $ml -Sev "Medium"
    foreach($log in @(@{N="Application";M=32768;C="18.9.27.1.1"},@{N="Security";M=196608;C="18.9.27.2.1"},@{N="System";M=32768;C="18.9.27.3.1"})){
        try{$el=Get-WinEvent -ListLog $log.N -EA Stop
            Add-Result -Cat "12. Logging" -Check "$($log.N) log size" -CIS $log.C -Status $(if($el.MaximumSizeInBytes -ge $log.M){"Pass"}else{"Fail"}) -Exp "$([math]::Round($log.M/1024))KB+" -Act "$([math]::Round($el.MaximumSizeInBytes/1024))KB"}catch{}}
}
#endregion

#region 13. System Hardening + CIS 18.x extras
function Test-Hardening {
    WS "13. System Hardening + CIS 18.x"
    try{$dep=(Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
        Add-Result -Cat "13. System Hardening" -Check "DEP/NX" -Status $(if($dep -ge 2){"Pass"}else{"Warning"}) -Act "$dep" -Sev "Medium"}catch{}
    $aslr=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" 1
    Add-Result -Cat "13. System Hardening" -Check "ASLR" -Status $(if($aslr -ne 0){"Pass"}else{"Fail"}) -Act $(if($null -eq $aslr){"Default"}else{$aslr}) -Sev "Medium"
    $spec=Get-RV "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
    Add-Result -Cat "13. System Hardening" -Check "Spectre mitigations" -Status $(if($null -ne $spec){"Pass"}else{"Warning"}) -Act $(if($null -eq $spec){"Not set"}else{$spec}) -Sev "Medium"
    $ep=Get-ExecutionPolicy -Scope LocalMachine -EA SilentlyContinue
    Add-Result -Cat "13. System Hardening" -Check "PS Execution Policy" -Status $(if($ep -in @("Restricted","AllSigned")){"Pass"}else{"Warning"}) -Exp "AllSigned" -Act $ep -Sev "Medium" -POC "$((Get-ExecutionPolicy -List|Out-String).Trim())"
    $wsl=Get-Command wsl.exe -EA SilentlyContinue
    Add-Result -Cat "13. System Hardening" -Check "WSL" -Status $(if($wsl){"Warning"}else{"Pass"}) -Act $(if($wsl){"Installed"}else{"No"}) -Sev "Medium" -Exploit "WSL bypasses AppLocker/AMSI"
    try{$ci=Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -EA SilentlyContinue
        Add-Result -Cat "13. System Hardening" -Check "WDAC" -Status $(if($ci -and $ci.Count -gt 0){"Pass"}else{"Warning"}) -Act $(if($ci){"Deployed"}else{"Not deployed"}) -Sev "Medium"}catch{}
    try{$bits=@(Get-BitsTransfer -EA SilentlyContinue|Where-Object{$_.JobState -ne "Transferred"})
        Add-Result -Cat "13. System Hardening" -Check "BITS jobs" -Status $(if($bits.Count -eq 0){"Pass"}else{"Warning"}) -Act "$($bits.Count) active" -Sev "Medium"}catch{}
    $crf=@();foreach($d in @("$env:USERPROFILE","C:\Users\Public","C:\ProgramData")){if(Test-Path $d){try{Get-ChildItem $d -Recurse -File -EA SilentlyContinue -Depth 3|Where-Object{$_.Name -match "(password|cred|secret|\.rdp|\.vnc|web\.config)" -and $_.Length -lt 1MB}|Select-Object -First 10|ForEach-Object{try{$c=Get-Content $_.FullName -TotalCount 50 -EA Stop;if(($c -join "`n") -match '(?i)(password|passwd|pwd|credential)\s*[:=]'){$crf+=$_.FullName}}catch{}}}catch{}}}
    Add-Result -Cat "13. System Hardening" -Check "Cleartext credential files" -Status $(if($crf.Count -eq 0){"Pass"}else{"Fail"}) -Exp "None" -Act $(if($crf.Count -eq 0){"None"}else{($crf|Select-Object -First 3)-join '; '}) -Sev "High"
    $br=@();foreach($db in @(@{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data";B="Chrome"},@{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data";B="Edge"})){
        if(Test-Path $db.P){$br+="$($db.B) ($((Get-Item $db.P).Length)b)"}}
    Add-Result -Cat "13. System Hardening" -Check "Browser credential DBs" -Status $(if($br.Count -eq 0){"Pass"}else{"Warning"}) -Act $(if($br.Count -eq 0){"None"}else{$br -join ', '}) -Sev "Medium"
    # CIS 18.x extras
    $v=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
    Add-Result -Cat "13. System Hardening" -Check "Lock screen camera" -CIS "18.1.1.1" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
    Add-Result -Cat "13. System Hardening" -Check "Lock screen slideshow" -CIS "18.1.1.2" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"
    Add-Result -Cat "13. System Hardening" -Check "Password reveal button" -CIS "18.10.12.1" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
    Add-Result -Cat "13. System Hardening" -Check "Consumer experiences" -CIS "18.10.14.1" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
    $v=Get-RV "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork"
    Add-Result -Cat "13. System Hardening" -Check "Device metadata from Internet" -CIS "18.9.7.2" -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Exp "1" -Act $(if($null -eq $v){"Not set"}else{$v}) -CISLvl 1
}
#endregion


#region Attack Summary + Report + Main
function Test-Summary {
    WS "Attack Path Summary"
    $fails=$Script:Results|Where-Object Status -eq "Fail"
    $c=($fails|Where-Object Severity -eq "Critical").Count;$h=($fails|Where-Object Severity -eq "High").Count
    if($fails.Count -gt 0){Add-Result -Cat "00. Summary" -Check "FINDINGS: Critical=$c High=$h Total=$($fails.Count)" `
        -Status "Fail" -Exp "0" -Act (($fails|ForEach-Object{"[$($_.Severity)] $($_.Check)"})-join " | ") -Sev "Critical" -Fix "Address Critical first."}
}

function Build-Report {
    WS "Generating Report"
    $end=Get-Date;$dur=$end-$Script:StartTime
    $tot=$Script:Results.Count;$p=($Script:Results|Where-Object Status -eq "Pass").Count;$f=($Script:Results|Where-Object Status -eq "Fail").Count
    $w=($Script:Results|Where-Object Status -eq "Warning").Count;$poc=($Script:Results|Where-Object{$_.POC -ne ""}).Count
    $comp=if(($p+$f) -gt 0){[math]::Round(($p/($p+$f))*100,1)}else{0};$compC=if($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}
    $cats=$Script:Results|Group-Object Category|Sort-Object Name;$ts=Get-Date -Format "yyyy-MM-dd_HHmmss"
    $rp=Join-Path $OutputPath "LowPriv_Build_Review_${Script:CN}_$ts.html"

    $html=@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Build Review - $Script:CN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.ctr{max-width:1400px;margin:0 auto;padding:20px}.hdr{background:linear-gradient(135deg,#0c1929,#0c2918);border-radius:12px;padding:28px;margin-bottom:22px;border:1px solid #166534}
.hdr h1{font-size:22px;color:#86efac}.hdr .sub{color:#94a3b8;font-size:13px}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:16px}
.mi{background:#1e293b;padding:9px 13px;border-radius:7px;border:1px solid #334155}.mi .lb{font-size:10px;text-transform:uppercase;color:#64748b}.mi .vl{font-size:14px;color:#f1f5f9;font-weight:600}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:22px}
.sc{background:#1e293b;border-radius:9px;padding:16px;text-align:center;border:1px solid #334155}.sc .n{font-size:28px;font-weight:700}.sc .l{font-size:10px;color:#94a3b8;text-transform:uppercase}
.sc.p .n{color:#4ade80}.sc.f .n{color:#f87171}.sc.w .n{color:#fbbf24}.sc.c .n{color:$compC}.sc.poc .n{color:#a78bfa}
.cat{background:#1e293b;border-radius:9px;margin-bottom:12px;border:1px solid #334155;overflow:hidden}
.ch{padding:13px 17px;cursor:pointer;display:flex;justify-content:space-between;align-items:center}.ch:hover{background:#253347}.ch h3{font-size:14px;color:#f1f5f9}
.cs span{font-size:10px;padding:2px 7px;border-radius:9px;font-weight:600;margin-left:3px}.cp{background:#14532d;color:#4ade80}.cf{background:#7f1d1d;color:#f87171}.cw{background:#78350f;color:#fbbf24}
.cb{display:none}.cb.open{display:block}table{width:100%;border-collapse:collapse;font-size:11px}th{background:#0f172a;padding:7px 9px;text-align:left;color:#94a3b8;font-size:9px;text-transform:uppercase}
td{padding:7px 9px;border-bottom:1px solid #1e293b;vertical-align:top}tr:hover td{background:#162032}
.b{padding:2px 7px;border-radius:7px;font-size:9px;font-weight:700;display:inline-block;min-width:42px;text-align:center}
.sP{background:#14532d;color:#4ade80}.sF{background:#7f1d1d;color:#f87171}.sW{background:#78350f;color:#fbbf24}.sI{background:#1e3a5f;color:#60a5fa}.sE{background:#581845;color:#e879f9}
.svC{color:#f87171;font-weight:700}.svH{color:#fb923c;font-weight:600}.svM{color:#fbbf24}.svL{color:#94a3b8}.svN{color:#64748b}
.desc{color:#64748b;font-size:10px;margin-top:2px}.rem{color:#34d399;font-size:10px;margin-top:3px;padding:3px 7px;background:#052e16;border-radius:3px}.rem::before{content:"FIX: ";font-weight:700}
.exp{color:#fb923c;font-size:10px;margin-top:3px;font-family:'Cascadia Code',Consolas,monospace;padding:3px 7px;background:#1c1306;border-radius:3px;white-space:pre-wrap;word-break:break-all}.exp::before{content:"EXPLOIT: ";font-weight:700}
.poc{color:#c4b5fd;font-size:10px;margin-top:4px;padding:5px 8px;background:#1a1030;border:1px solid #6d28d9;border-radius:3px;white-space:pre-wrap;font-family:'Cascadia Code',Consolas,monospace;max-height:250px;overflow-y:auto}.poc::before{content:"EVIDENCE ";font-weight:700;color:#a78bfa}
.crit-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:9px;padding:16px;margin-bottom:18px}.crit-box h3{color:#f87171;margin-bottom:8px;font-size:14px}
.crit-box ul{list-style:none}.crit-box li{padding:4px 0;color:#fca5a5;font-size:11px;border-bottom:1px solid #2d1318}.crit-box li:last-child{border-bottom:none}.crit-box li::before{content:"! ";font-weight:bold}
.tb{background:#334155;border:none;color:#94a3b8;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:10px;margin-bottom:8px;margin-right:5px}.tb:hover{background:#475569;color:#f1f5f9}
.ftr{text-align:center;padding:16px;color:#475569;font-size:10px}
</style></head>
<body><div class="ctr">
<div class="hdr"><h1>Windows Security Build Review (Low-Priv)</h1>
<div class="sub">13 Assessment Areas + CIS L$Script:Level | Standard User + Fallbacks</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:CN</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OS</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:Build</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:User</div></div>
<div class="mi"><div class="lb">Privilege</div><div class="vl" style="color:#fbbf24">$(if($Script:IsAdmin){'ADMIN'}else{'Standard'})</div></div>
<div class="mi"><div class="lb">CIS Level</div><div class="vl" style="color:#c4b5fd">L$Script:Level</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
<div class="mi"><div class="lb">Duration</div><div class="vl">$([math]::Round($dur.TotalSeconds,1))s</div></div>
<div class="mi"><div class="lb">Evidence</div><div class="vl" style="color:#a78bfa">$poc items</div></div>
</div></div>
<div class="dash">
<div class="sc"><div class="n">$tot</div><div class="l">Checks</div></div>
<div class="sc p"><div class="n">$p</div><div class="l">Pass</div></div>
<div class="sc f"><div class="n">$f</div><div class="l">Fail</div></div>
<div class="sc w"><div class="n">$w</div><div class="l">Warn</div></div>
<div class="sc c"><div class="n">${comp}%</div><div class="l">Score</div></div>
<div class="sc poc"><div class="n">$poc</div><div class="l">Evidence</div></div>
</div>
"@
    $cf=$Script:Results|Where-Object{$_.Status -eq "Fail" -and $_.Severity -in @("Critical","High")}|Sort-Object Severity
    if($cf.Count -gt 0){$html+="<div class=`"crit-box`"><h3>Critical/High Findings ($($cf.Count))</h3><ul>`n"
        foreach($fx in $cf){$html+="        <li><strong>[$($fx.Severity)]</strong> $($fx.Category) - $(Safe-Html $fx.Check)</li>`n"}
        $html+="    </ul></div>`n"}
    $html+="<button class=`"tb`" onclick=`"document.querySelectorAll('.cb').forEach(e=>e.classList.toggle('open'))`">Toggle All</button>"
    $html+="<button class=`"tb`" onclick=`"document.querySelectorAll('.cb').forEach(e=>e.classList.remove('open'));document.querySelectorAll('.cf').forEach(e=>{var cb=e.closest('.cs')?.parentElement?.nextElementSibling;if(cb)cb.classList.add('open')})`">Failures Only</button>`n"
    foreach($cat in $cats){$cP=($cat.Group|Where-Object Status -eq "Pass").Count;$cF=($cat.Group|Where-Object Status -eq "Fail").Count;$cW=($cat.Group|Where-Object Status -eq "Warning").Count
        $html+="<div class=`"cat`"><div class=`"ch`" onclick=`"this.nextElementSibling.classList.toggle('open')`">"
        $html+="<h3>$($cat.Name) ($($cat.Count))</h3><div class=`"cs`">"
        if($cP){$html+="<span class='cp'>$cP Pass</span>"};if($cF){$html+="<span class='cf'>$cF Fail</span>"};if($cW){$html+="<span class='cw'>$cW Warn</span>"}
        $html+="</div></div><div class=`"cb$(if($cF -gt 0){' open'})`"><table><thead><tr><th>Status</th><th>Sev</th><th>Check</th><th>Expected</th><th>Actual</th></tr></thead><tbody>`n"
        $sorted=$cat.Group|Sort-Object @{Expression={switch($_.Status){"Fail"{0}"Warning"{1}"Error"{2}"Info"{3}"Pass"{4}}};Ascending=$true}
        foreach($fx in $sorted){$scc=switch($fx.Severity){"Critical"{"svC"}"High"{"svH"}"Medium"{"svM"}"Low"{"svL"}default{"svN"}}
            $stc=switch($fx.Status){"Pass"{"sP"}"Fail"{"sF"}"Warning"{"sW"}"Info"{"sI"}"Error"{"sE"}default{"sI"}}
            $cell=Safe-Html $fx.Check
            if($fx.Description){$cell+="<div class='desc'>$(Safe-Html $fx.Description)</div>"}
            if($fx.Remediation){$cell+="<div class='rem'>$(Safe-Html $fx.Remediation)</div>"}
            if($fx.Exploit){$cell+="<div class='exp'>$(Safe-Html $fx.Exploit)</div>"}
            if($fx.POC){$cell+="<div class='poc'>$(Safe-Html $fx.POC)</div>"}
            $html+="<tr><td><span class=`"b $stc`">$($fx.Status)</span></td><td><span class=`"$scc`">$($fx.Severity)</span></td>"
            $html+="<td>$cell</td><td>$(Safe-Html $fx.Expected)</td><td>$(Safe-Html $fx.Actual)</td></tr>`n"}
        $html+="</tbody></table></div></div>`n"}
    $html+="<div class=`"ftr`"><p>LowPriv Build Review v5.0 | CIS L$Script:Level | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $poc evidence | Authorised use only.</p></div></div></body></html>"
    $html|Out-File -FilePath $rp -Encoding UTF8 -Force;return $rp
}

function Invoke-Review {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  Windows Security Build Review v5.0 (Low-Priv)" -ForegroundColor Magenta
    Write-Host "  13 Task Areas + CIS L$Script:Level + POC Evidence" -ForegroundColor Cyan
    Write-Host "  $Script:CN | $Script:User | $(Get-Date)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor White
    @({Test-BIOS},{Test-FDE},{Test-Patching},{Test-Services},{Test-FileSystem},{Test-SecurityConfig},
      {Test-RemovableMedia},{Test-AccountConfig},{Test-PrivEsc},{Test-Network},{Test-Logging},
      {Test-Hardening},{Test-Summary}
    )|ForEach-Object{try{& $_}catch{Write-Host "  [!] $_" -ForegroundColor Red}}
    $rp=Build-Report;$fc=($Script:Results|Where-Object Status -eq 'Fail').Count;$pc=($Script:Results|Where-Object{$_.POC -ne ""}).Count
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host "  DONE | Checks:$($Script:Results.Count) Fail:$fc Evidence:$pc" -ForegroundColor Green
    Write-Host "  Report: $rp" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White
    $cp=$rp -replace '\.html$','.csv';$Script:Results|Export-Csv -Path $cp -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV: $cp" -ForegroundColor Cyan

    # Policy table (tab-separated, copy-paste ready for reports)
    $tp=$rp -replace '\.html$','_PolicyTable.txt'
    $sb=[System.Text.StringBuilder]::new()
    $tab=[char]9
    $null=$sb.AppendLine("Policy${tab}Description${tab}Configured${tab}Recommended")
    foreach($r in $Script:Results|Where-Object{$_.Status -in @("Fail","Warning")}|Sort-Object Category,Check){
        $pol=$r.Check -replace '\[[\d\.]+\]\s*',''
        $desc=$r.Exploit;if(-not $desc){$desc=$r.Description};if(-not $desc){$desc=$r.Remediation};if(-not $desc){$desc="This setting was not configured per security best practice."}
        $cfg=switch($r.Status){"Fail"{"Disabled"};"Warning"{"Partially Configured"};default{"Disabled"}}
        if($r.Actual -match "Enabled|On|True|Running|1"){$cfg=$r.Actual}
        elseif($r.Actual -match "Disabled|Off|False|0|Not (set|configured)"){$cfg="Disabled"}
        else{$cfg=$r.Actual}
        $rec=$r.Expected;if(-not $rec -or $rec -eq ""){$rec="Enabled"}
        # Clean for TSV
        $pol=$pol -replace "`t"," " -replace "`r",""  -replace "`n"," "
        $desc=$desc -replace "`t"," " -replace "`r","" -replace "`n"," "
        $cfg=$cfg -replace "`t"," " -replace "`r","" -replace "`n"," "
        $rec=$rec -replace "`t"," " -replace "`r","" -replace "`n"," "
        $null=$sb.AppendLine("${pol}${tab}${desc}${tab}${cfg}${tab}${rec}")
    }
    $sb.ToString()|Out-File -FilePath $tp -Encoding UTF8 -Force
    Write-Host "  Policy Table: $tp" -ForegroundColor Cyan
}
Invoke-Review
#endregion
