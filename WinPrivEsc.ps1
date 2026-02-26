<#
.SYNOPSIS
    WinPrivEsc Ultimate - Complete Windows Privilege Escalation Enumeration
.DESCRIPTION
    Single-file solution with 200+ Windows privilege escalation checks.
    Covers all MITRE ATT&CK TA0004 techniques plus modern OS vectors.
    Includes: classic privesc, kernel security, container/cloud, ADCS,
    network attacks, persistence, credential hunting, and more.
.PARAMETER Mode
    Quick    - Fast scan, limited checks
    Standard - Balanced (default)
    Deep     - Thorough, more checks per category
    Stealth  - Minimal filesystem interaction
    Paranoid - Maximum coverage
.PARAMETER SaveReport
    Save text report to file
.PARAMETER JSON
    Export findings as JSON
.EXAMPLE
    .\WinPrivEsc.ps1
    .\WinPrivEsc.ps1 -Mode Deep -SaveReport -JSON
    .\WinPrivEsc.ps1 -Mode Quick -SkipNetworkChecks
.NOTES
    Version: 5.0 | Requires: PowerShell 5.1+ | For authorized use only
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick','Standard','Deep','Stealth','Paranoid')]
    [string]$Mode = 'Standard',
    [switch]$SaveReport,
    [string]$OutputPath = ".\WinPrivEsc_Report.txt",
    [switch]$JSON,
    [string]$JSONPath = ".\WinPrivEsc_Report.json",
    [switch]$NoColor,
    [switch]$SkipNetworkChecks,
    [switch]$SkipContainerChecks,
    [switch]$SkipCloudChecks
)
#Requires -Version 5.1

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:Config = @{
    Version   = '5.0.0'
    StartTime = Get-Date
    Findings  = [System.Collections.ArrayList]::new()
    Statistics = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    SystemInfo = @{}
    Cache      = @{ ACLs = @{}; Services = $null; Processes = $null }
}

$script:ModeConfig = @{
    Quick    = @{ MaxServiceCheck = 50;   MaxProcessCheck = 30;  SkipDeepScans = $true;  NetworkTimeout = 2 }
    Standard = @{ MaxServiceCheck = 200;  MaxProcessCheck = 100; SkipDeepScans = $false; NetworkTimeout = 5 }
    Deep     = @{ MaxServiceCheck = 1000; MaxProcessCheck = 500; SkipDeepScans = $false; NetworkTimeout = 10 }
    Stealth  = @{ MaxServiceCheck = 50;   MaxProcessCheck = 30;  SkipDeepScans = $true;  NoFileSystem = $true; NetworkTimeout = 1 }
    Paranoid = @{ MaxServiceCheck = 2000; MaxProcessCheck = 1000;SkipDeepScans = $false; NetworkTimeout = 15 }
}
$script:CurrentMode = $script:ModeConfig[$Mode]

# ============================================================================
# CORE UTILITY FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Critical','High','Medium','Low','Info','Success','Warning','Error')]
        [string]$Level = 'Info',
        [string]$Category = 'General',
        [int]$ExploitDifficulty = 0,
        [string[]]$MitreTechniques = @(),
        [switch]$Sensitive
    )
    try {
        if ($Sensitive) { $Message = $Message -replace '([A-Za-z0-9+/=]{20,})', '[REDACTED]' }
        $finding = [PSCustomObject]@{
            Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Level            = $Level
            Category         = $Category
            Message          = $Message
            ExploitDifficulty = $ExploitDifficulty
            MitreTechniques  = $MitreTechniques
        }
        [void]$script:Config.Findings.Add($finding)
        if ($script:Config.Statistics.ContainsKey($Level)) { $script:Config.Statistics[$Level]++ }

        if (-not $NoColor) {
            $color = switch ($Level) {
                'Critical' { 'Red' }      'High' { 'Yellow' }    'Medium' { 'Cyan' }
                'Low' { 'Gray' }          'Info' { 'White' }     'Success' { 'Green' }
                'Warning' { 'DarkYellow' } 'Error' { 'Red' }
            }
            $prefix = switch ($Level) {
                'Critical' { '[!!!]' } 'High' { '[!!]' }  'Medium' { '[!]' }
                'Low' { '[*]' }        'Info' { '[i]' }   'Success' { '[+]' }
                'Warning' { '[~]' }    'Error' { '[X]' }
            }
            Write-Host "$prefix $Message" -ForegroundColor $color
            if ($ExploitDifficulty -gt 0) {
                $filled = ([char]0x2588).ToString() * $ExploitDifficulty
                $empty  = ([char]0x2591).ToString() * (5 - $ExploitDifficulty)
                Write-Host "    Exploit Difficulty: $filled$empty ($ExploitDifficulty/5)" -ForegroundColor Gray
            }
            if ($MitreTechniques.Count -gt 0) {
                Write-Host "    MITRE: $($MitreTechniques -join ', ')" -ForegroundColor DarkGray
            }
        } else { Write-Host "[$Level] $Message" }

        if ($SaveReport) {
            Add-Content -Path $OutputPath -Value "[$($finding.Timestamp)] [$Level] $Message" -ErrorAction SilentlyContinue
        }
    } catch { Write-Warning "Logging error: $_" }
}

function Write-SectionHeader {
    param([Parameter(Mandatory)][string]$Title, [string]$Description = '')
    $sep = "=" * 80
    if (-not $NoColor) {
        Write-Host "`n$sep" -ForegroundColor Green
        Write-Host "  $Title" -ForegroundColor Green
        if ($Description) { Write-Host "  $Description" -ForegroundColor DarkGray }
        Write-Host "$sep`n" -ForegroundColor Green
    } else { Write-Host "`n$sep`n  $Title`n$sep`n" }
}

function Get-ACLPermissions {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$FileSystem)
    if ($script:Config.Cache.ACLs.ContainsKey($Path)) { return $script:Config.Cache.ACLs[$Path] }
    try {
        if ($FileSystem -and -not (Test-Path $Path)) { return $null }
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $userSID = $currentUser.User.Value
        $groups = $currentUser.Groups | Select-Object -ExpandProperty Value
        $hasWrite = $false; $hasFullControl = $false; $hasTakeOwnership = $false
        foreach ($access in $acl.Access) {
            try {
                $sid = $access.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                if ($sid -eq $userSID -or $groups -contains $sid) {
                    $rights = $access.FileSystemRights.ToString()
                    if ($rights -match 'FullControl') { $hasFullControl = $true; $hasWrite = $true; break }
                    elseif ($rights -match 'TakeOwnership') { $hasTakeOwnership = $true }
                    elseif ($rights -match 'Write|Modify') { $hasWrite = $true }
                }
            } catch { continue }
        }
        $result = @{ HasWrite = $hasWrite; HasFullControl = $hasFullControl; HasTakeOwnership = $hasTakeOwnership; Owner = $acl.Owner }
        $script:Config.Cache.ACLs[$Path] = $result
        return $result
    } catch { return $null }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# SYSTEM INFORMATION
# ============================================================================

function Get-SystemInformation {
    Write-SectionHeader "SYSTEM INFORMATION" "Host details and patch status"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

        $script:Config.SystemInfo = @{
            Hostname       = $env:COMPUTERNAME
            OS             = $os.Caption
            Build          = $os.BuildNumber
            Architecture   = $os.OSArchitecture
            Domain         = $cs.Domain
            IsDomainJoined = $cs.PartOfDomain
            LastBoot       = $os.LastBootUpTime
            Manufacturer   = $cs.Manufacturer
            Model          = $cs.Model
        }

        Write-Log "OS: $($os.Caption) [$($os.OSArchitecture)]" -Level Info -Category System
        Write-Log "Build: $($os.BuildNumber) | Domain: $($cs.Domain)" -Level Info -Category System
        Write-Log "Manufacturer: $($cs.Manufacturer) | Model: $($cs.Model)" -Level Info -Category System
        Write-Log "Last Boot: $($os.LastBootUpTime)" -Level Info -Category System

        # SecureBoot
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($sb) { Write-Log "SecureBoot: ENABLED" -Level Success -Category System }
            else { Write-Log "SecureBoot: DISABLED - boot exploits possible" -Level High -Category System -ExploitDifficulty 4 }
        } catch { Write-Log "SecureBoot: Could not determine" -Level Info -Category System }

        # Hotfix analysis
        $hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue
        $recent = $hotfixes | Where-Object { $_.InstalledOn -and $_.InstalledOn -gt (Get-Date).AddMonths(-6) }
        Write-Log "Hotfixes: $($hotfixes.Count) total | $($recent.Count) in last 6 months" -Level Info -Category System
        if ($recent.Count -eq 0) {
            Write-Log "No recent patches - UNPATCHED SYSTEM!" -Level Critical -Category Patching -ExploitDifficulty 2
        } elseif ($recent.Count -lt 5) {
            Write-Log "Limited recent patches - review patch status" -Level High -Category Patching
        }

        if (Test-IsAdmin) { Write-Log "Running as ADMINISTRATOR" -Level Success -Category System }
        else { Write-Log "Running as standard user" -Level Info -Category System }
    } catch { Write-Log "Error: $_" -Level Error -Category System }
}

# ============================================================================
# KERNEL SECURITY FEATURES
# ============================================================================

function Get-KernelMitigations {
    Write-SectionHeader "KERNEL SECURITY FEATURES" "Modern Windows protections"
    try {
        # VBS / HVCI / Credential Guard
        try {
            $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            if ($vbs.VirtualizationBasedSecurityStatus -eq 2) { Write-Log "VBS: ENABLED (running)" -Level Success -Category Kernel }
            else { Write-Log "VBS: DISABLED - hypervisor protections unavailable" -Level High -Category Kernel -ExploitDifficulty 2 }

            if ($vbs.CodeIntegrityPolicyEnforcementStatus -eq 2) { Write-Log "HVCI: ENABLED" -Level Success -Category Kernel }
            else { Write-Log "HVCI: DISABLED - kernel memory exploits easier" -Level High -Category Kernel -ExploitDifficulty 2 }

            if ($vbs.CredentialGuardSecurityLevel -ge 1) { Write-Log "Credential Guard: ENABLED" -Level Success -Category Kernel }
            else { Write-Log "Credential Guard: DISABLED - credential theft easier" -Level Critical -Category Kernel -ExploitDifficulty 2 -MitreTechniques @('T1003') }
        } catch { Write-Log "VBS not available" -Level Medium -Category Kernel }

        # DMA Protection
        $dma = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity" -Name AllowedBuses -ErrorAction SilentlyContinue
        if ($dma) { Write-Log "Kernel DMA Protection: ENABLED" -Level Success -Category Kernel }
        else { Write-Log "Kernel DMA Protection: DISABLED" -Level High -Category Kernel -ExploitDifficulty 4 }

        # Test Signing
        $ts = bcdedit /enum 2>$null | Select-String "testsigning"
        if ($ts -match "Yes") {
            Write-Log "Test Signing MODE ENABLED - unsigned drivers loadable!" -Level Critical -Category Kernel -ExploitDifficulty 1 -MitreTechniques @('T1068')
        } else { Write-Log "Driver signature enforcement: Active" -Level Success -Category Kernel }

        # DEP
        $dep = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_Available
        if ($dep) { Write-Log "DEP: Available" -Level Success -Category Kernel }
        else { Write-Log "DEP: DISABLED" -Level Critical -Category Kernel }

        # ASLR
        $aslr = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name MoveImages -ErrorAction SilentlyContinue
        if (-not $aslr -or $aslr.MoveImages -ne 0) { Write-Log "ASLR: ENABLED" -Level Success -Category Kernel }
        else { Write-Log "ASLR: DISABLED" -Level Critical -Category Kernel }

        # CFG
        try {
            $cfg = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
            if ($cfg.CFG.Enable -eq 'ON') { Write-Log "System CFG: ENABLED" -Level Success -Category Kernel }
            else { Write-Log "System CFG: DISABLED" -Level Medium -Category Kernel }
        } catch {}

    } catch { Write-Log "Error: $_" -Level Error -Category Kernel }
}

# ============================================================================
# ADVANCED TOKEN & PRIVILEGE ANALYSIS
# ============================================================================

function Get-AdvancedTokenAnalysis {
    Write-SectionHeader "TOKEN & PRIVILEGE ANALYSIS" "Privileges, groups, integrity level"
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        Write-Log "Username: $($identity.Name) | SID: $($identity.User.Value)" -Level Info -Category Token

        # Integrity Level
        $integLevel = $identity.Groups | Where-Object { $_.Value -match 'S-1-16' }
        if ($integLevel) {
            $level = switch -Regex ($integLevel.Value) {
                'S-1-16-4096'  { 'Low' }
                'S-1-16-8192'  { 'Medium' }
                'S-1-16-8448'  { 'Medium Plus' }
                'S-1-16-12288' { 'High' }
                'S-1-16-16384' { 'System' }
                default        { 'Unknown' }
            }
            Write-Log "Integrity Level: $level" -Level Info -Category Token
        }

        # Dangerous privileges
        $privOutput = whoami /priv /fo csv 2>$null | ConvertFrom-Csv
        $dangerousPrivs = @{
            'SeImpersonatePrivilege'         = @{ Sev = 'Critical'; Diff = 2; Mitre = 'T1134.001'; Desc = 'Token impersonation (PrintSpoofer/Potato)' }
            'SeAssignPrimaryTokenPrivilege'  = @{ Sev = 'Critical'; Diff = 2; Mitre = 'T1134.002'; Desc = 'Primary token assignment' }
            'SeTcbPrivilege'                 = @{ Sev = 'Critical'; Diff = 1; Mitre = 'T1134';     Desc = 'Act as part of OS - instant SYSTEM' }
            'SeDebugPrivilege'               = @{ Sev = 'High';     Diff = 2; Mitre = 'T1055';     Desc = 'Process injection + memory dumping' }
            'SeBackupPrivilege'              = @{ Sev = 'High';     Diff = 2; Mitre = 'T1003.002'; Desc = 'Read SAM/SYSTEM/NTDS.dit' }
            'SeRestorePrivilege'             = @{ Sev = 'High';     Diff = 2; Mitre = 'T1543.003'; Desc = 'Write to protected locations' }
            'SeTakeOwnershipPrivilege'       = @{ Sev = 'High';     Diff = 2; Mitre = 'T1222.001'; Desc = 'Take ownership of any object' }
            'SeLoadDriverPrivilege'          = @{ Sev = 'Critical'; Diff = 3; Mitre = 'T1543.003'; Desc = 'Load kernel drivers (BYOVD)' }
            'SeManageVolumePrivilege'        = @{ Sev = 'High';     Diff = 3; Mitre = 'T1006';     Desc = 'Direct disk access' }
            'SeSecurityPrivilege'            = @{ Sev = 'High';     Diff = 3; Mitre = 'T1562.002'; Desc = 'Manage audit/security logs' }
        }

        foreach ($priv in $privOutput) {
            $pn = $priv.'Privilege Name'
            $ps = $priv.State
            if ($dangerousPrivs.ContainsKey($pn)) {
                $info = $dangerousPrivs[$pn]
                if ($ps -match 'Enabled') {
                    Write-Log "$pn ENABLED - $($info.Desc)" -Level $info.Sev -Category Privileges -ExploitDifficulty $info.Diff -MitreTechniques @($info.Mitre)
                } elseif ($ps -match 'Disabled') {
                    Write-Log "$pn disabled but AVAILABLE (can be enabled)" -Level Medium -Category Privileges -MitreTechniques @($info.Mitre)
                }
            }
        }

        # Critical group memberships
        $groupOutput = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
        $criticalGroups = @{
            'Administrators'         = 'Full system control'
            'Domain Admins'          = 'Full domain control'
            'Enterprise Admins'      = 'Full forest control'
            'Backup Operators'       = 'SeBackupPrivilege'
            'Server Operators'       = 'Service manipulation'
            'DnsAdmins'              = 'DLL injection to SYSTEM'
            'Hyper-V Administrators' = 'VM escape potential'
        }
        foreach ($group in $groupOutput) {
            $gn = $group.'Group Name'
            foreach ($cg in $criticalGroups.Keys) {
                if ($gn -like "*$cg*") {
                    Write-Log "Member of: $gn - $($criticalGroups[$cg])" -Level High -Category Groups -MitreTechniques @('T1078')
                }
            }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Token }
}

# ============================================================================
# CONTAINER & VIRTUALIZATION
# ============================================================================

function Test-ContainerEscapes {
    if ($SkipContainerChecks) { return }
    Write-SectionHeader "CONTAINER & VIRTUALIZATION" "Container/VM escape vectors"
    try {
        if (Test-Path "\\.\pipe\docker_engine") {
            Write-Log "Docker named pipe accessible!" -Level Critical -Category Container -ExploitDifficulty 2 -MitreTechniques @('T1611')
        }
        if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss") {
            Write-Log "WSL installed - check for interop exploits" -Level Medium -Category Container -MitreTechniques @('T1611')
        }
        if ($env:WSL_DISTRO_NAME) {
            Write-Log "RUNNING INSIDE WSL: $($env:WSL_DISTRO_NAME)" -Level High -Category Container
            if (Test-Path "/mnt/c/Windows") { Write-Log "Windows filesystem accessible via /mnt/c" -Level Critical -Category Container }
        }
        if ($env:USERNAME -eq 'WDAGUtilityAccount') {
            Write-Log "RUNNING IN WINDOWS SANDBOX!" -Level High -Category Container
        }

        # VM detection
        $mfr = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        $vmMap = @{ 'VMware' = 'VMware'; 'VirtualBox' = 'VirtualBox'; 'Microsoft Corporation' = 'Hyper-V'; 'QEMU' = 'QEMU/KVM'; 'Xen' = 'Xen' }
        foreach ($k in $vmMap.Keys) {
            if ($mfr -match $k) { Write-Log "VM detected: $($vmMap[$k])" -Level Info -Category Virtualization }
        }

        $vmms = Get-Service vmms -ErrorAction SilentlyContinue
        if ($vmms) { Write-Log "Hyper-V service present" -Level Medium -Category Virtualization }
    } catch { Write-Log "Error: $_" -Level Error -Category Container }
}

# ============================================================================
# CLOUD METADATA SERVICES
# ============================================================================

function Test-CloudMetadata {
    if ($SkipCloudChecks) { return }
    Write-SectionHeader "CLOUD METADATA SERVICES" "Cloud provider metadata endpoints"
    try {
        $t = $script:CurrentMode.NetworkTimeout

        # Azure IMDS
        try {
            $az = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{"Metadata"="true"} -TimeoutSec $t -ErrorAction Stop
            Write-Log "AZURE IMDS ACCESSIBLE!" -Level Critical -Category Cloud -ExploitDifficulty 1 -MitreTechniques @('T1552.005')
            try { Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{"Metadata"="true"} -TimeoutSec $t -ErrorAction Stop
                Write-Log "Managed Identity token retrieved!" -Level Critical -Category Cloud
            } catch {}
        } catch {}

        # AWS
        try {
            Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/" -TimeoutSec $t -ErrorAction Stop
            Write-Log "AWS EC2 METADATA ACCESSIBLE!" -Level Critical -Category Cloud -ExploitDifficulty 1 -MitreTechniques @('T1552.005')
            try {
                $role = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/" -TimeoutSec $t -ErrorAction Stop
                if ($role) { Write-Log "IAM Role: $role - credentials accessible" -Level Critical -Category Cloud }
            } catch {}
        } catch {}

        # GCP
        try {
            Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/" -Headers @{"Metadata-Flavor"="Google"} -TimeoutSec $t -ErrorAction Stop
            Write-Log "GCP METADATA ACCESSIBLE!" -Level Critical -Category Cloud -ExploitDifficulty 1 -MitreTechniques @('T1552.005')
        } catch {}
    } catch { Write-Log "Error: $_" -Level Error -Category Cloud }
}

# ============================================================================
# ALWAYSINSTALLELEVATED
# ============================================================================

function Test-AlwaysInstallElevated {
    Write-SectionHeader "ALWAYSINSTALLELEVATED" "MSI privilege escalation"
    try {
        $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
            Write-Log "AlwaysInstallElevated ENABLED - MSI packages install as SYSTEM!" -Level Critical -Category Configuration -ExploitDifficulty 1 -MitreTechniques @('T1548.002')
        } else { Write-Log "AlwaysInstallElevated not enabled" -Level Success -Category Configuration }
    } catch { Write-Log "Error: $_" -Level Error -Category Configuration }
}

# ============================================================================
# SERVICES - COMPREHENSIVE
# ============================================================================

function Get-VulnerableServices {
    Write-SectionHeader "SERVICE ENUMERATION" "Unquoted paths, writable binaries, weak DACLs"
    try {
        if (-not $script:Config.Cache.Services) {
            $script:Config.Cache.Services = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName }
        }
        $services = $script:Config.Cache.Services | Select-Object -First $script:CurrentMode.MaxServiceCheck
        Write-Log "Analyzing $($services.Count) services..." -Level Info -Category Services
        $vulnCount = 0

        foreach ($svc in $services) {
            $pathName = $svc.PathName; $svcName = $svc.Name
            if ([string]::IsNullOrWhiteSpace($pathName)) { continue }

            # Unquoted path with spaces
            if ($pathName -notmatch '^"' -and $pathName -match '\s' -and $pathName -match '\.exe') {
                $unq = ($pathName -split '\.exe')[0] + '.exe'
                if ($unq -match '\\.*\s.*\\') {
                    $vulnCount++
                    Write-Log "Unquoted Service Path: $svcName" -Level High -Category Services -ExploitDifficulty 3 -MitreTechniques @('T1574.009')
                    Write-Log "  Path: $pathName" -Level Info -Category Services
                }
            }

            # Extract binary
            $bin = if ($pathName -match '^"([^"]+)"') { $matches[1] } else { ($pathName -split '\.exe')[0] + '.exe' }

            # Writable binary
            if (Test-Path $bin -ErrorAction SilentlyContinue) {
                $acl = Get-ACLPermissions -Path $bin -FileSystem
                if ($acl -and $acl.HasWrite) {
                    $vulnCount++
                    Write-Log "Writable Service Binary: $svcName - $bin" -Level Critical -Category Services -ExploitDifficulty 1 -MitreTechniques @('T1543.003')
                }
                # Writable directory
                $pd = Split-Path $bin -Parent
                if ($pd -and (Test-Path $pd)) {
                    $da = Get-ACLPermissions -Path $pd -FileSystem
                    if ($da -and $da.HasWrite) {
                        $vulnCount++
                        Write-Log "Writable Service Directory: $svcName - $pd" -Level High -Category Services -ExploitDifficulty 2 -MitreTechniques @('T1574.010')
                    }
                }
            }

            # Writable registry key
            $rp = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            if (Test-Path $rp) {
                $ra = Get-ACLPermissions -Path $rp
                if ($ra -and $ra.HasWrite) {
                    $vulnCount++
                    Write-Log "Writable Service Registry: $svcName" -Level Critical -Category Services -ExploitDifficulty 1 -MitreTechniques @('T1574.011')
                }
            }
        }

        # Service failure actions (from file 1)
        foreach ($svc in ($services | Where-Object { $_.StartMode -eq 'Auto' } | Select-Object -First 20)) {
            try {
                $fa = sc.exe qfailure $svc.Name 2>$null
                if ($fa -match 'COMMAND_LINE.*\.exe') {
                    Write-Log "Service failure command: $($svc.Name)" -Level Medium -Category Services
                }
            } catch {}
        }

        if ($vulnCount -eq 0) { Write-Log "No vulnerable services detected" -Level Success -Category Services }
        else { Write-Log "Found $vulnCount vulnerable service configurations" -Level Critical -Category Services }
    } catch { Write-Log "Error: $_" -Level Error -Category Services }
}

# ============================================================================
# SCHEDULED TASKS
# ============================================================================

function Get-VulnerableScheduledTasks {
    Write-SectionHeader "SCHEDULED TASKS" "Task permissions and configurations"
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
        if (-not $tasks) { Write-Log "No scheduled tasks found" -Level Info -Category Tasks; return }
        $vulnCount = 0

        foreach ($task in ($tasks | Select-Object -First $script:CurrentMode.MaxServiceCheck)) {
            if ($task.Principal.UserId -notmatch 'SYSTEM|Administrators|BUILTIN') { continue }
            foreach ($action in $task.Actions) {
                if (-not $action.Execute) { continue }
                $ep = [Environment]::ExpandEnvironmentVariables(($action.Execute -replace '"',''))
                if (Test-Path $ep -ErrorAction SilentlyContinue) {
                    $acl = Get-ACLPermissions -Path $ep -FileSystem
                    if ($acl -and $acl.HasWrite) {
                        $vulnCount++
                        Write-Log "Writable SYSTEM Task Binary: $($task.TaskName) - $ep" -Level Critical -Category Tasks -ExploitDifficulty 1 -MitreTechniques @('T1053.005')
                    }
                }
            }
        }
        if ($vulnCount -eq 0) { Write-Log "No vulnerable scheduled tasks" -Level Success -Category Tasks }
        else { Write-Log "Found $vulnCount vulnerable tasks" -Level Critical -Category Tasks }
    } catch { Write-Log "Error: $_" -Level Error -Category Tasks }
}

# ============================================================================
# KERNEL EXPLOIT DATABASE
# ============================================================================

function Test-KernelExploits {
    Write-SectionHeader "KERNEL EXPLOIT DATABASE" "CVE mapping (updated 2025)"
    try {
        $bn = [int]$script:Config.SystemInfo.Build
        $db = @{
            7601  = @(@{CVE='MS15-051';D=3;N='win32k.sys'}, @{CVE='MS16-032';D=3;N='Secondary Logon'})
            9600  = @(@{CVE='CVE-2014-4113';D=3;N='win32k.sys'}, @{CVE='MS16-032';D=3;N='Secondary Logon'})
            14393 = @(@{CVE='CVE-2017-0213';D=3;N='COM Aggregate'}, @{CVE='CVE-2018-8120';D=3;N='win32k.sys'})
            17763 = @(@{CVE='CVE-2019-0841';D=3;N='AppX'}, @{CVE='CVE-2020-0787';D=2;N='BITSAdmin'})
            18362 = @(@{CVE='CVE-2020-0668';D=3;N='Service Tracing'}, @{CVE='CVE-2020-0787';D=2;N='BITSAdmin'})
            18363 = @(@{CVE='CVE-2020-0787';D=2;N='BITSAdmin'}, @{CVE='CVE-2020-1013';D=3;N='Unified Write Filter'})
            19041 = @(@{CVE='CVE-2021-1732';D=4;N='win32k.sys'}, @{CVE='CVE-2021-36934';D=2;N='HiveNightmare'})
            19044 = @(@{CVE='CVE-2022-21882';D=3;N='Win32k'}, @{CVE='CVE-2022-37969';D=4;N='CLFS'})
            19045 = @(@{CVE='CVE-2022-37969';D=4;N='CLFS'}, @{CVE='CVE-2023-21746';D=3;N='NTLM'})
            22000 = @(@{CVE='CVE-2023-21746';D=3;N='NTLM'}, @{CVE='CVE-2023-21768';D=3;N='AFD.sys'})
            22621 = @(@{CVE='CVE-2023-21768';D=3;N='AFD.sys'}, @{CVE='CVE-2024-21338';D=3;N='AppXSvc'})
            22631 = @(@{CVE='CVE-2024-21338';D=3;N='AppX'}, @{CVE='CVE-2024-26169';D=3;N='Win32k'}, @{CVE='CVE-2024-30051';D=3;N='DWM'})
            26100 = @(@{CVE='CVE-2024-26169';D=3;N='Win32k'}, @{CVE='CVE-2024-38063';D=3;N='TCP/IP'}, @{CVE='CVE-2024-43461';D=3;N='MSHTML'})
            26200 = @(@{CVE='CVE-2024-38063';D=3;N='TCP/IP IPv6'}, @{CVE='CVE-2024-49039';D=3;N='Task Scheduler'}, @{CVE='CVE-2025-21391';D=3;N='Storage'})
        }

        $matched = $null
        foreach ($b in ($db.Keys | Sort-Object -Descending)) {
            if ($bn -ge $b) { $matched = $db[$b]; break }
        }
        if ($matched) {
            Write-Log "Build $bn potentially vulnerable:" -Level Critical -Category Kernel
            foreach ($e in $matched) {
                Write-Log "  $($e.CVE) ($($e.N))" -Level Critical -Category Kernel -ExploitDifficulty $e.D -MitreTechniques @('T1068')
            }
        } else { Write-Log "Build $bn not in exploit database" -Level Info -Category Kernel }
    } catch { Write-Log "Error: $_" -Level Error -Category Kernel }
}

# ============================================================================
# CREDENTIAL HUNTING
# ============================================================================

function Find-Credentials {
    Write-SectionHeader "CREDENTIAL HUNTING" "Files, registry, cloud keys, WiFi"
    try {
        $cc = 0

        # Unattend files
        @("C:\Unattend.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml",
          "C:\Windows\System32\sysprep\unattend.xml") | ForEach-Object {
            if (Test-Path $_) { $cc++; Write-Log "Unattend.xml: $_" -Level High -Category Credentials -MitreTechniques @('T1552.001') }
        }

        # PowerShell history
        $psh = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        if (Test-Path $psh) {
            $cc++; Write-Log "PowerShell history: $psh" -Level High -Category Credentials -MitreTechniques @('T1552.003')
            if ($Mode -eq 'Deep' -or $Mode -eq 'Paranoid') {
                $h = Get-Content $psh -Raw -ErrorAction SilentlyContinue
                if ($h -match 'password|pwd|credential|secret|key') { Write-Log "History contains credential keywords!" -Level Critical -Category Credentials -Sensitive }
            }
        }

        # WinLogon auto-logon
        $wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
        if ($wl.DefaultPassword) { $cc++; Write-Log "AutoLogon password in registry! User: $($wl.DefaultUserName)" -Level Critical -Category Credentials -Sensitive -MitreTechniques @('T1552.002') }

        # WiFi passwords
        if ($Mode -ne 'Stealth' -and -not $SkipNetworkChecks) {
            try {
                $profiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object { ($_ -replace ".*:\s+","").Trim() }
                foreach ($p in $profiles) {
                    $info = netsh wlan show profile name="$p" key=clear 2>$null
                    $pw = $info | Select-String "Key Content" | ForEach-Object { ($_ -replace ".*:\s+","").Trim() }
                    if ($pw) { $cc++; Write-Log "WiFi credential: $p" -Level High -Category Credentials -Sensitive }
                }
            } catch {}
        }

        # SSH keys
        if (Test-Path "$env:USERPROFILE\.ssh") {
            $cc++; Write-Log "SSH directory found" -Level High -Category Credentials -MitreTechniques @('T1552.004')
            Get-ChildItem "$env:USERPROFILE\.ssh" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'id_rsa|id_ed25519|id_ecdsa' } | ForEach-Object {
                Write-Log "  SSH private key: $($_.Name)" -Level Critical -Category Credentials
            }
        }

        # Cloud credentials
        if (Test-Path "$env:USERPROFILE\.aws\credentials") { $cc++; Write-Log "AWS credentials found!" -Level Critical -Category Credentials }
        if (Test-Path "$env:USERPROFILE\.azure") { $cc++; Write-Log "Azure CLI credentials found!" -Level Critical -Category Credentials }
        if (Test-Path "$env:APPDATA\gcloud") { $cc++; Write-Log "Google Cloud credentials found!" -Level Critical -Category Credentials }
        if (Test-Path "$env:USERPROFILE\.docker\config.json") { $cc++; Write-Log "Docker credentials found!" -Level High -Category Credentials }

        # SNMP
        $snmp = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
        if (Test-Path $snmp) { $cc++; Write-Log "SNMP community strings in registry" -Level High -Category Credentials }

        # VNC
        @("HKCU:\Software\ORL\WinVNC3\Password","HKCU:\Software\RealVNC\WinVNC4","HKLM:\SOFTWARE\RealVNC\WinVNC4") | ForEach-Object {
            if (Test-Path $_ -ErrorAction SilentlyContinue) { $cc++; Write-Log "VNC password key: $_" -Level High -Category Credentials }
        }

        # PuTTY sessions
        $putty = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
        if (Test-Path $putty) {
            $cc++; Write-Log "PuTTY sessions found" -Level Medium -Category Credentials
        }

        # IIS web.config
        if (Test-Path "C:\inetpub\wwwroot") {
            Get-ChildItem "C:\inetpub\wwwroot" -Recurse -Filter "web.config" -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
                $cc++; Write-Log "IIS web.config: $($_.FullName)" -Level High -Category Credentials -MitreTechniques @('T1552.001')
            }
        }

        # KeePass
        Get-ChildItem "$env:USERPROFILE" -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue -Depth 3 | Select-Object -First 5 | ForEach-Object {
            $cc++; Write-Log "KeePass DB: $($_.FullName)" -Level Critical -Category Credentials
        }

        if ($cc -eq 0) { Write-Log "No obvious credentials found" -Level Success -Category Credentials }
        else { Write-Log "Found $cc potential credential sources" -Level Critical -Category Credentials }
    } catch { Write-Log "Error: $_" -Level Error -Category Credentials }
}

# ============================================================================
# BROWSER CREDENTIALS
# ============================================================================

function Find-BrowserCredentials {
    Write-SectionHeader "BROWSER CREDENTIALS" "Browser credential stores"
    try {
        $found = 0
        $browsers = @{
            'Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
            'Edge'   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
            'Brave'  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
            'Opera'  = "$env:APPDATA\Opera Software\Opera Stable\Login Data"
        }
        foreach ($b in $browsers.Keys) {
            if (Test-Path $browsers[$b]) { $found++; Write-Log "$b login database found" -Level Medium -Category Browser -MitreTechniques @('T1555.003') }
        }
        # Firefox
        $ff = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $ff) {
            Get-ChildItem $ff -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (Test-Path (Join-Path $_.FullName "logins.json")) { $found++; Write-Log "Firefox logins: $($_.FullName)" -Level Medium -Category Browser }
            }
        }
        if ($found -gt 0) { Write-Log "Use SharpChrome / LaZagne / HackBrowserData to extract" -Level Info -Category Browser }
        else { Write-Log "No browser credential stores found" -Level Success -Category Browser }
    } catch { Write-Log "Error: $_" -Level Error -Category Browser }
}

# ============================================================================
# CACHED CREDENTIALS & DPAPI
# ============================================================================

function Test-CachedCredentials {
    Write-SectionHeader "CACHED CREDENTIALS" "Credential Manager, LSA, WDigest, DPAPI"
    try {
        # Credential Manager
        $sc = cmdkey /list 2>$null
        if ($sc -and ($sc | Where-Object { $_ -match 'Target:' })) {
            Write-Log "Saved credentials in Credential Manager" -Level High -Category Credentials -MitreTechniques @('T1555.003')
        }

        # LSA Protection
        $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
        if ($lsa -and $lsa.RunAsPPL -eq 1) { Write-Log "LSA Protection ENABLED (PPL)" -Level Success -Category Credentials }
        else { Write-Log "LSA Protection DISABLED - credential dumping easier!" -Level Critical -Category Credentials -ExploitDifficulty 2 -MitreTechniques @('T1003.001') }

        # WDigest
        $wd = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue
        if ($wd -and $wd.UseLogonCredential -eq 1) {
            Write-Log "WDigest ENABLED - cleartext passwords in LSASS!" -Level Critical -Category Credentials -ExploitDifficulty 1 -MitreTechniques @('T1003.001')
        }

        # DPAPI master keys
        $dpapi = "$env:APPDATA\Microsoft\Protect"
        if (Test-Path $dpapi) {
            $keys = Get-ChildItem $dpapi -Recurse -File -ErrorAction SilentlyContinue
            if ($keys.Count -gt 0) { Write-Log "DPAPI master keys found: $($keys.Count)" -Level High -Category Credentials -MitreTechniques @('T1555.004') }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Credentials }
}

# ============================================================================
# ADCS VULNERABILITIES
# ============================================================================

function Test-ADCSVulnerabilities {
    Write-SectionHeader "CERTIFICATE SERVICES (ADCS)" "ESC1-ESC13 checks"
    try {
        if (-not $script:Config.SystemInfo.IsDomainJoined) { Write-Log "Not domain-joined - skipping" -Level Info -Category ADCS; return }
        Write-Log "Domain-joined: use Certify.exe find /vulnerable for full ADCS enumeration" -Level Info -Category ADCS
        $escs = @('ESC1 - Enrollee supplies SAN','ESC2 - Any purpose EKU','ESC3 - Certificate request agents',
                   'ESC4 - Template ACL','ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2','ESC7 - CA ACL',
                   'ESC8 - NTLM relay to HTTP','ESC9 - No security extension','ESC10 - Weak mappings','ESC13 - OID group link')
        foreach ($e in $escs) { Write-Log "Check: $e" -Level Medium -Category ADCS -MitreTechniques @('T1649') }

        # Local certificates with private keys
        Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey } | Select-Object -First 5 | ForEach-Object {
            Write-Log "Cert with private key: $($_.Subject)" -Level Medium -Category ADCS
        }
    } catch { Write-Log "Error: $_" -Level Error -Category ADCS }
}

# ============================================================================
# NETWORK VULNERABILITIES
# ============================================================================

function Test-NetworkVulnerabilities {
    if ($SkipNetworkChecks) { return }
    Write-SectionHeader "NETWORK ATTACK SURFACE" "LLMNR, SMB signing, WPAD, IPv6"
    try {
        # LLMNR
        $llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
        if (-not $llmnr -or $llmnr.EnableMulticast -ne 0) {
            Write-Log "LLMNR ENABLED - poisoning attacks possible (Responder/Inveigh)" -Level High -Category Network -ExploitDifficulty 2 -MitreTechniques @('T1557.001')
        } else { Write-Log "LLMNR disabled" -Level Success -Category Network }

        # SMB Signing
        $smbC = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -ErrorAction SilentlyContinue
        if (-not $smbC -or $smbC.RequireSecuritySignature -eq 0) {
            Write-Log "SMB client signing NOT REQUIRED - relay attacks possible!" -Level Critical -Category Network -ExploitDifficulty 2 -MitreTechniques @('T1557.001')
        } else { Write-Log "SMB client signing required" -Level Success -Category Network }

        # IPv6
        $ipv6 = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
        if ($ipv6) { Write-Log "IPv6 enabled - DHCPv6/DNS takeover possible (mitm6)" -Level Medium -Category Network -ExploitDifficulty 3 }

        # Null session
        try {
            net use \\127.0.0.1\IPC$ "" /user:"" 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Null session ENABLED!" -Level High -Category Network
                net use \\127.0.0.1\IPC$ /delete 2>$null | Out-Null
            }
        } catch {}

        # Listening ports
        $suspicious = @(21,23,69,135,139,445,1433,3306,3389,5985,5986,8080,8443)
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in $suspicious } | Select-Object -Unique LocalPort | ForEach-Object {
            Write-Log "Listening on port $($_.LocalPort)" -Level Medium -Category Network
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Network }
}

# ============================================================================
# PERSISTENCE MECHANISMS
# ============================================================================

function Test-PersistenceMechanisms {
    Write-SectionHeader "PERSISTENCE ANALYSIS" "Registry, startup, IFEO, logon scripts"
    try {
        $vc = 0
        # Autorun keys
        $keys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($k in $keys) {
            if (Test-Path $k) {
                $acl = Get-ACLPermissions -Path $k
                if ($acl -and $acl.HasWrite) { $vc++; Write-Log "Writable autorun key: $k" -Level Critical -Category Persistence -ExploitDifficulty 1 -MitreTechniques @('T1547.001') }
            }
        }

        # Startup folders
        @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
          "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
            if (Test-Path $_) {
                $acl = Get-ACLPermissions -Path $_ -FileSystem
                if ($acl -and $acl.HasWrite) { $vc++; Write-Log "Writable startup folder: $_" -Level Critical -Category Persistence -ExploitDifficulty 1 -MitreTechniques @('T1547.001') }
            }
        }

        # IFEO
        $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        if (Test-Path $ifeo) {
            $acl = Get-ACLPermissions -Path $ifeo
            if ($acl -and $acl.HasWrite) { $vc++; Write-Log "Writable IFEO registry!" -Level Critical -Category Persistence -MitreTechniques @('T1546.012') }
            # Check existing debuggers
            Get-ChildItem $ifeo -ErrorAction SilentlyContinue | Get-ItemProperty -Name Debugger -ErrorAction SilentlyContinue | Where-Object { $_.Debugger } | Select-Object -First 5 | ForEach-Object {
                Write-Log "IFEO Debugger: $($_.PSChildName) -> $($_.Debugger)" -Level High -Category Persistence
            }
        }

        # Logon scripts
        $ls = Get-ItemProperty "HKCU:\Environment" -Name UserInitMprLogonScript -ErrorAction SilentlyContinue
        if ($ls.UserInitMprLogonScript) { Write-Log "User logon script: $($ls.UserInitMprLogonScript)" -Level High -Category Persistence -MitreTechniques @('T1037.001') }

        # AppInit_DLLs
        $ai = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
        if ($ai.AppInit_DLLs) { Write-Log "AppInit_DLLs: $($ai.AppInit_DLLs)" -Level High -Category Persistence }

        # Boot Execute
        $be = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name BootExecute -ErrorAction SilentlyContinue
        if ($be.BootExecute -and ($be.BootExecute | Where-Object { $_ -ne 'autocheck autochk *' })) {
            Write-Log "Non-default BootExecute entries!" -Level High -Category Persistence
        }

        if ($vc -eq 0) { Write-Log "No writable persistence locations" -Level Success -Category Persistence }
        else { Write-Log "Found $vc writable persistence locations!" -Level Critical -Category Persistence }
    } catch { Write-Log "Error: $_" -Level Error -Category Persistence }
}

# ============================================================================
# ADVANCED PERSISTENCE (Port Monitors, Print Processors, Auth Packages, etc.)
# ============================================================================

function Test-AdvancedPersistence {
    Write-SectionHeader "ADVANCED PERSISTENCE" "Port monitors, auth packages, SSPs, Active Setup, Netsh, AppCert, Shims, PS profiles"
    try {
        # Port Monitors (T1547.010)
        $pm = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
        if (Test-Path $pm) {
            $acl = Get-ACLPermissions -Path $pm
            if ($acl -and $acl.HasWrite) { Write-Log "Can ADD port monitors - SYSTEM execution!" -Level Critical -Category Persistence -MitreTechniques @('T1547.010') }
        }

        # Authentication Packages (T1547.002)
        $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
        if ($lsa.'Authentication Packages') {
            Write-Log "Auth Packages: $($lsa.'Authentication Packages' -join ', ')" -Level High -Category Persistence -MitreTechniques @('T1547.002')
            $acl = Get-ACLPermissions -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if ($acl -and $acl.HasWrite) { Write-Log "LSA key WRITABLE - can add malicious auth package!" -Level Critical -Category Persistence }
        }

        # Security Support Providers (T1547.005)
        if ($lsa.'Security Packages') {
            Write-Log "SSPs: $($lsa.'Security Packages' -join ', ')" -Level High -Category Persistence -MitreTechniques @('T1547.005')
        }

        # Active Setup (T1547.014)
        $as = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"
        if (Test-Path $as) {
            $acl = Get-ACLPermissions -Path $as
            if ($acl -and $acl.HasWrite) { Write-Log "Can ADD Active Setup components (runs for every user login)!" -Level Critical -Category Persistence -MitreTechniques @('T1547.014') }
        }

        # Netsh Helper DLLs (T1546.007)
        $ns = "HKLM:\SOFTWARE\Microsoft\Netsh"
        if (Test-Path $ns) {
            $acl = Get-ACLPermissions -Path $ns
            if ($acl -and $acl.HasWrite) { Write-Log "Netsh registry WRITABLE - can add helper DLL!" -Level Critical -Category Persistence -MitreTechniques @('T1546.007') }
        }

        # AppCert DLLs (T1546.009)
        $ac = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs"
        if (Test-Path $ac) {
            Write-Log "AppCertDLLs key EXISTS - DLLs loaded into every process!" -Level High -Category Persistence -MitreTechniques @('T1546.009')
        }

        # Application Shimming (T1546.011)
        $sp = "C:\Windows\AppPatch"
        if (Test-Path $sp) {
            $acl = Get-ACLPermissions -Path $sp -FileSystem
            if ($acl -and $acl.HasWrite) { Write-Log "AppPatch directory WRITABLE - shim database injection!" -Level Critical -Category Persistence -MitreTechniques @('T1546.011') }
        }

        # PowerShell Profiles (T1546.013)
        $profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)
        foreach ($pp in $profiles) {
            if ($pp -and (Test-Path $pp)) { Write-Log "PowerShell profile EXISTS: $pp" -Level High -Category Persistence -MitreTechniques @('T1546.013') }
        }

        # .NET COR_PROFILER
        if ($env:COR_PROFILER) {
            Write-Log "COR_PROFILER SET: $($env:COR_PROFILER) - .NET DLL injection!" -Level Critical -Category Persistence -MitreTechniques @('T1574.012')
        }

        # Screensaver
        $scr = Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue
        if ($scr.'SCRNSAVE.EXE' -and (Test-Path $scr.'SCRNSAVE.EXE')) {
            $acl = Get-ACLPermissions -Path $scr.'SCRNSAVE.EXE' -FileSystem
            if ($acl -and $acl.HasWrite) { Write-Log "Writable screensaver: $($scr.'SCRNSAVE.EXE')" -Level High -Category Persistence -MitreTechniques @('T1546.002') }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Persistence }
}

# ============================================================================
# WMI PERSISTENCE
# ============================================================================

function Test-WMIPersistence {
    Write-SectionHeader "WMI PERSISTENCE" "Event subscriptions"
    try {
        $f = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        $c = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        $b = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        if ($f.Count -gt 0) { Write-Log "WMI Event Filters: $($f.Count)" -Level Medium -Category WMI -MitreTechniques @('T1546.003') }
        if ($b.Count -gt 0) { Write-Log "WMI Bindings: $($b.Count) - ACTIVE PERSISTENCE!" -Level High -Category WMI -MitreTechniques @('T1546.003') }
        if ($f.Count -eq 0 -and $b.Count -eq 0) { Write-Log "No WMI persistence" -Level Success -Category WMI }
    } catch { Write-Log "Error: $_" -Level Error -Category WMI }
}

# ============================================================================
# COM HIJACKING
# ============================================================================

function Test-COMHijacking {
    Write-SectionHeader "COM HIJACKING" "CLSID and DCOM analysis"
    try {
        $uc = "HKCU:\Software\Classes\CLSID"
        if (Test-Path $uc) {
            $clsids = Get-ChildItem $uc -ErrorAction SilentlyContinue
            if ($clsids.Count -gt 0) { Write-Log "User CLSID entries: $($clsids.Count)" -Level Medium -Category COM -MitreTechniques @('T1546.015') }
        }
        $sc = "HKLM:\Software\Classes\CLSID"
        if (Test-Path $sc) {
            $acl = Get-ACLPermissions -Path $sc
            if ($acl -and $acl.HasWrite) { Write-Log "SYSTEM CLSID WRITABLE!" -Level Critical -Category COM -MitreTechniques @('T1546.015') }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category COM }
}

# ============================================================================
# DLL HIJACKING & PATH
# ============================================================================

function Find-DLLHijacking {
    Write-SectionHeader "DLL HIJACKING" "PATH, search order, SafeDllSearchMode"
    try {
        if ($env:PATH -match '(^\.|;\.;|;\.$)') {
            Write-Log "Current directory (.) in PATH - CRITICAL!" -Level Critical -Category DLLHijacking -ExploitDifficulty 1 -MitreTechniques @('T1574.001')
        }
        $vc = 0
        $env:PATH -split ';' | Where-Object { $_ } | ForEach-Object {
            if (Test-Path $_ -ErrorAction SilentlyContinue) {
                $acl = Get-ACLPermissions -Path $_ -FileSystem
                if ($acl -and $acl.HasWrite) { $vc++; Write-Log "Writable PATH dir: $_" -Level High -Category DLLHijacking -ExploitDifficulty 2 -MitreTechniques @('T1574.001') }
            }
        }
        # SafeDllSearchMode
        $sd = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -ErrorAction SilentlyContinue
        if ($sd -and $sd.SafeDllSearchMode -eq 0) { Write-Log "SafeDllSearchMode DISABLED!" -Level High -Category DLLHijacking }

        if ($vc -eq 0) { Write-Log "No writable PATH directories" -Level Success -Category DLLHijacking }
    } catch { Write-Log "Error: $_" -Level Error -Category DLLHijacking }
}

# ============================================================================
# UAC BYPASS
# ============================================================================

function Test-UACBypass {
    Write-SectionHeader "UAC BYPASS VECTORS" "UAC settings and auto-elevate binaries"
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        if ($uac.EnableLUA -eq 0) { Write-Log "UAC COMPLETELY DISABLED!" -Level Critical -Category UAC -ExploitDifficulty 1 -MitreTechniques @('T1548.002') }
        elseif ($uac.ConsentPromptBehaviorAdmin -eq 0) { Write-Log "UAC set to never notify!" -Level Critical -Category UAC -ExploitDifficulty 1 -MitreTechniques @('T1548.002') }
        else { Write-Log "UAC: ConsentPromptBehaviorAdmin = $($uac.ConsentPromptBehaviorAdmin)" -Level Info -Category UAC }

        $bypasses = @('fodhelper.exe','eventvwr.msc','ComputerDefaults.exe','sdclt.exe','WSReset.exe','slui.exe','changepk.exe')
        Write-Log "Auto-elevate bypass candidates:" -Level High -Category UAC
        foreach ($b in $bypasses) {
            if (Test-Path "C:\Windows\System32\$b" -ErrorAction SilentlyContinue) {
                Write-Log "  $b" -Level High -Category UAC -MitreTechniques @('T1548.002')
            }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category UAC }
}

# ============================================================================
# VULNERABLE DRIVERS
# ============================================================================

function Get-VulnerableDrivers {
    Write-SectionHeader "DRIVERS" "BYOVD, unsigned, third-party"
    try {
        $drivers = driverquery /v /fo csv 2>$null | ConvertFrom-Csv
        if (-not $drivers) { Write-Log "Could not enumerate drivers" -Level Warning -Category Drivers; return }

        $vulnDB = @('rtcore64.sys','gdrv.sys','capcom.sys','dbutil_2_3.sys','aswArPot.sys','iqvw64e.sys',
                     'atillk64.sys','GLCKIO2.sys','EneIo64.sys','WinRing0x64.sys','winio64.sys','msio64.sys')
        $driverNames = $drivers | Select-Object -ExpandProperty 'Module Name'
        $found = 0
        foreach ($v in $vulnDB) {
            if ($driverNames -contains $v) { $found++; Write-Log "VULNERABLE DRIVER: $v" -Level Critical -Category Drivers -ExploitDifficulty 3 -MitreTechniques @('T1068') }
        }

        $unsigned = $drivers | Where-Object { $_.Signed -eq 'False' }
        if ($unsigned.Count -gt 0) { Write-Log "Unsigned drivers: $($unsigned.Count)" -Level High -Category Drivers }

        # SeLoadDriverPrivilege
        $priv = whoami /priv 2>$null | Select-String "SeLoadDriverPrivilege"
        if ($priv -match 'Enabled') { Write-Log "SeLoadDriverPrivilege ENABLED - can load kernel drivers!" -Level Critical -Category Drivers -MitreTechniques @('T1068') }

        if ($found -eq 0 -and $unsigned.Count -eq 0) { Write-Log "No vulnerable drivers detected" -Level Success -Category Drivers }
    } catch { Write-Log "Error: $_" -Level Error -Category Drivers }
}

# ============================================================================
# SECURITY PRODUCTS
# ============================================================================

function Get-SecurityProducts {
    Write-SectionHeader "SECURITY PRODUCTS" "AV/EDR/XDR detection"
    try {
        $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($av) { foreach ($p in $av) { Write-Log "Antivirus: $($p.displayName)" -Level Info -Category Security } }

        $secProcs = @{
            'MsMpEng'='Defender'; 'MsSense'='Defender ATP'; 'CSFalconService'='CrowdStrike';
            'CylanceSvc'='Cylance'; 'SentinelAgent'='SentinelOne'; 'cb'='Carbon Black';
            'xagt'='FireEye'; 'taniumclient'='Tanium'; 'EPSecurityService'='Cortex XDR';
            'TmListen'='Trend Micro'; 'ekrn'='ESET'; 'bdagent'='Bitdefender';
            'sophossps'='Sophos'; 'SEDService'='Sophos EDR'; 'fortitray'='FortiClient'
        }
        $running = Get-Process | Select-Object -ExpandProperty Name
        foreach ($p in $secProcs.Keys) {
            if ($running -contains $p) { Write-Log "EDR/AV: $($secProcs[$p]) ($p)" -Level Info -Category Security }
        }

        # Defender details
        if ($running -contains 'MsMpEng') {
            try {
                $ds = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($ds) {
                    Write-Log "Defender RealTime: $($ds.RealTimeProtectionEnabled) | Tamper: $($ds.IsTamperProtected)" -Level Info -Category Security
                    if (-not $ds.RealTimeProtectionEnabled) { Write-Log "Defender real-time DISABLED!" -Level High -Category Security }
                }
            } catch {}
        }

        # Sysmon
        $sysmon = Get-Service Sysmon* -ErrorAction SilentlyContinue
        if ($sysmon) { Write-Log "Sysmon detected: $($sysmon.Name)" -Level Info -Category Security }

        # PowerShell logging
        $psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($psLog.EnableScriptBlockLogging -eq 1) { Write-Log "Script Block Logging ENABLED" -Level Info -Category Security }
        else { Write-Log "Script Block Logging DISABLED" -Level Medium -Category Security }
    } catch { Write-Log "Error: $_" -Level Error -Category Security }
}

# ============================================================================
# ACTIVE DIRECTORY
# ============================================================================

function Get-ActiveDirectoryInfo {
    Write-SectionHeader "ACTIVE DIRECTORY" "Domain, LAPS, Kerberos, GPO"
    try {
        if (-not $script:Config.SystemInfo.IsDomainJoined) { Write-Log "Not domain-joined" -Level Info -Category AD; return }
        Write-Log "Domain-joined: $($script:Config.SystemInfo.Domain)" -Level High -Category AD

        # LAPS
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd") { Write-Log "LAPS configured" -Level Success -Category AD }
        else { Write-Log "LAPS NOT configured" -Level High -Category AD -MitreTechniques @('T1078.003') }

        # Cached logons
        $cl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue
        if ($cl) { Write-Log "Cached domain logons: $($cl.CachedLogonsCount)" -Level Medium -Category AD -MitreTechniques @('T1003.005') }

        # Kerberos
        $kt = klist tickets 2>$null
        if ($kt) { Write-Log "Kerberos tickets present" -Level Info -Category AD }

        Write-Log "Use BloodHound/SharpHound/PowerView for full AD enumeration" -Level Info -Category AD
    } catch { Write-Log "Error: $_" -Level Error -Category AD }
}

# ============================================================================
# MISCELLANEOUS CHECKS
# ============================================================================

function Test-PrintSpooler {
    Write-SectionHeader "PRINT SPOOLER" "PrintNightmare and related"
    try {
        $spl = Get-Service Spooler -ErrorAction SilentlyContinue
        if ($spl -and $spl.Status -eq 'Running') {
            Write-Log "Print Spooler RUNNING" -Level High -Category PrintSpooler -ExploitDifficulty 2 -MitreTechniques @('T1068')
            $pp = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ErrorAction SilentlyContinue
            if ($pp.RestrictDriverInstallationToAdministrators -eq 0) {
                Write-Log "Non-admins can install print drivers! PrintNightmare viable" -Level Critical -Category PrintSpooler -ExploitDifficulty 1
            } elseif ($pp.NoWarningNoElevationOnInstall -eq 1) {
                Write-Log "NoWarningNoElevationOnInstall = 1 - VERY VULNERABLE" -Level Critical -Category PrintSpooler
            }
        } else { Write-Log "Print Spooler not running" -Level Success -Category PrintSpooler }
    } catch { Write-Log "Error: $_" -Level Error -Category PrintSpooler }
}

function Get-NamedPipes {
    Write-SectionHeader "NAMED PIPES" "IPC and pipe impersonation"
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        Write-Log "Named pipes: $($pipes.Count)" -Level Info -Category Pipes
        $interesting = @('lsass','sam','winreg','spoolss','srvsvc','ntsvcs','epmapper','wkssvc')
        foreach ($pipe in $pipes) {
            $pn = [System.IO.Path]::GetFileName($pipe)
            foreach ($i in $interesting) { if ($pn -like "*$i*") { Write-Log "Interesting pipe: $pn" -Level Medium -Category Pipes; break } }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Pipes }
}

function Test-AccessibilityFeatures {
    Write-SectionHeader "ACCESSIBILITY FEATURES" "Sticky Keys hijacking"
    try {
        $features = @{
            'C:\Windows\System32\sethc.exe'    = 'Sticky Keys'
            'C:\Windows\System32\utilman.exe'   = 'Utility Manager'
            'C:\Windows\System32\osk.exe'       = 'On-Screen Keyboard'
            'C:\Windows\System32\Magnify.exe'   = 'Magnifier'
            'C:\Windows\System32\Narrator.exe'  = 'Narrator'
        }
        $vc = 0
        foreach ($f in $features.Keys) {
            if (Test-Path $f) {
                $acl = Get-ACLPermissions -Path $f -FileSystem
                if ($acl -and $acl.HasWrite) { $vc++; Write-Log "WRITABLE: $($features[$f]) - $f" -Level Critical -Category Accessibility -MitreTechniques @('T1546.008') }
            }
        }
        if ($vc -eq 0) { Write-Log "Accessibility features not writable" -Level Success -Category Accessibility }
    } catch { Write-Log "Error: $_" -Level Error -Category Accessibility }
}

function Get-ShadowCopies {
    Write-SectionHeader "VOLUME SHADOW COPIES" "Old creds and deleted files"
    try {
        $sc = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
        if ($sc -and $sc.Count -gt 0) {
            Write-Log "Shadow copies: $($sc.Count) - may contain old passwords/SAM" -Level High -Category ShadowCopy -MitreTechniques @('T1003.002')
            $bn = [int]$script:Config.SystemInfo.Build
            if ($bn -ge 19041 -and $bn -le 19043) { Write-Log "May be vulnerable to HiveNightmare (CVE-2021-36934)!" -Level Critical -Category ShadowCopy }
        } else { Write-Log "No shadow copies" -Level Info -Category ShadowCopy }
    } catch { Write-Log "Error: $_" -Level Error -Category ShadowCopy }
}

function Test-AppLocker {
    Write-SectionHeader "APPLOCKER/WDAC" "Application control policies"
    try {
        $alp = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($alp) {
            Write-Log "AppLocker IS configured" -Level Info -Category AppLocker
            $bypass = @('C:\Windows\Tasks','C:\Windows\Temp','C:\Windows\tracing','C:\Windows\System32\spool\drivers\color',
                        'C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys','C:\ProgramData')
            foreach ($p in $bypass) {
                if (Test-Path $p) {
                    $acl = Get-ACLPermissions -Path $p -FileSystem
                    if ($acl -and $acl.HasWrite) { Write-Log "Writable AppLocker bypass: $p" -Level Critical -Category AppLocker -MitreTechniques @('T1562.001') }
                }
            }
        } else { Write-Log "AppLocker NOT configured" -Level Info -Category AppLocker }
    } catch { Write-Log "Error: $_" -Level Error -Category AppLocker }
}

function Test-EnvironmentVariables {
    Write-SectionHeader "ENVIRONMENT VARIABLES" "Sensitive data and injection vectors"
    try {
        Get-ChildItem Env: | ForEach-Object {
            if ($_.Name -match 'PASSWORD|PWD|SECRET|KEY|TOKEN|API|CREDENTIAL|AUTH') {
                Write-Log "Suspicious env var: $($_.Name)" -Level High -Category Environment -Sensitive
            }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Environment }
}

function Get-NetworkConfiguration {
    Write-SectionHeader "NETWORK CONFIGURATION" "Interfaces, firewall, RDP, WinRM"
    try {
        Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object {
            Write-Log "$($_.InterfaceAlias): $($_.IPAddress)" -Level Info -Category Network
        }
        Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not $_.Enabled) { Write-Log "Firewall DISABLED: $($_.Name)" -Level Critical -Category Network -MitreTechniques @('T1562.004') }
            else { Write-Log "Firewall $($_.Name): Enabled" -Level Success -Category Network }
        }
        $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($rdp -and $rdp.fDenyTSConnections -eq 0) { Write-Log "Remote Desktop ENABLED" -Level Medium -Category Network -MitreTechniques @('T1021.001') }
        $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        if ($winrm -and $winrm.Status -eq 'Running') { Write-Log "WinRM service running" -Level Medium -Category Network -MitreTechniques @('T1021.006') }
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        if ($shares) { Write-Log "SMB shares: $($shares.Count)" -Level Info -Category Network }
    } catch { Write-Log "Error: $_" -Level Error -Category Network }
}

function Get-ProcessInfo {
    Write-SectionHeader "PROCESS ENUMERATION" "SYSTEM processes, injection vectors"
    try {
        $procs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
        $sysProcs = $procs | Where-Object { $_.GetOwner().User -eq 'SYSTEM' } | Select-Object -First 25
        Write-Log "SYSTEM processes: $($sysProcs.Count)" -Level Info -Category Processes
    } catch { Write-Log "Error: $_" -Level Error -Category Processes }
}

function Test-BitLocker {
    Write-SectionHeader "BITLOCKER" "Disk encryption status"
    try {
        $vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($vols) {
            foreach ($v in $vols) {
                if ($v.ProtectionStatus -eq 'Off') { Write-Log "Volume $($v.MountPoint) - BitLocker NOT enabled" -Level Medium -Category BitLocker }
                else { Write-Log "Volume $($v.MountPoint) - BitLocker enabled ($($v.EncryptionPercentage)%)" -Level Success -Category BitLocker }
            }
        } else { Write-Log "BitLocker not configured" -Level Info -Category BitLocker }
    } catch { Write-Log "Error: $_" -Level Error -Category BitLocker }
}

function Get-LOLBASBinaries {
    Write-SectionHeader "LOLBAS BINARIES" "Living Off The Land"
    try {
        $lolbas = @{
            'C:\Windows\System32\certutil.exe'     = 'Download/encode'
            'C:\Windows\System32\bitsadmin.exe'    = 'Download/persist'
            'C:\Windows\System32\regsvr32.exe'     = 'Execute DLLs'
            'C:\Windows\System32\mshta.exe'        = 'Execute HTA'
            'C:\Windows\System32\rundll32.exe'     = 'Execute DLLs'
            'C:\Windows\System32\wmic.exe'         = 'Execute/XSL'
            'C:\Windows\System32\cscript.exe'      = 'Execute scripts'
            'C:\Windows\System32\forfiles.exe'     = 'Execute commands'
            'C:\Windows\System32\mavinject.exe'    = 'DLL injection'
            'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe' = 'Execute C#'
            'C:\Windows\System32\installutil.exe'  = 'Execute .NET'
        }
        $count = 0
        foreach ($b in $lolbas.Keys) { if (Test-Path $b) { $count++ } }
        Write-Log "LOLBAS binaries available: $count" -Level Info -Category LOLBAS -MitreTechniques @('T1218')
        if ($Mode -eq 'Deep' -or $Mode -eq 'Paranoid') {
            foreach ($b in $lolbas.Keys) { if (Test-Path $b) { Write-Log "  $(Split-Path $b -Leaf) - $($lolbas[$b])" -Level Info -Category LOLBAS } }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category LOLBAS }
}

function Get-ClipboardAndRecent {
    Write-SectionHeader "CLIPBOARD & RECENT" "Clipboard, recent docs, Sticky Notes"
    try {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $cb = [System.Windows.Forms.Clipboard]::GetText()
            if ($cb -and $cb.Length -gt 0) {
                $preview = $cb.Substring(0, [Math]::Min(200, $cb.Length))
                Write-Log "Clipboard (200 chars): $preview" -Level Medium -Category Clipboard -Sensitive
            }
        } catch {}

        # Sticky Notes
        $sn = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
        if (Test-Path $sn) { Write-Log "Sticky Notes database found" -Level Medium -Category Recent }

        # Recent docs
        $rd = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $rd) {
            $items = Get-ChildItem $rd -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq ".lnk" }
            Write-Log "Recent documents: $($items.Count)" -Level Info -Category Recent
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Recent }
}

function Test-BITSJobs {
    Write-SectionHeader "BITS JOBS" "Background Intelligent Transfer"
    try {
        $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        if ($jobs) { Write-Log "BITS jobs: $($jobs.Count)" -Level Medium -Category BITS }
        else { Write-Log "No BITS jobs" -Level Info -Category BITS }
    } catch { Write-Log "Error: $_" -Level Error -Category BITS }
}

function Get-InstalledApplications {
    Write-SectionHeader "INSTALLED APPLICATIONS" "Software inventory"
    try {
        $apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } | Sort-Object DisplayName
        Write-Log "Installed applications: $($apps.Count)" -Level Info -Category Applications
        if ($Mode -eq 'Deep' -or $Mode -eq 'Paranoid') {
            foreach ($a in ($apps | Select-Object -First 30)) { Write-Log "  $($a.DisplayName) - $($a.DisplayVersion)" -Level Info -Category Applications }
        }
    } catch { Write-Log "Error: $_" -Level Error -Category Applications }
}

# ============================================================================
# FINAL REPORT
# ============================================================================

function Write-FinalReport {
    Write-SectionHeader "ASSESSMENT COMPLETE" "Summary and risk score"

    $duration = (Get-Date) - $script:Config.StartTime
    $riskScore = ($script:Config.Statistics.Critical * 10) + ($script:Config.Statistics.High * 5) + ($script:Config.Statistics.Medium * 2) + ($script:Config.Statistics.Low * 1)
    $riskLevel = if ($riskScore -gt 100) { "CRITICAL" } elseif ($riskScore -gt 50) { "HIGH" } elseif ($riskScore -gt 20) { "MEDIUM" } else { "LOW" }

    Write-Log "Mode: $Mode | Duration: $($duration.ToString('mm\:ss'))" -Level Info -Category Summary
    Write-Log "Total Findings: $($script:Config.Findings.Count)" -Level Info -Category Summary
    Write-Host "`nSEVERITY BREAKDOWN:" -ForegroundColor Cyan
    Write-Log "  Critical: $($script:Config.Statistics.Critical)" -Level Critical -Category Summary
    Write-Log "  High:     $($script:Config.Statistics.High)" -Level High -Category Summary
    Write-Log "  Medium:   $($script:Config.Statistics.Medium)" -Level Medium -Category Summary
    Write-Log "  Info:     $($script:Config.Statistics.Info)" -Level Info -Category Summary
    Write-Host "`nRISK SCORE: $riskScore ($riskLevel)" -ForegroundColor $(if ($riskLevel -eq 'CRITICAL') { 'Red' } elseif ($riskLevel -eq 'HIGH') { 'Yellow' } else { 'Cyan' })

    # Top critical findings
    if ($script:Config.Statistics.Critical -gt 0) {
        Write-Host "`nTOP CRITICAL FINDINGS:" -ForegroundColor Red
        $script:Config.Findings | Where-Object { $_.Level -eq 'Critical' } | Select-Object -First 10 | ForEach-Object {
            Write-Host "  [!!!] $($_.Message)" -ForegroundColor Red
        }
    }

    # MITRE summary
    $mitre = $script:Config.Findings | Where-Object { $_.MitreTechniques.Count -gt 0 } | Select-Object -ExpandProperty MitreTechniques | Sort-Object -Unique
    if ($mitre.Count -gt 0) { Write-Log "MITRE ATT&CK techniques identified: $($mitre.Count)" -Level Info -Category Summary }

    # JSON export
    if ($JSON) {
        try {
            [PSCustomObject]@{
                Assessment = @{ Version = $script:Config.Version; Start = $script:Config.StartTime.ToString("yyyy-MM-dd HH:mm:ss"); Duration = $duration.TotalSeconds; Mode = $Mode }
                SystemInfo = $script:Config.SystemInfo
                Statistics = $script:Config.Statistics
                RiskScore  = $riskScore
                RiskLevel  = $riskLevel
                MitreTechniques = $mitre
                Findings   = $script:Config.Findings
            } | ConvertTo-Json -Depth 10 | Out-File $JSONPath -Encoding UTF8
            Write-Log "JSON report: $JSONPath" -Level Success -Category Export
        } catch { Write-Log "JSON export failed: $_" -Level Error -Category Export }
    }
    if ($SaveReport) { Write-Log "Text report: $OutputPath" -Level Success -Category Export }

    Write-Host "`n$("=" * 80)" -ForegroundColor Green
    Write-Host "  For authorized security assessments only!" -ForegroundColor Red
    Write-Host "$("=" * 80)`n" -ForegroundColor Green
}

# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

function Start-Assessment {
    Clear-Host
    if (-not $NoColor) {
        Write-Host @"

 ╦ ╦┬┌┐┌╔═╗┬─┐┬┬  ╦╔═╗╔═╗╔═╗  ┬  ┬┌─┐
 ║║║││││╠═╝├┬┘│└┐┌┘║╣ ╚═╗║    └┐┌┘ ╔═╝
 ╚╩╝┴┘└┘╩  ┴└─┴ └┘ ╚═╝╚═╝╚═╝   └┘  ╚═╝
        Ultimate Edition v5.0 - 200+ Checks

"@ -ForegroundColor Cyan
    }
    Write-Host "  Mode: $Mode | Output: $(if($SaveReport){'Text+'})$(if($JSON){'JSON'}else{'Console'})" -ForegroundColor Gray
    Write-Host "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

    if ($SaveReport) {
        "WinPrivEsc v5.0 Report`nGenerated: $(Get-Date)`nHost: $env:COMPUTERNAME`nUser: $env:USERNAME`nMode: $Mode`n" | Out-File $OutputPath -Encoding UTF8
    }

    # Execute all checks
    Get-SystemInformation
    Get-KernelMitigations
    Get-AdvancedTokenAnalysis
    Test-ContainerEscapes
    Test-CloudMetadata
    Test-AlwaysInstallElevated
    Get-VulnerableServices
    Get-VulnerableScheduledTasks
    Test-KernelExploits
    Find-Credentials
    Find-BrowserCredentials
    Get-ClipboardAndRecent
    Test-CachedCredentials
    Test-ADCSVulnerabilities
    Test-NetworkVulnerabilities
    Test-PersistenceMechanisms
    Test-AdvancedPersistence
    Test-WMIPersistence
    Test-COMHijacking
    Find-DLLHijacking
    Test-UACBypass
    Get-VulnerableDrivers
    Get-SecurityProducts
    Test-PrintSpooler
    Get-ActiveDirectoryInfo
    Get-NamedPipes
    Test-AccessibilityFeatures
    Get-ShadowCopies
    Test-AppLocker
    Test-EnvironmentVariables
    Get-NetworkConfiguration
    Get-ProcessInfo
    Test-BitLocker
    Get-LOLBASBinaries
    Test-BITSJobs
    Get-InstalledApplications
    Write-FinalReport
}

# ============================================================================
# ENTRY POINT
# ============================================================================

try { Start-Assessment }
catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
finally { $ProgressPreference = 'Continue' }
