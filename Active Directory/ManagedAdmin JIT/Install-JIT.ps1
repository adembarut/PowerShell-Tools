<#
.SYNOPSIS
   JIT Admin Solution
   
.DESCRIPTION
   - Integrated logic (Check/Grant/Watchdog) with Race Condition protections.
   - Event Log Authority (SID Based) for Turkish/Multi-language OS support.
   - Extremely Detailed Logging for troubleshooting.

.NOTES
   Run this script to reset the JIT environment to a known good state.
#>

$InstallLog = "C:\JIT_KURULUM_LOGU.txt"
"[" + (Get-Date).ToString() + "] Kurulum V22 (Golden) Başladı..." | Out-File $InstallLog -Force

# --- YOL TANIMLARI ---
$BinDir = "C:\Program Files\CorpIT\JIT"
$DataDir = "C:\ProgramData\CorpIT\JIT"
$StateFile = "$DataDir\State.json"

try {
    # 1. TEMİZLİK
    Write-Host "Temizlik yapılıyor..."
    if (Test-Path "C:\IT\JIT") { Remove-Item "C:\IT\JIT" -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "HKLM\SOFTWARE\CorpIT") { Remove-Item "HKLM\SOFTWARE\CorpIT" -Recurse -Force -ErrorAction SilentlyContinue }

    # Görevleri Temizle
    foreach ($T in @("JIT-Check-Eligibility", "JIT-Elevate-Task", "JIT-Watchdog-Task", "JIT-Tray-App", "JIT-Security-Monitor", "JIT-Hourly-Cleanup")) {
        Unregister-ScheduledTask -TaskName $T -Confirm:$false -ErrorAction SilentlyContinue
    }

    # 2. KLASÖR OLUŞTURMA
    if (-not (Test-Path $BinDir)) { New-Item -Path $BinDir -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $DataDir)) { New-Item -Path $DataDir -ItemType Directory -Force | Out-Null }

    # 3. DEFAULT STATE (Reset)
    # Resetting state ensures we don't carry over broken "Unauthorized" states
    $DefaultState = @{
        IsAuthorized   = $false
        IsAdminActive  = $false
        AuthorizedUser = $null
        LastUpdate     = (Get-Date).ToString()
        AuthSource     = "InstallInitialization"
    }
    $DefaultState | ConvertTo-Json | Set-Content $StateFile -Force

    # 4. İZİNLER
    $Acl = Get-Acl $DataDir
    $RuleUser = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.AddAccessRule($RuleUser)
    Set-Acl -Path $DataDir -AclObject $Acl
    
    # 5. AUDIT POLICY
    Start-Process "auditpol.exe" -ArgumentList "/set /subcategory:`"Security Group Management`" /success:enable" -WindowStyle Hidden -Wait
    "[" + (Get-Date).ToString() + "] Audit Policy Configured." | Out-File $InstallLog -Append

}
catch {
    "[" + (Get-Date).ToString() + "] HATA (Hazırlık): $_" | Out-File $InstallLog -Append
}

# -------------------------------------------------------------------------
# A. JIT-CORE.ps1 (GOLDEN LOGIC)
# -------------------------------------------------------------------------
$CoreScriptContent = @'
param (
    [string]$Action,
    [string]$TargetUser
)

$StateFile = "C:\ProgramData\CorpIT\JIT\State.json"
$LogFile   = "C:\ProgramData\CorpIT\JIT\Service.log"

# --- CONFIGURATION (EDIT HERE) ---
$Duration  = 5  # [Mins] Testing: 5, Production: 30
# Add GPP Groups or other Admins here. Wildcards supported (e.g. *GPP*).
$Whitelist = @("Administrator", "Domain Admins", "Tier 2 Help-desk Operators") 
# ---------------------------------

function Write-Log {
    param($Message)
    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Date] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "------------------------------------------------"
Write-Log "SERVICE START: Action=$Action | User=$TargetUser"

function Save-State {
    param($StateObj)
    $StateObj | ConvertTo-Json | Set-Content $StateFile -Force
}

function Get-State {
    if (Test-Path $StateFile) { return Get-Content $StateFile -Raw | ConvertFrom-Json }
    return $null
}

function Get-ActiveUser {
    # Robust Loop
    for ($i = 0; $i -lt 5; $i++) {
        $Explorer = Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($Explorer.UserName) { return $Explorer.UserName.Split('\')[-1] }
        
        $Cim = Get-CimInstance Win32_ComputerSystem
        if ($Cim.UserName) { return $Cim.UserName.Split('\')[-1] }
        
        Start-Sleep -Seconds 1
    }
    return $null
}

function Get-AdminGroupName {
    try {
        $SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $Obj = $SID.Translate([System.Security.Principal.NTAccount])
        return $Obj.Value.Split('\')[-1]
    } catch { return "Administrators" }
}

# --- WATCHDOG (Expired Admin Cleanup) ---
if ($Action -eq "Watchdog") {
    $AdminGroup = Get-AdminGroupName
    Write-Log "WATCHDOG: Checking group '$AdminGroup'..."
    
    try {
        $Members = Get-LocalGroupMember -Group $AdminGroup
        
        foreach ($Member in $Members) {
            # Whitelist Check (Wildcard)
            $IsWhitelisted = $false
            foreach ($W in $Whitelist) { if ($Member.Name -like "*$W*") { $IsWhitelisted = $true; break } }
            if ($IsWhitelisted) { 
                Write-Log "WATCHDOG: Skipping Whitelisted Member: $($Member.Name)"
                continue 
            }
            
            # Search Event Log (SID Based)
            Write-Log "WATCHDOG: Scanning Event Log for SID: $($Member.SID.Value) ($($Member.Name))"
            $Events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
            
            $FoundEvent = $null
            if ($Events) {
                foreach ($Ev in $Events) {
                    try {
                        # XML Parsing (The most robust way)
                        $Xml = [xml]$Ev.ToXml()
                        
                        $EventMemberSid = $null
                        # Try standard path
                        $DataNode = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq "MemberSid" }
                        if ($DataNode.'#text') { $EventMemberSid = $DataNode.'#text' }
                        elseif ($DataNode.InnerText) { $EventMemberSid = $DataNode.InnerText }

                        if ($EventMemberSid -eq $Member.SID.Value) {
                            $FoundEvent = $Ev
                            Write-Log "WATCHDOG: Found Match! Event ID: $($Ev.Id) Time: $($Ev.TimeCreated)"
                            break
                        }
                    } catch {}
                }
            }
            
            if ($FoundEvent) {
                $TimeAdded = $FoundEvent.TimeCreated
                $TimeExpired = $TimeAdded.AddMinutes($Duration)
                $Now = Get-Date 
                
                if ($Now -gt $TimeExpired) {
                    Write-Log "ENFORCEMENT: TIME EXPIRED. Now: $Now > Limit: $TimeExpired. Removing $($Member.Name)."
                    
                    try { Remove-LocalGroupMember -Group $AdminGroup -Member $Member.Name -ErrorAction Stop }
                    catch { Remove-LocalGroupMember -Group $AdminGroup -Member $Member.SID.Value -ErrorAction SilentlyContinue }
                    
                    # Update State
                    $State = Get-State
                    if ($State) {
                        $State.IsAdminActive = $false; $State.ExpirationTime = $null
                        Save-State -StateObj $State
                    }
                } else {
                    $Remaining = ($TimeExpired - $Now).TotalMinutes -as [int]
                    Write-Log "CHECK: OK. Remaining: $Remaining mins."
                }
            } else {
                Write-Log "WARNING: No Event Log found for $($Member.Name). Checking File Fallback..."
                # Fallback to JSON
                 $State = Get-State
                 if ($State -and $State.IsAdminActive -and $State.ExpirationTime) {
                   if ((Get-Date) -gt (Get-Date $State.ExpirationTime)) {
                       Write-Log "ENFORCEMENT (Fallback): JSON Expired. REMOVING."
                       try { Remove-LocalGroupMember -Group $AdminGroup -Member $Member.Name -ErrorAction Stop } catch {}
                       $State.IsAdminActive = $false; $State.ExpirationTime = $null; Save-State -StateObj $State
                   }
                }
            }
        }
    } catch {
        Write-Log "HATA (Watchdog Loop): $_"
    }
}

# --- YETKİ VERME (GrantAccess) ---
if ($Action -eq "GrantAccess") {
    try {
        $CurrentState = Get-State
        if ($CurrentState.IsAuthorized -eq $true) {
            $TargetUser = $CurrentState.AuthorizedUser
            $AdminGroup = Get-AdminGroupName
            
            # [FIX] Save State FIRST (Race Condition Protection)
            $NewState = @{
                IsAuthorized   = $true
                IsAdminActive  = $true
                AuthorizedUser = $TargetUser
                GrantTime      = (Get-Date).ToString()
                ExpirationTime = (Get-Date).AddMinutes($Duration).ToString()
                LastUpdate     = (Get-Date).ToString()
            }
            Save-State -StateObj $NewState
            
            # Add to Group
            try { 
                # Pre-check
                if (Get-LocalGroupMember -Group $AdminGroup -Member $TargetUser -ErrorAction SilentlyContinue) {
                    Write-Log "GRANTED: User already in group."
                } else {
                    try { Add-LocalGroupMember -Group $AdminGroup -Member "$env:USERDOMAIN\$TargetUser" -ErrorAction Stop }
                    catch { Add-LocalGroupMember -Group $AdminGroup -Member $TargetUser -ErrorAction Stop }
                    Write-Log "GRANTED: User added successfully."
                }
            } catch {
                $Err = $_.Exception.Message
                if ($Err -match "already a member") {
                    Write-Log "GRANTED: User was already member (Exception catch)."
                } else {
                    Write-Log "ERROR: Add Failed: $Err. Rolling back."
                    $CurrentState.IsAdminActive = $false
                    Save-State -StateObj $CurrentState
                    throw $_
                }
            }
        } else {
            Write-Log "GRANT DENIED: IsAuthorized is False in State.json."
        }
    } catch {
        Write-Log "HATA (Grant): $_"
    }
}

# --- UYGUNLUK KONTROLÜ (CheckEligibility) ---
if ($Action -eq "CheckEligibility") {
    $CurrentActive = Get-ActiveUser
    if ([string]::IsNullOrWhiteSpace($TargetUser) -or $TargetUser -like "*%LogonUser%*") { $TargetUser = $CurrentActive }
    
    if ([string]::IsNullOrWhiteSpace($TargetUser)) { 
        Write-Log "ABORT: No Active User Found."
        exit 
    }

    Write-Log "CHECK: Verifying eligibility for '$TargetUser'..."

    try {
        $ComputerName = $env:COMPUTERNAME
        $Searcher = [adsisearcher]"(sAMAccountName=$ComputerName$)"
        $CompResult = $Searcher.FindOne()
        $IsOwner = $false
        
        $RawManagedBy = "?"
        $AuthorizedUser = "?"

        if ($CompResult -and $CompResult.Properties["managedby"]) {
            $RawManagedBy = $CompResult.Properties["managedby"][0].ToString()
            try {
                $ManagerObj = [adsi]"LDAP://$RawManagedBy"
                $AuthorizedUser = $ManagerObj.sAMAccountName
            } catch {
                $AuthorizedUser = $RawManagedBy.Split(',')[0].Replace("CN=", "").Trim()
            }
        }
        
        Write-Log "AD DATA: ManagedBy(DN)='$RawManagedBy' -> ParsedUser='$AuthorizedUser'"

        if ($AuthorizedUser -eq $TargetUser) { 
            $IsOwner = $true 
            Write-Log "RESULT: MATCH! ($TargetUser is eligible)."
        } else {
            Write-Log "RESULT: NO MATCH. ($TargetUser != $AuthorizedUser)."
        }
        
        $CurrentState = Get-State
        if ($CurrentState -eq $null) { $CurrentState = @{ IsAdminActive = $false; ExpirationTime = $null } }
        
        $NewState = @{
            IsAuthorized   = $IsOwner
            IsAdminActive  = $CurrentState.IsAdminActive
            AuthorizedUser = $TargetUser
            ExpirationTime = $CurrentState.ExpirationTime
            LastUpdate     = (Get-Date).ToString()
            DebugInfo      = "Found=$AuthorizedUser | Target=$TargetUser"
        }
        Save-State -StateObj $NewState

    } catch {
        Write-Log "HATA (Check): $_"
    }
}

# --- SECURITY WATCHDOG (Event 4732) ---
if ($Action -eq "SecurityWatchdog") {
    Write-Log "SECURITY: Event 4732 Detected. Scanning for unauthorized admins..."
    
    $State = Get-State
    $AllowedUser = $null
    if ($State -and $State.IsAdminActive) { 
        $AllowedUser = $State.AuthorizedUser 
        Write-Log "SECURITY: JIT Session Active for '$AllowedUser'. All others will be removed (unless Whitelisted)."
    } else {
        Write-Log "SECURITY: No JIT Session Active. All admins will be removed (unless Whitelisted)."
    }
    
    $AdminGroup = Get-AdminGroupName
    $Members = Get-LocalGroupMember -Group $AdminGroup
    foreach ($Member in $Members) {
        # 1. Whitelist Check (Wildcard)
        $IsWhitelisted = $false
        foreach ($W in $Whitelist) { if ($Member.Name -like "*$W*") { $IsWhitelisted = $true; break } }
        if ($IsWhitelisted) { 
            # Write-Log "SECURITY: Skipping Whitelisted: $($Member.Name)" 
            continue 
        }
        
        # 2. Check JIT Authorized User (STRICT MATCH)
        # Fix: Previous -match was too loose (e.g. 'Adem' matched 'Adem2')
        # We must handle 'DOMAIN\User' or 'COMPUTER\User' vs 'User'
        $MemberNameOnly = $Member.Name.Split('\')[-1]
        
        if ($AllowedUser -and ($MemberNameOnly -eq $AllowedUser)) { 
            # Write-Log "SECURITY: Skipping Authorized JIT User: $($Member.Name)"
            continue 
        }
        
        # 3. intruder Detected
        Write-Log "CRITICAL: Unauthorized Admin '$($Member.Name)' detected! (Not Whitelisted, Not Approved JIT). REMOVING IMMEDIATELY."
        try { Remove-LocalGroupMember -Group $AdminGroup -Member $Member.Name -ErrorAction Stop }
        catch { Remove-LocalGroupMember -Group $AdminGroup -Member $Member.SID.Value -ErrorAction SilentlyContinue }
    }
}
'@
$CoreScriptContent | Set-Content "$BinDir\JIT-Core.ps1" -Encoding UTF8


# -------------------------------------------------------------------------
# B. JIT-TRAY.ps1 (UI - LEFT CLICK FIX INCLUDED)
# -------------------------------------------------------------------------
$TrayScriptContent = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$StateFile = "C:\ProgramData\CorpIT\JIT\State.json"
$TrayLog = "$env:TEMP\JIT_Tray_Debug.log"

function Write-TrayLog { param($Msg) "[$((Get-Date).ToString('HH:mm:ss'))] $Msg" | Out-File $TrayLog -Append }

try {
    $NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $NotifyIcon.Text = "JIT Yönetici Erişimi (Başlatılıyor...)"
    $NotifyIcon.Visible = $true

    try {
        $IconPath = "C:\Windows\System32\UserAccountControlSettings.exe"
        $NotifyIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($IconPath)
    } catch {
        $NotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
    }

    $ContextMenu = New-Object System.Windows.Forms.ContextMenu
    $MenuItemStatus = New-Object System.Windows.Forms.MenuItem("Durum Kontrolü...")
    $MenuItemRequest = New-Object System.Windows.Forms.MenuItem("Yönetici Yetkisi İste")
    $MenuItemRequest.Enabled = $false
    
    $ContextMenu.MenuItems.Add($MenuItemStatus)
    $ContextMenu.MenuItems.Add("-")
    $ContextMenu.MenuItems.Add($MenuItemRequest)

    $NotifyIcon.ContextMenu = $ContextMenu

    function Update-Status {
        try {
            if (Test-Path $StateFile) {
                $State = Get-Content $StateFile -Raw | ConvertFrom-Json
                
                if ($State.IsAdminActive -eq $true) {
                    $NotifyIcon.Text = "JIT Admin: AKTİF"
                    $MenuItemStatus.Text = "Durum: Yöneticisiniz"
                    $MenuItemRequest.Enabled = $false
                }
                elseif ($State.IsAuthorized -eq $true) {
                    $NotifyIcon.Text = "JIT Admin: Uygun"
                    $MenuItemStatus.Text = "Durum: Yetki İstenebilir"
                    $MenuItemRequest.Enabled = $true
                }
                else {
                    $NotifyIcon.Text = "JIT Admin: Yetkisiz"
                    $MenuItemStatus.Text = "Durum: Yetkisiz ($($State.DebugInfo))"
                    $MenuItemRequest.Enabled = $false
                }
            }
        } catch {
            $NotifyIcon.Text = "JIT Admin: Veri Okunamadı"
        }
    }

    $NotifyIcon.Add_MouseClick({
        param($sender, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            $Method = $NotifyIcon.GetType().GetMethod("ShowContextMenu", [System.Reflection.BindingFlags]"NonPublic, Instance")
            $Method.Invoke($NotifyIcon, $null)
        }
    })

    $MenuItemRequest.Add_Click({
        $NotifyIcon.ShowBalloonTip(3000, "İşleniyor", "Yetki tanımlanıyor...", [System.Windows.Forms.ToolTipIcon]::Info)
        
        try {
            Start-Process "schtasks.exe" -ArgumentList "/run /tn JIT-Elevate-Task" -WindowStyle Hidden -Wait
            Start-Sleep -Seconds 3
            Update-Status
            
            $State = Get-Content $StateFile -Raw | ConvertFrom-Json
            if ($State.IsAdminActive -eq $true) {
                $NotifyIcon.ShowBalloonTip(5000, "Başarılı", "Yönetici yetkisi tanımlandı!", [System.Windows.Forms.ToolTipIcon]::Info)
            }
        } catch {
            Write-TrayLog "Task Hatası: $_"
        }
    })

    $Timer = New-Object System.Windows.Forms.Timer
    $Timer.Interval = 5000
    $Timer.Add_Tick({ Update-Status })
    $Timer.Start()

    Update-Status
    $ApplicationContext = New-Object System.Windows.Forms.ApplicationContext
    [System.Windows.Forms.Application]::Run($ApplicationContext)

} catch {
    Write-TrayLog "CRASH: $_"
}
'@
$TrayScriptContent | Set-Content "$BinDir\JIT-Tray.ps1" -Encoding UTF8


# -------------------------------------------------------------------------
# C. LAUNCHER.VBS
# -------------------------------------------------------------------------
$VbsContent = @"
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$BinDir\JIT-Tray.ps1""", 0, False
"@
$VbsContent | Set-Content "$BinDir\Launcher.vbs" -Encoding ASCII


# -------------------------------------------------------------------------
# D. REGISTER TASKS
# -------------------------------------------------------------------------

$LogonAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$BinDir\JIT-Core.ps1`" -Action CheckEligibility"
$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn
try { Register-ScheduledTask -Action $LogonAction -Trigger $LogonTrigger -TaskName "JIT-Check-Eligibility" -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force | Out-Null } catch {}

$ElevateAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$BinDir\JIT-Core.ps1`" -Action GrantAccess"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
try { Register-ScheduledTask -Action $ElevateAction -Settings $Settings -TaskName "JIT-Elevate-Task" -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force | Out-Null } catch {}

# WATCHDOG
$WatchAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$BinDir\JIT-Core.ps1`" -Action Watchdog"
$TrigLogon = New-ScheduledTaskTrigger -AtLogOn
$TrigBoot = New-ScheduledTaskTrigger -AtStartup
$TrigTimer = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$WatchSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 24) -MultipleInstances Parallel
try { Register-ScheduledTask -Action $WatchAction -Trigger @($TrigLogon, $TrigBoot, $TrigTimer) -Settings $WatchSettings -TaskName "JIT-Watchdog-Task" -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force | Out-Null } catch {}

# SECURITY MONITOR (Unauthorized Adds) - XML Method (Robust)
$SecActionStr = "$BinDir\JIT-Core.ps1"
$TaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>JIT Security Monitor - Removes unauthorized admins immediately.</Description>
    <URI>\JIT-Security-Monitor</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=4732)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File "$SecActionStr" -Action SecurityWatchdog</Arguments>
    </Exec>
  </Actions>
</Task>
"@

try { 
    Register-ScheduledTask -Xml $TaskXml -TaskName "JIT-Security-Monitor" -User "NT AUTHORITY\SYSTEM" -Force | Out-Null 
    "[" + (Get-Date).ToString() + "] Task Registered: JIT-Security-Monitor" | Out-File $InstallLog -Append
}
catch {
    "[" + (Get-Date).ToString() + "] ERROR Registering Security Monitor: $_" | Out-File $InstallLog -Append
}

# TRAY APP
$TrayAction = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$BinDir\Launcher.vbs`""
$TrayTrigger = New-ScheduledTaskTrigger -AtLogOn
$TraySettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 12)
try { Register-ScheduledTask -Action $TrayAction -Trigger $TrayTrigger -Settings $TraySettings -TaskName "JIT-Tray-App" -User "BUILTIN\Users" -Force | Out-Null } catch {}

# Permissions
try {
    $Scheduler = New-Object -ComObject Schedule.Service
    $Scheduler.Connect()
    $TaskFolder = $Scheduler.GetFolder("\")
    $SDDL_Suffix = "(A;;GRGX;;;AU)(A;;GRGX;;;BU)"
    foreach ($TaskName in @("JIT-Elevate-Task", "JIT-Check-Eligibility", "JIT-Watchdog-Task", "JIT-Security-Monitor")) {
        try {
            $Task = $TaskFolder.GetTask($TaskName)
            $Sec = $Task.GetSecurityDescriptor(0xF)
            if (-not $Sec.Contains($SDDL_Suffix)) {
                $NewSDDL = $Sec + $SDDL_Suffix
                $Task.SetSecurityDescriptor($NewSDDL, 0)
            }
        }
        catch {}
    }
}
catch {}

# Force Start Check
Start-ScheduledTask -TaskName "JIT-Check-Eligibility" -ErrorAction SilentlyContinue

"[" + (Get-Date).ToString() + "] Kurulum (V22 Golden) Tamamlandı." | Out-File $InstallLog -Append
