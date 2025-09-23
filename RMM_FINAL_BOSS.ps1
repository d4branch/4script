<#
Offboard-ASIO + Bootstrap Good Tools (ScreenConnect + Syncro)
- Ensures GOOD ScreenConnect present (installs if missing)
- Ensures Syncro RMM present (installs if missing)
- Removes BAD ScreenConnect (…8eb)
- Removes ASIO/SAAZOD/SAAZODBKP/ITSPlatform services, tasks, WMI, run-keys, ARP, files
- Adds egress firewall blocks on ASIO folders
- SYSTEM-safe, 64-bit aware, robust .exe path parsing
#>

# =========================
# CONFIG (EDIT IF NEEDED)
# =========================
# Good ScreenConnect (keep/install)
$GoodClientId        = '1b85fab1db68c4d6'   # 16-hex ID in "ScreenConnect Client (<id>)"
$GoodInstallerUrl    = 'https://github.com/d4branch/4script/raw/main/ScreenConnect.ClientSetup.msi'
$GoodInstallerSha256 = ''                   # optional integrity pin (Get-FileHash -Algorithm SHA256)

# Syncro RMM (install if missing)
$SyncroInstallerUrl    = 'https://github.com/d4branch/4script/raw/main/GATEWAY_SyncroInstaller.msi'
$SyncroInstallerSha256 = ''                 # optional integrity pin

# Bad ScreenConnect (remove)
$BadTail  = '8eb'
$BadFull  = 'aec4a5eef3dce8eb'

# Parent/hostile stacks
$Parents  = @('ITSIPlatformManager','SAAZappr')
$HostileRegex = '(?i)ASIO|SAAZ|SAAZOD|SAAZODBKP|ITSI|ITSPlatform|Platform-?Agent'

# =========================
# LOGGING
# =========================
$logDir = 'C:\ProgramData\ASIO_Removal_Logs'
$null = New-Item -ItemType Directory -Force -Path $logDir -ErrorAction SilentlyContinue
$LogFile = Join-Path $logDir 'ASIO_Remove.log'
function Log([string]$m){ try{ "$(Get-Date -Format s) [$env:COMPUTERNAME] $m" | Tee-Object -FilePath $LogFile -Append | Out-Null }catch{} }
Log '===== Start cleanup/bootstrap ====='

# Relaunch in 64-bit PowerShell if currently under 32-bit host (common under SYSTEM)
if ($env:PROCESSOR_ARCHITEW6432){
  Log 'Re-launching in 64-bit PowerShell…'
  & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
  exit $LASTEXITCODE
}

# Harden TLS (older hosts)
try{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }catch{}

# =========================
# HELPERS
# =========================
function Get-ExePath([string]$cmd){
  if(-not $cmd){ return $null }
  $c = $cmd.Trim()
  if($c -match '^\s*"([^"]+?\.exe)"'){ return $matches[1] }          # quoted
  if($c -match '^\s*([^\s"]+?\.exe)'){ return $matches[1] }          # bare
  return $null
}

function Stop-Delete-ServiceByName([string]$Name){
  $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
  if($svc){
    Log "Stopping service $Name"
    try{ Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }catch{}
    $exe = Get-ExePath $svc.PathName
    if($exe){ $leaf = Split-Path $exe -Leaf; if($leaf){ try{ taskkill /IM $leaf /F 2>$null }catch{} } }
    Log "Deleting service $Name"
    sc.exe delete $Name | Out-Null
    if($exe){ try{ $dir = Split-Path $exe -Parent }catch{ $dir=$null }
      if($dir -and (Test-Path -LiteralPath $dir)){
        Log "Removing folder $dir"
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  } else { Log "Service $Name not present" }
}

function Download-IfNeeded($Url,$OutFile,$Sha256=''){
  if(Test-Path -LiteralPath $OutFile){ Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
  Log "Downloading: $Url -> $OutFile"
  try{
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
    if($Sha256){
      $h = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash
      if($h -ne $Sha256){ throw "SHA256 mismatch (have $h, expected $Sha256)" }
    }
    return $true
  }catch{
    Log "Download failed: $($_.Exception.Message)"
    return $false
  }
}

function Ensure-GoodScreenConnect{
  $sc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "ScreenConnect Client*($GoodClientId)" } |
        Select-Object -First 1
  if($sc){
    Log "Good ScreenConnect present ($GoodClientId). Ensuring Auto+Running."
    try{ Set-Service -Name $sc.Name -StartupType Automatic }catch{}
    if($sc.State -ne 'Running'){ try{ Start-Service -Name $sc.Name -ErrorAction SilentlyContinue }catch{} }
    return
  }
  Log "Good ScreenConnect NOT present; installing from MSI."
  $msi = Join-Path $env:TEMP 'ScreenConnect.ClientSetup.msi'
  if(Download-IfNeeded $GoodInstallerUrl $msi $GoodInstallerSha256){
    Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait
    Start-Sleep -s 5
    $ok = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -like "ScreenConnect Client*($GoodClientId)" } |
          Select-Object -First 1
    if($ok){
      try{ Set-Service -Name $ok.Name -StartupType Automatic }catch{}
      try{ Start-Service -Name $ok.Name -ErrorAction SilentlyContinue }catch{}
      Log "ScreenConnect installed and running."
    } else {
      Log "ScreenConnect install completed but service not detected."
    }
  }
}

function Ensure-Syncro{
  # basic detection by services/binaries
  $svcA = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Syncro.Service.Runner' -or $_.Name -eq 'SyncroLive.Agent.Runner' } | Select-Object -First 1
  $dirA = Test-Path 'C:\Program Files\RepairTech\Syncro' -PathType Container
  $dirB = Test-Path 'C:\Program Files\RepairTech\LiveAgent' -PathType Container
  if($svcA -or $dirA -or $dirB){
    Log "Syncro appears present; ensuring services are Auto+Running."
    foreach($n in 'Syncro.Service.Runner','SyncroLive.Agent.Runner'){
      if(Get-Service -Name $n -ErrorAction SilentlyContinue){
        try{ Set-Service -Name $n -StartupType Automatic }catch{}
        try{ Start-Service -Name $n -ErrorAction SilentlyContinue }catch{}
      }
    }
    return
  }
  if([string]::IsNullOrWhiteSpace($SyncroInstallerUrl)){
    Log "Syncro missing but no installer URL provided; skipping install."
    return
  }
  Log "Syncro not present; installing from MSI."
  $msi = Join-Path $env:TEMP 'SyncroInstaller.msi'
  if(Download-IfNeeded $SyncroInstallerUrl $msi $SyncroInstallerSha256){
    Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait
    Start-Sleep -s 5
    foreach($n in 'Syncro.Service.Runner','SyncroLive.Agent.Runner'){
      if(Get-Service -Name $n -ErrorAction SilentlyContinue){
        try{ Set-Service -Name $n -StartupType Automatic }catch{}
        try{ Start-Service -Name $n -ErrorAction SilentlyContinue }catch{}
      }
    }
    Log "Syncro install step finished."
  }
}

function Remove-ARP-ByDisplayNamePattern([string]$pattern){
  $hives = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
  $entries = Get-ChildItem $hives -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if($p.DisplayName -and ($p.DisplayName -match $pattern)){
      [PSCustomObject]@{ Key=$_.PSChildName; PSPath=$_.PSPath; Name=$p.DisplayName; Uninstall=$p.UninstallString }
    }
  }
  foreach($e in $entries){
    Log ("ARP remove: " + $e.Name)
    if($e.Key -match '^\{[0-9A-F-]+\}$'){ Start-Process msiexec.exe -ArgumentList "/x $($e.Key) /qn /norestart" -Wait }
    elseif($e.Uninstall){ Start-Process cmd.exe -ArgumentList "/c $($e.Uninstall) /qn" -Wait }
    if(Test-Path $e.PSPath){ Remove-Item -LiteralPath $e.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

function Kill-ScheduledTasksByPattern([string]$pattern){
  Get-ScheduledTask | Where-Object { $_.TaskName -match $pattern -or $_.TaskPath -match $pattern } |
    ForEach-Object {
      Log ("Deleting task: " + $_.TaskPath + $_.TaskName)
      try{ Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false }catch{}
    }
}
function Kill-WMIByPattern([string]$pattern){
  $ns='root\subscription'
  Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding |
    Where-Object { $_.__RELPATH -match $pattern } | ForEach-Object { Log ("WMI Bind delete: " + $_.__RELPATH); $_.Delete() | Out-Null }
  Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer |
    Where-Object { $_.Name -match $pattern } | ForEach-Object { Log ("WMI Consumer delete: " + $_.Name); $_.Delete() | Out-Null }
  Get-WmiObject -Namespace $ns -Class __EventFilter |
    Where-Object { $_.Name -match $pattern } | ForEach-Object { Log ("WMI Filter delete: " + $_.Name); $_.Delete() | Out-Null }
}
function Remove-RunKeysByPattern([string]$pattern){
  $roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
  )
  foreach($r in $roots){
    if(Test-Path $r){
      $props = (Get-Item $r | Get-ItemProperty).PSObject.Properties | Where-Object {$_.MemberType -eq 'NoteProperty'}
      foreach($p in $props){
        $val = [string]$p.Value
        if($val -match $pattern){
          Log ("Run key remove: " + $r + " :: " + $p.Name)
          try{ Remove-ItemProperty -Path $r -Name $p.Name -Force -ErrorAction SilentlyContinue }catch{}
        }
      }
    }
  }
}
function Block-EgressForFolders([string[]]$folders){
  foreach($f in $folders){
    if($f -and (Test-Path -LiteralPath $f)){
      $rule = "Block-ASIO-RMM-" + ($f -replace '[:\\\/ ]','_')
      Log ("Firewall block (program path): " + $f + "\*")
      New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program ($f + '\*') -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
  }
}

# =========================
# 0) Bootstrap good tools
# =========================
Ensure-GoodScreenConnect
Ensure-Syncro

# =========================
# 1) Kill parent services first (prevents re-spawn)
# =========================
foreach($p in $Parents){ Stop-Delete-ServiceByName $p }

# =========================
# 2) Remove ONLY the bad ScreenConnect instance (…8eb)
# =========================
$badSvc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
  $_.DisplayName -match ("ScreenConnect Client.*" + [regex]::Escape($BadFull) + "\)") -or
  $_.DisplayName -match ("ScreenConnect Client.*" + [regex]::Escape($BadTail) + "\)")
} | Select-Object -First 1

if($badSvc){
  Log ("Stopping bad SC service " + $badSvc.Name)
  try{ Stop-Service -Name $badSvc.Name -Force -ErrorAction SilentlyContinue }catch{}
  Log ("Deleting bad SC service " + $badSvc.Name); sc.exe delete $badSvc.Name | Out-Null

  $paths = @()
  $svcExe = Get-ExePath $badSvc.PathName
  if($svcExe){ $paths += (Split-Path $svcExe -Parent) }

  foreach($root in @('HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node')){
    $k = Join-Path $root ("ScreenConnect Client (" + $BadFull + ")")
    if(Test-Path $k){
      $ip = (Get-ItemProperty $k -ea 0).InstallPath
      if($ip){ $paths += $ip }
      Log ("Removing registry " + $k); Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  $paths | Where-Object { $_ } | Select-Object -Unique | ForEach-Object {
    if(Test-Path -LiteralPath $_){ Log ("Removing folder " + $_); Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction SilentlyContinue }
  }

  # ARP cleanup for the bad instance
  $patternBadSC = 'ScreenConnect Client.*\(([a-f0-9]{16})\)$'
  $hives = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
  $entries = Get-ChildItem $hives -ea 0 | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ea 0
    if($p.DisplayName -like 'ScreenConnect Client*'){
      $m = [regex]::Match($p.DisplayName,$patternBadSC)
      if($m.Success -and ($m.Groups[1].Value -eq $BadFull -or $m.Groups[1].Value -like ("*" + $BadTail))){
        [PSCustomObject]@{ Key=$_.PSChildName; PSPath=$_.PSPath; Name=$p.DisplayName; Uninstall=$p.UninstallString }
      }
    }
  }
  foreach($e in $entries){
    Log ("ARP remove (bad SC): " + $e.Name)
    if($e.Key -match '^\{[0-9A-F-]+\}$'){ Start-Process msiexec.exe -ArgumentList "/x $($e.Key) /qn /norestart" -Wait }
    elseif($e.Uninstall){ Start-Process cmd.exe -ArgumentList "/c $($e.Uninstall) /qn" -Wait }
    if(Test-Path $e.PSPath){ Remove-Item -LiteralPath $e.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
  }
}else{
  Log 'Bad ScreenConnect service not found (already removed or renamed)'
}

# =========================
# 3) Remove remaining hostile stacks (SAAZOD / SAAZODBKP / ITSPlatform)
# =========================
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match $HostileRegex -or $_.DisplayName -match $HostileRegex -or $_.PathName -match $HostileRegex
} | ForEach-Object {
  $n = $_.Name
  try{ Stop-Service -Name $n -Force -ErrorAction SilentlyContinue }catch{}
  sc.exe delete $n | Out-Null
  $exe = Get-ExePath $_.PathName
  if($exe){
    $leaf = Split-Path $exe -Leaf
    if($leaf){ try{ taskkill /IM $leaf /F 2>$null }catch{} }
    $dir = $null; try{ $dir = Split-Path $exe -Parent }catch{}
    if($dir -and (Test-Path -LiteralPath $dir)){
      Log ("Removing folder " + $dir)
      Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

# Scheduled tasks / WMI / Run keys / ARP
Kill-ScheduledTasksByPattern $HostileRegex
Kill-WMIByPattern $HostileRegex
Remove-RunKeysByPattern $HostileRegex
Remove-ARP-ByDisplayNamePattern $HostileRegex

# Delete well-known folders (if any still exist) + block egress
$folders = @(
  'C:\Program Files (x86)\SAAZOD',
  'C:\Program Files (x86)\SAAZODBKP',
  'C:\Program Files (x86)\ITSPlatform',
  'C:\ProgramData\SAAZOD',
  'C:\ProgramData\ITSPlatform'
)
foreach($f in $folders){ if(Test-Path -LiteralPath $f){ Log ("Removing folder " + $f); Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction SilentlyContinue } }
Block-EgressForFolders $folders

# =========================
# 4) Verify & tidy
# =========================
$remain = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match $HostileRegex -or $_.DisplayName -match $HostileRegex -or $_.PathName -match $HostileRegex -or $_.DisplayName -like 'ScreenConnect Client*'
} | Select-Object Name,State
Log ("Remaining related services: " + (($remain | ForEach-Object { $_.Name + ':' + $_.State }) -join ', '))

$arpLeft = Get-ChildItem @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') -ea 0 |
  ForEach-Object { (Get-ItemProperty $_.PSPath -ea 0).DisplayName } |
  Where-Object { $_ -like 'ScreenConnect Client*' }
Log ("Remaining SC ARP entries: " + (($arpLeft | Sort-Object -Unique) -join '; '))

Stop-Process -Name SystemSettings -Force -ErrorAction SilentlyContinue
ipconfig /flushdns | Out-Null
Log '===== End cleanup/bootstrap ====='
