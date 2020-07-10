$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){

$runtime = Measure-Command{

Write-Host ('Starting NurseOne Script')

$ErrorActionPreference = "silentlycontinue"

$Comp = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -Property *
$IP = (((Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object -ExpandProperty IPAddress) -like "*.*")[0])
$OSBuild = ((Get-WMIObject win32_operatingsystem).version)
$OS = ((Get-WMIObject win32_operatingsystem).caption)

if ((Test-Path -Path ($env:ProgramData+'\NurseOne') -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path ($env:ProgramData+'\NurseOne')}

if ((Get-ChildItem -Path ($env:ProgramData+'\NurseOne') -Recurse).count -ge 100)
{
Get-ChildItem -Path ($env:ProgramData+'\NurseOne') -Recurse | Sort-Object LastWriteTime | Select-Object -First ((Get-ChildItem -Path ($env:ProgramData+'\NurseOne') -Recurse).count -1) | Remove-Item -Force
}

$Inv = ($env:ProgramData+'\NurseOne\NurseOne_'+ $Comp.Name +'_Inv_'+(get-date -Format 'yyyy-MM-dd')+".json") 
if ((test-path $Inv) -eq $false) {new-item $Inv -Type file -Force}

write-host ('------------------------------------------') 

write-host ('Hostname: ') -NoNewline
write-host ($Comp.Name) -ForegroundColor Magenta

write-host ('Domain: ') -NoNewline
write-host ($Comp.Domain) -ForegroundColor Magenta

write-host ('IP Address: ') -NoNewline
write-host $IP -ForegroundColor Magenta

write-host ('Operating System: ') -NoNewline
write-host $OS -ForegroundColor Magenta

write-host ('OS Build: ') -NoNewline
write-host $OSBuild -ForegroundColor Magenta

write-host ('------------------------------------------') 

Write-Host ('Page File: ') -NoNewline
if($Comp.AutomaticManagedPagefile -eq 1)
{
write-host ('OS Managed. ') -ForegroundColor Green 
}
else
{
write-host ('Non OS Managed. ') -ForegroundColor Red
}

Write-Host ('Memory Dump File: ') -NoNewline
if ((Get-CimInstance -Class Win32_OSRecoveryConfiguration).DebugInfoType -eq 3 -or (Get-CimInstance -Class Win32_OSRecoveryConfiguration).DebugInfoType -eq 0)
{
write-host ('Disabled or Small.') -ForegroundColor Red
}
else
{
write-host ('Enabled.') -ForegroundColor Green 
}

Write-Host ('Important Services: ') -NoNewline
if((Get-Service -Name Dnscache,Spooler,LanmanServer,StateRepository,SENS,Schedule,Appinfo,CryptSvc,DcomLaunch,diagtrack).status -ne 'Running')
{
write-host ('Not Running.') -ForegroundColor Red
}
else
{
write-host ('Running.') -ForegroundColor Green 
}


$Update = Get-HotFix | sort { [datetime]$_.InstalledOn },HotFixID -desc | Select-Object -First 1

Write-Host ('Lastest Hostfix installed: ') -NoNewline
if ((New-TimeSpan -Start $Update.InstalledOn.ToShortDateString() -End (get-date)).Days -ge 30)
{
write-host $Update.HotFixID -NoNewline -ForegroundColor Red
Write-Host '. Install date: ' -NoNewline
write-host $Update.InstalledOn.ToShortDateString() -ForegroundColor Red
Write-Host ('Remediate Action: Triggering Windows Update..')
Invoke-Command -ScriptBlock {wuauclt.exe /updatenow}
}
else
{
write-host $Update.HotFixID -NoNewline -ForegroundColor Green
Write-Host '. Install date: ' -NoNewline
write-host $Update.InstalledOn.ToShortDateString() -ForegroundColor Green
}

$wmi = Invoke-Command -ScriptBlock {winmgmt -verifyrepository}

Write-Host ('WMI: ') -NoNewline
if (!($wmi | Select-String -Pattern 'WMI repository is consistent'))
{
write-host $wmi -ForegroundColor Red
Write-Host ('Remediate Action: Rebuilding inconsistent repository..')
Invoke-Command -ScriptBlock {winmgmt -salvagerepository}
}
else
{
write-host $wmi -ForegroundColor Green
}

$dism = Invoke-Command -ScriptBlock {DISM /Online /Cleanup-Image /CheckHealth}

Write-Host ('DISM Health: ') -NoNewline
if (!($dism[6] | Select-String -Pattern 'No component store corruption detected.'))
{
write-host $dism[6] -ForegroundColor Red
}
else
{
write-host $dism[6] -ForegroundColor Green
}

Write-Host ('Internet Access to Microsoft: ') -NoNewline
$atping = @()
$atping += (Invoke-WebRequest -Uri "ctldl.windowsupdate.com" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode
$atping += (Invoke-WebRequest -Uri "microsoft.com" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode
$atping += (Invoke-WebRequest -Uri "securitycenter.windows.com" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 3).StatusCode
$atping += (Invoke-WebRequest -Uri "update.microsoft.com" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode
$atping += (Invoke-WebRequest -Uri "winatp-gw-eus.microsoft.com/test" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode
$atping += (Invoke-WebRequest -Uri "winatp-gw-cus.microsoft.com/test" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode
$atping += (Invoke-WebRequest -Uri "winatp-gw-weu.microsoft.com/test" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode
$atping += (Invoke-WebRequest -Uri "winatp-gw-neu.microsoft.com/test" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 2).StatusCode

if($atping.count -ne 8)
{
write-host 'Failed' -ForegroundColor Red
}
else
{
write-host 'Success' -ForegroundColor Green
}

Write-Host ('LDAP client signing: ') -NoNewline
$ldap = (Get-Itemproperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' -Name 'ldapclientintegrity').ldapclientintegrity
if($ldap -eq 1)
{
write-host 'Negotiate signing' -ForegroundColor Green
}
elseif($ldap -eq 0)
{
write-host 'None' -ForegroundColor Red
}
elseif($ldap -eq 2)
{
write-host 'Require signature' -ForegroundColor Green
}

Write-Host ('% Processor Time: ') -NoNewline
$proc = get-counter -Counter "\Processor(_Total)\% Processor Time"
if(($proc.CounterSamples.CookedValue.toString('###.##')) -ge 80)
{
write-host ($proc.CounterSamples.CookedValue.toString('###.##')+' %') -ForegroundColor Red 
}
else
{
write-host ($proc.CounterSamples.CookedValue.toString('###.##')+' %') -ForegroundColor Green
}

Write-Host ('Available Memory: ') -NoNewline
$mem = Get-Counter -Counter "\Memory\Available Bytes"
if(((($mem.CounterSamples.CookedValue)/1024)/1024).ToString('#####.##') -le 250)
{
write-host (((($mem.CounterSamples.CookedValue)/1024)/1024).ToString('#####.##')+' MB') -ForegroundColor Red 
}
else
{
write-host (((($mem.CounterSamples.CookedValue)/1024)/1024).ToString('#####.##')+' MB') -ForegroundColor Green
}

Write-Host ('% Disk Free Space (in C:): ') -NoNewline
$disk = Get-Counter -counter "\LogicalDisk(*)\% Free Space"
$disk = $disk.CounterSamples | ? {$_.InstanceName -eq 'c:'}
if($Disk.CookedValue -le 20)
{
write-host ($Disk.CookedValue.ToString('###.##')+' %') -ForegroundColor Red 
}
else
{
write-host ($Disk.CookedValue.ToString('###.##')+' %') -ForegroundColor Green
}


$InvData = @{

'Hostname' = $Comp.Name;
'Domain' = $Comp.Domain;
'IP' = $IP;
'OS' = $OS;
'Build' = $OSBuild;
'PageFile' = $Comp.AutomaticManagedPagefile;
'HotFix' = $Result.HotFixID;
'WMI' = $wmi;
'DISM' = $dism[6];
'Ldap' = $ldap;
'ATPPing' = $atping.count;
'ProcTime' = $proc.CounterSamples.CookedValue;
'Memory' = $mem.CounterSamples.CookedValue;
'Disk' = $Disk.CookedValue;

}

ConvertTo-Json $InvData | Out-File $Inv

}
Write-Host ('Total Script runtime: ') -NoNewline
write-host ($runtime.TotalSeconds.ToString('##########.##')+' Secs') -ForegroundColor Magenta

}
else
{
Write-Host ('This script has to be run with administrative rights..')
}
