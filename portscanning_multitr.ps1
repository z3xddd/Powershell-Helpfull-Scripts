<#
.SYNOPSIS
    Port Scanner com Multi-threading em PowerShell
.DESCRIPTION
    Escaneia portas TCP em um alvo específico usando multi-threading
    para melhor performance.
.PARAMETER Target
    IP ou hostname do alvo
.PARAMETER Ports
    Array de portas para escanear (padrão: portas mais comuns)
.PARAMETER Timeout
    Timeout em milissegundos para cada tentativa (padrão: 100ms)
.PARAMETER Threads
    Número de threads simultâneas (padrão: 50)
.PARAMETER AllPorts
    Escanear todas as portas de 1 a 65535
.EXAMPLE
    Invoke-PortScan -Target "192.168.1.1" -Threads 100
.EXAMPLE
    Invoke-PortScan -Target "example.com" -Ports @(80,443,22,21,3389) -Timeout 200
.EXAMPLE
    Invoke-PortScan -Target "10.0.0.1" -AllPorts -Threads 200
#>

function Invoke-PortScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        
        [int[]]$Ports,
        [int]$Timeout = 100,
        [int]$Threads = 50,
        [switch]$AllPorts
    )
    
    if ($AllPorts) {
        $Ports = 1..65535
        Write-Host "[!] Scanning ALL 65535 ports - This may take a while..." -ForegroundColor Yellow
    }
    elseif (-not $Ports) {
        $Ports = Get-DefaultPorts
    }
    
    $startTime = Get-Date
    $openPorts = [System.Collections.ArrayList]@()
    $totalPorts = $Ports.Count
    $completedPorts = 0
    $lock = New-Object System.Object
    
    Write-Host "`n=== PowerShell Port Scanner ===" -ForegroundColor Green
    Write-Host "Target: $Target" -ForegroundColor Cyan
    Write-Host "Ports to scan: $totalPorts" -ForegroundColor Cyan
    Write-Host "Threads: $Threads" -ForegroundColor Cyan
    Write-Host "Timeout: ${Timeout}ms" -ForegroundColor Cyan
    Write-Host "Start time: $startTime" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Green
    
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $runspacePool.Open()
    $jobs = New-Object System.Collections.ArrayList
    
    foreach ($port in $Ports) {
        $powershell = [powershell]::Create()
        $powershell.RunspacePool = $runspacePool
        
        [void]$powershell.AddScript({
            param($target, $port, $timeout)
            
            $result = @{
                Port = $port
                Status = "CLOSED"
                Protocol = "Unknown"
                Banner = $null
            }
            
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $asyncResult = $tcpClient.BeginConnect($target, $port, $null, $null)
                $wait = $asyncResult.AsyncWaitHandle.WaitOne($timeout, $false)
                
                if ($wait -and $tcpClient.Connected) {
                    $tcpClient.EndConnect($asyncResult)
                    $result.Status = "OPEN"
                    $result.Protocol = Get-ServiceName -Port $port
                    
                    try {
                        $stream = $tcpClient.GetStream()
                        $stream.ReadTimeout = 500
                        $writer = New-Object System.IO.StreamWriter($stream)
                        $reader = New-Object System.IO.StreamReader($stream)
                        
                        $writer.WriteLine("HEAD / HTTP/1.0`r`n")
                        $writer.Flush()
                        Start-Sleep -Milliseconds 100
                        $banner = $reader.ReadLine()
                        if ($banner) { $result.Banner = $banner.Trim() }
                    }
                    catch {
                    }
                }
            }
            catch {
            }
            finally {
                if ($tcpClient) { $tcpClient.Close() }
            }
            
            return $result
        })
        
        [void]$powershell.AddArgument($Target)
        [void]$powershell.AddArgument($port)
        [void]$powershell.AddArgument($Timeout)
        
        $job = [PSCustomObject]@{
            PowerShell = $powershell
            AsyncResult = $powershell.BeginInvoke()
            Port = $port
        }
        
        [void]$jobs.Add($job)
    }
    
    while ($jobs.Count -gt 0) {
        foreach ($job in $jobs.ToArray()) {
            if ($job.AsyncResult.IsCompleted) {
                $result = $job.PowerShell.EndInvoke($job.AsyncResult)
                
                if ($result.Status -eq "OPEN") {
                    $message = "Port $($result.Port) : OPEN - $($result.Protocol)"
                    if ($result.Banner) { $message += " [$($result.Banner)]" }
                    Write-Host $message -ForegroundColor Green
                    
                    $lockObject = [PSCustomObject]@{
                        Port = $result.Port
                        Status = $result.Status
                        Protocol = $result.Protocol
                        Banner = $result.Banner
                    }
                    [void]$openPorts.Add($lockObject)
                }
                
                $job.PowerShell.Dispose()
                $jobs.Remove($job)
                
                $completedPorts++
                $progress = [math]::Round(($completedPorts / $totalPorts) * 100, 2)
                Write-Progress -Activity "Scanning Ports" -Status "$progress% Complete ($completedPorts/$totalPorts)" -PercentComplete $progress
            }
        }
        Start-Sleep -Milliseconds 100
    }
    
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`n" + "=" * 50 -ForegroundColor Green
    Write-Host "SCAN COMPLETED!" -ForegroundColor Green
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Cyan
    Write-Host "Open ports found: $($openPorts.Count)" -ForegroundColor Yellow
    
    if ($openPorts.Count -gt 0) {
        Write-Host "`n=== OPEN PORTS ===" -ForegroundColor Green
        $openPorts | Sort-Object Port | Format-Table -AutoSize -Property Port, Protocol, Banner
    } else {
        Write-Host "No open ports found." -ForegroundColor Red
    }
    
    return $openPorts | Sort-Object Port
}

function Get-DefaultPorts {
    return @(
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
        993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443,
        20, 67, 68, 69, 123, 161, 162, 389, 636, 989, 990,
        1194, 1701, 1720, 1812, 1813, 2222, 3128, 3268, 3269,
        5000, 5060, 5222, 5223, 5269, 5280, 5298, 8000, 8008,
        8081, 8444, 8888, 9000, 9001, 9090, 9100, 10000
    )
}

function Get-ServiceName {
    param([int]$Port)
    
    $serviceMap = @{
        21 = "FTP"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        53 = "DNS"
        67 = "DHCP Server"
        68 = "DHCP Client"
        69 = "TFTP"
        80 = "HTTP"
        110 = "POP3"
        123 = "NTP"
        135 = "RPC"
        139 = "NetBIOS"
        143 = "IMAP"
        161 = "SNMP"
        162 = "SNMP Trap"
        389 = "LDAP"
        443 = "HTTPS"
        445 = "SMB"
        636 = "LDAPS"
        989 = "FTPS Data"
        990 = "FTPS Control"
        993 = "IMAPS"
        995 = "POP3S"
        1194 = "OpenVPN"
        1433 = "MSSQL"
        1701 = "L2TP"
        1720 = "H.323"
        1723 = "PPTP"
        1812 = "RADIUS Auth"
        1813 = "RADIUS Accounting"
        2222 = "DirectAdmin"
        3128 = "Squid Proxy"
        3268 = "LDAP GC"
        3269 = "LDAP GC SSL"
        3306 = "MySQL"
        3389 = "RDP"
        5000 = "UPnP"
        5060 = "SIP"
        5222 = "XMPP"
        5223 = "XMPP SSL"
        5269 = "XMPP Server"
        5280 = "XMPP HTTP"
        5298 = "XMPP J2ME"
        5900 = "VNC"
        8000 = "HTTP Alt"
        8008 = "HTTP Alt2"
        8080 = "HTTP Proxy"
        8081 = "HTTP Alt3"
        8443 = "HTTPS Alt"
        8444 = "HTTPS Alt2"
        8888 = "HTTP Alt4"
        9000 = "Hadoop"
        9001 = "Tor"
        9090 = "WebSM"
        9100 = "JetDirect"
        10000 = "Webmin"
    }
    
    return $serviceMap[$Port]
}

function Invoke-PortRangeScan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [int]$StartPort = 1,
        [int]$EndPort = 1024,
        [int]$Timeout = 100,
        [int]$Threads = 50
    )
    
    $Ports = $StartPort..$EndPort
    return Invoke-PortScan -Target $Target -Ports $Ports -Timeout $Timeout -Threads $Threads
}

Write-Host "`n=== EXEMPLOS DE USO ===" -ForegroundColor Yellow
Write-Host "1. Scan portas comuns: Invoke-PortScan -Target `"192.168.1.1`"" -ForegroundColor White
Write-Host "2. Scan portas específicas: Invoke-PortScan -Target `"example.com`" -Ports 80,443,22,21,3389" -ForegroundColor White
Write-Host "3. Scan todas as portas: Invoke-PortScan -Target `"10.0.0.1`" -AllPorts -Threads 200" -ForegroundColor White
Write-Host "4. Scan range: Invoke-PortRangeScan -Target `"192.168.1.100`" -StartPort 1 -EndPort 1000" -ForegroundColor White
Write-Host "`n"
