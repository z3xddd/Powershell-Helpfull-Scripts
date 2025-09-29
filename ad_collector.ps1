param(
    [string]$ReportPath = ".\SystemReports",
    [string]$CompanyDomain = $env:USERDOMAIN,
    [switch]$FullInventory,
    [switch]$UserAccounts,
    [switch]$SecurityGroups,
    [switch]$Workstations,
    [switch]$AccessReview,
    [switch]$SlowMode,
    [int]$DelaySeconds = 15
)

Set-StrictMode -Version 3
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

$FunctionNames = @("Get-EmployeeData", "Get-TeamData", "Get-DeviceData", "Get-SecurityData")

function Invoke-EmployeeListing {
    Write-Output "[*] Coletando informações de colaboradores..."
    
    $employeeList = @()
    $staffMembers = Get-ADUser -Filter * -Properties SamAccountName, DistinguishedName, SID, Enabled, MemberOf, LastLogon, pwdLastSet, Description, Title
    
    foreach ($person in $staffMembers) {
        $teamMemberships = @()
        if ($person.MemberOf) {
            foreach ($groupDN in $person.MemberOf) {
                $team = Get-ADGroup $groupDN -Properties SID 2>$null
                if ($team) { $teamMemberships += $team.SID.Value }
            }
        }
        
        $employeeList += @{
            ID = $person.SID.Value
            Type = "Employee"
            Details = @{
                login = $person.SamAccountName
                fullpath = $person.DistinguishedName
                domaincode = $person.SID.AccountDomainSid.Value
                company = $CompanyDomain
                active = $person.Enabled
                securityflag = $person.AdminCount
                lastpassword = [datetime]::FromFileTime($person.pwdLastSet)
                lastaccess = [datetime]::FromFileTime($person.LastLogon)
                notes = $person.Description
                position = $person.Title
                teams = $teamMemberships
            }
        }
    }
    
    return $employeeList
}

function Invoke-TeamStructure {
    Write-Output "[*] Analisando estrutura de equipes..."
    
    $teamStructure = @()
    $companyTeams = Get-ADGroup -Filter * -Properties SamAccountName, DistinguishedName, SID, Description, MemberOf
    
    foreach ($team in $companyTeams) {
        $teamMembers = Get-ADGroupMember -Identity $team.DistinguishedName -Recursive 2>$null | 
                      Select-Object SID, ObjectClass
        
        $teamStructure += @{
            ID = $team.SID.Value
            Type = "Team"
            Details = @{
                name = $team.SamAccountName
                fullpath = $team.DistinguishedName
                domaincode = $team.SID.AccountDomainSid.Value
                company = $CompanyDomain
                securityflag = $team.AdminCount
                description = $team.Description
                members = @($teamMembers | ForEach-Object { $_.SID.Value })
            }
        }
    }
    
    return $teamStructure
}

function Invoke-DeviceInventory {
    Write-Output "[*] Inventariando dispositivos corporativos..."
    
    $deviceList = @()
    $companyDevices = Get-ADComputer -Filter * -Properties Name, DistinguishedName, SID, Enabled, OperatingSystem, LastLogon
    
    foreach ($device in $companyDevices) {
        $deviceList += @{
            ID = $device.SID.Value
            Type = "Device"
            Details = @{
                hostname = $device.Name
                fullpath = $device.DistinguishedName
                domaincode = $device.SID.AccountDomainSid.Value
                company = $CompanyDomain
                active = $device.Enabled
                os = $device.OperatingSystem
                lastaccess = if ($device.LastLogon -gt 0) { 
                    [datetime]::FromFileTime($device.LastLogon) 
                } else { $null }
            }
        }
    }
    
    return $deviceList
}

function Invoke-PermissionAudit {
    Write-Output "[*] Revisando configurações de acesso..."
    
    $accessMatrix = @()
    
    $sampleUsers = Get-ADUser -Filter {AdminCount -eq 1} -Properties nTSecurityDescriptor | Select-Object -First 10
    $sampleGroups = Get-ADGroup -Filter {AdminCount -eq 1} -Properties nTSecurityDescriptor | Select-Object -First 10
    
    foreach ($item in (@($sampleUsers) + @($sampleGroups))) {
        $acl = $item.nTSecurityDescriptor
        if ($acl) {
            foreach ($ace in $acl.Access) {
                $accessMatrix += @{
                    Source = $ace.IdentityReference.Value
                    Target = $item.SID.Value
                    Relation = "Access"
                    Properties = @{
                        Permission = $ace.ActiveDirectoryRights.ToString()
                        Inherited = $ace.IsInherited
                    }
                }
            }
        }
    }
    
    return $accessMatrix
}

function Start-GradualCollection {
    Write-Output "[*] Executando coleta incremental..."
    
    $inventoryData = @()
    $collectionSteps = @(
        { Invoke-EmployeeListing },
        { Invoke-TeamStructure },
        { Invoke-DeviceInventory },
        { Invoke-PermissionAudit }
    )
    
    foreach ($step in $collectionSteps) {
        try {
            $inventoryData += & $step
            Write-Output "[+] Etapa concluída. Aguardando próximo ciclo..."
            Start-Sleep -Seconds $DelaySeconds
        }
        catch {
            Write-Output "[!] Etapa com intercorrência, continuando..."
        }
    }
    
    return $inventoryData
}

try {
    if (!(Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $inventoryResults = @()

    if ($SlowMode) {
        $inventoryResults = Start-GradualCollection
    } else {
        if ($FullInventory -or $UserAccounts) {
            $inventoryResults += Invoke-EmployeeListing
        }
        
        if ($FullInventory -or $SecurityGroups) {
            $inventoryResults += Invoke-TeamStructure
        }
        
        if ($FullInventory -or $Workstations) {
            $inventoryResults += Invoke-DeviceInventory
        }
        
        if ($FullInventory -or $AccessReview) {
            $inventoryResults += Invoke-PermissionAudit
        }
    }

    $reportFile = Join-Path $ReportPath "system_inventory_$currentTime.dat"
    $inventoryResults | ConvertTo-Json -Depth 8 | Out-File -FilePath $reportFile -Encoding UTF8

    $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-Content $reportFile -Raw))
    $compressed = [System.Convert]::ToBase64String($bytes)
    $finalFile = Join-Path $ReportPath "network_audit_$currentTime.bin"
    $compressed | Out-File -FilePath $finalFile -Encoding ASCII
    
    Remove-Item $reportFile -Force
    
    Write-Output "[*] Processo de inventário concluído: $finalFile"
    Write-Output "[*] Itens documentados: $($inventoryResults.Count)"
}
catch {
    Write-Output "[!] Interrupção no processo de inventário"
}
