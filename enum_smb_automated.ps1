param(
    [string]$TargetHost
)

$shareOutput = net view "\\$TargetHost" 2>&1
$results = @()
$startParsing = $false

foreach ($line in $shareOutput) {
    if ($line -match "^----+") {
        $startParsing = -not $startParsing
        continue
    }

    if ($startParsing -and $line.Trim() -ne "") {
        $shareName = $line.Trim().Split(" ")[0]
        $path = "\\$TargetHost\$shareName"
        if (Test-Path $path) {
            $results += "$path : [+] Access Granted."
        } else {
        }
    }
}

$results | ForEach-Object { Write-Output $_ }