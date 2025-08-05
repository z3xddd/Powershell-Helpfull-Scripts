#Import powerview before.

Get-NetComputer -Domain "corp2.com" | % { $n=$_.DNSHostName; $i=(Resolve-DnsName $n -Type A -ErrorAction SilentlyContinue | ? Type -eq 'A' | Select -Expand IPAddress); [PSCustomObject]@{DNSHostName=$n; IPAddress=$(if($i.Count-gt1){"{$($i-join', ')}"}else{$i})} }
