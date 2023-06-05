param (
    [Parameter(Mandatory=$false)]
    [bool]$DnsOnly = $false,

    [Parameter(Mandatory=$false)]
    [bool]$DnsPktCap = $false
)

$Global:All = $true

if ($DnsOnly -eq $true) {
    $All = $false
}


function CountAvailableEphemeralPorts([string]$protocol = "TCP") {

    [uint32]$portRangeSize = 64
    # First, remove all the text bells and whistle (plain text, table headers, dashes, empty lines, ...) from netsh output 
    $tcpRanges = (netsh int ipv4 sh excludedportrange $protocol) -replace "[^0-9,\ ]", '' | ? { $_.trim() -ne "" }
 
    # Then, remove any extra space characters. Only capture the numbers representing the beginning and end of range
    $tcpRangesArray = $tcpRanges -replace "\s+(\d+)\s+(\d+)\s+", '$1,$2' | ConvertFrom-String -Delimiter ","
    #Convert from PSCustomObject to Object[] type
    $tcpRangesArray = @($tcpRangesArray)
    
    # Extract the ephemeral ports ranges
    $EphemeralPortRange = (netsh int ipv4 sh dynamicportrange $protocol) -replace "[^0-9]", '' | ? { $_.trim() -ne "" }
    $EphemeralPortStart = [Convert]::ToUInt32($EphemeralPortRange[0])
    $EphemeralPortEnd = $EphemeralPortStart + [Convert]::ToUInt32($EphemeralPortRange[1]) - 1

    # Find the external interface
    $externalInterfaceIdx = (Get-NetRoute -DestinationPrefix "0.0.0.0/0")[0].InterfaceIndex
    $hostIP = (Get-NetIPConfiguration -ifIndex $externalInterfaceIdx).IPv4Address.IPAddress

    # Extract the used TCP ports from the external interface
    $usedTcpPorts = (Get-NetTCPConnection -LocalAddress $hostIP -ErrorAction Ignore).LocalPort
    $usedTcpPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_ } }

    # Extract the used TCP ports from the 0.0.0.0 interface
    $usedTcpGlobalPorts = (Get-NetTCPConnection -LocalAddress "0.0.0.0" -ErrorAction Ignore).LocalPort
    $usedTcpGlobalPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_ } }
    # Sort the list and remove duplicates
    $tcpRangesArray = ($tcpRangesArray | Sort-Object { $_.P1 } -Unique)

    $tcpRangesList = New-Object System.Collections.ArrayList($null)
    $tcpRangesList.AddRange($tcpRangesArray)

    # Remove overlapping ranges
    for ($i = $tcpRangesList.P1.Length - 2; $i -gt 0 ; $i--) { 
        if ($tcpRangesList[$i].P2 -gt $tcpRangesList[$i + 1].P1 ) { 
            $tcpRangesList.Remove($tcpRangesList[$i + 1])
            $i++
        } 
    }

    # Remove the non-ephemeral port reservations from the list
    $filteredTcpRangeArray = $tcpRangesList | ? { $_.P1 -ge $EphemeralPortStart }
    $filteredTcpRangeArray = $filteredTcpRangeArray | ? { $_.P2 -le $EphemeralPortEnd }
    
    if ($null -eq $filteredTcpRangeArray) {
        $freeRanges = @($EphemeralPortRange[1])
    }
    else {
        $freeRanges = @()
        # The first free range goes from $EphemeralPortStart to the beginning of the first reserved range
        $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[0].P1) - $EphemeralPortStart)

        for ($i = 1; $i -lt $filteredTcpRangeArray.length; $i++) {
            # Subsequent free ranges go from the end of the previous reserved range to the beginning of the current reserved range
            $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[$i].P1) - [Convert]::ToUInt32($filteredTcpRangeArray[$i - 1].P2) - 1)
        }

        # The last free range goes from the end of the last reserved range to $EphemeralPortEnd
        $freeRanges += ($EphemeralPortEnd - [Convert]::ToUInt32($filteredTcpRangeArray[$filteredTcpRangeArray.length - 1].P2))
    }
    
    # Count the number of available free ranges
    [uint32]$freeRangesCount = 0
    ($freeRanges | % { $freeRangesCount += [Math]::Floor($_ / $portRangeSize) } )

    return $freeRangesCount
}


function CheckHnsDnsRuleMissing {
    $expectedDnsRuleCount = 2
    Write-Host "Checking HNS DNS Rule missing"
    $dnsRuleCount = ((Get-HnsPolicyList).Policies | where InternalPort -EQ 53 | where ExternalPort -EQ 53).Count
    if($dnsRuleCount -lt $expectedDnsRuleCount) {
        Write-Host "HNS DNS rule count is $dnsRuleCount. DNS issue for sure." -ForegroundColor Red
        Write-Host "Resolution: Upgrade to 1.24.10+, 1.25.6+, 1.26.1+, 1.27.0+" -ForegroundColor Red
        Write-Host "Mitigation : Restart-Service -f kubeproxy" -ForegroundColor Red
        return $true
    }
    Write-Host "HNS DNS rule count is $dnsRuleCount. No DNS issue due to missing HNS DNS rules." -ForegroundColor Green
    return $false
}

function CheckHnsDeadlock {
    Write-Host "Checking HNS Deadlock."
    $hnsThreadThrshold = 100
    $hnsProcessId = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Hns'" | Select-Object -ExpandProperty ProcessId
    $hnsThreads = (Get-Process -Id $hnsProcessId).Threads
    $threadCount = $hnsThreads.Count
    if($threadCount -ge $hnsThreadThrshold) {
        Write-Host "HNS thread count is $threadCount which is greater than expected $hnsThreadThrshold. There are chances of deadlock." -ForegroundColor Red
        Write-Host "Resolution: Upgrade to Windows 2022" -ForegroundColor Red
        Write-Host "Mitigation : Restart-Service -f hns , Start-Sleep -Seconds 10 ; Restart-Service -f KubeProxy " -ForegroundColor Red
        return $true
    }
    Write-Host "HNS thread count is $threadCount . No chances of deadlock." -ForegroundColor Green
    return $false
}

function CheckHnsCrash {
    Write-Host "Checking HNS crash"
    $hnsCrashCount = (Get-WinEvent -FilterHashtable @{logname = 'System'; ProviderName = 'Service Control Manager' } | Select-Object -Property TimeCreated, Id, LevelDisplayName, Message | Where-Object Message -like "*The Host Network Service terminated unexpectedly*").Count
    if($hnsCrashCount -gt 0) {
        Write-Host "HNS crash count is $hnsCrashCount. There are chances of issues." -ForegroundColor Red
        Write-Host "Resolution: Upgrade to 1.24.10+, 1.25.6+, 1.26.1+, 1.27.0+" -ForegroundColor Red
        Write-Host "Mitigation : Restart-Service -f KubeProxy " -ForegroundColor Red
        return $true
    }
    Write-Host "HNS crash count is $hnsCrashCount. No issue reported with HNS crash." -ForegroundColor Green
    return $false
}

function CheckPortExhaustion {
    Write-Host "Checking Port Exhaustion"
    $avTcpPorts = CountAvailableEphemeralPorts -protocol TCP
    if($avTcpPorts -lt 10) {
        Write-Host "Available TCP ports are $avTcpPorts. Port exhaustion suspected." -ForegroundColor Red
        return $true
    }
    $avUdpPorts = CountAvailableEphemeralPorts -protocol UDP
    if($avTcpPorts -lt 10) {
        Write-Host "Available UDP ports are $avUdpPorts. Port exhaustion suspected." -ForegroundColor Red
        return $true
    }
    Write-Host "Available TCP Ports :  $avTcpPorts , UDP Ports : $avUdpPorts . No port exhaustion suspected." -ForegroundColor Green
    return $false
}

function CheckKubeProxyCrash {
    Write-Host "Checking KubeProxy restart"
    for($i = 1; $i -le 10; $i++) {
        $status = (Get-Service kubeproxy).Status
        if($status -eq "Stopped") {
            Write-Host "KubeProxy is restarting. There are chances of issues." -ForegroundColor Red
            Write-Host "Resolution: Upgrade to v1.24.12+, v1.25.8, v1.26.3+, v1.27.0+" -ForegroundColor Red
            Write-Host "Mitigation : Restart the node or drain to a new node " -ForegroundColor Red
            return $true
        }
        $waitTime = (10 - $i)
        Write-Host "Checking KubeProxy restart. Wait time : $waitTime seconds"
        Start-Sleep -Seconds 1
    }
    Write-Host "KubeProxy service state is $status . No issues identified with KubeProxy restart." -ForegroundColor Green
    return $false
}

function CheckVfpDnsRuleMissing {
    Write-Host "Checking VFP DNS Rule missing"
    $vfpDnsRuleMissing = $false
    $endpoints = Get-HnsEndpoint
    foreach($ep in $endpoints) {
        if($ep.IsRemoteEndpoint -eq $true) {
            # Write-Host "REP found : $ep"
            continue
        }
        $epID = $ep.ID
        $epMac = $ep.MacAddress
        $epIpAddress = $ep.IPAddress
        $portID = $ep.Resources.Allocators[0].EndpointPortGuid
        $tcpRule = vfpctrl.exe /port $portID /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | Select-String -Pattern "RULE.*53_53_6"
        if($tcpRule.Count -lt 1) {
            $vfpDnsRuleMissing = $true
            Write-Host "VFP DNS TCP Rule missing for VFP Port : $portID . Endpoint ID : $epID , Mac : $epMac , IP Address : $epIpAddress" -ForegroundColor Red
        }
        $udpRule = vfpctrl.exe /port $portID /layer LB_DSR /group LB_DSR_IPv4_OUT /list-rule | Select-String -Pattern "RULE.*53_53_17"
        if($udpRule.Count -lt 1) {
            $vfpDnsRuleMissing = $true
            Write-Host "VFP DNS UDP Rule missing for VFP Port : $portID . Endpoint ID : $epID , Mac : $epMac , IP Address : $epIpAddress" -ForegroundColor Red
        }
    }

    if($vfpDnsRuleMissing){
        Write-Host "Mitigation : Restart-Service -f hns " -ForegroundColor Red
        return $true
    }

    Write-Host "No issues identified with VFP DNS Rule Missing for local endpoints." -ForegroundColor Green
    return $false
}

function DnsPktCapture {
    $pktmonLogs = "C:\k\pktmonLogs"
    $captureTime = 15
    pktmon stop
    Write-Host "Starting DNS Packet Capture"
    Write-Host "Removing all pktmon filters if anything existing..."
    pktmon filter remove
    Write-Host "Create DNS Port filter..."
    pktmon filter add DNSFilter -p 53
    Write-Host "Create a directory for pktmon logs..."
    remove-item -Recurse -Force $pktmonLogs -ErrorAction Ignore
    mkdir $pktmonLogs
    Set-Location $pktmonLogs
    Write-Host "Start pktmon. Command : [pktmon start -c --comp all --pkt-size 0 -m multi-file] ..."
    pktmon start -c --comp all --pkt-size 0 -m multi-file
    Write-Host "Waiting for $captureTime seconds."
    Start-Sleep -Seconds $captureTime
    pktmon stop
    Write-Host "Logs will be available in $pktmonLogs"
    Write-Host "DNS Packet Capture Completed"
}

function ValidateDns {
    Write-Host "Checking DNS Issue."
    if(CheckHnsDnsRuleMissing) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
        return $true
    }
    if(CheckHnsDeadlock) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
        return $true
    }
    if(CheckHnsCrash) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
        return $true
    }
    if(CheckPortExhaustion) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
        return $true
    }
    if(CheckKubeProxyCrash) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
        return $true
    }
    if(CheckVfpDnsRuleMissing) {
        Write-Host "DNS Issue Found." -ForegroundColor Red
        return $true
    }
    Write-Host "No DNS Issues identified as per current test." -ForegroundColor Green
}



if ($All -or $DnsOnly) {
    $dnsIssueFound = ValidateDns
    if(!$dnsIssueFound -and $DnsPktCap) {
        DnsPktCapture
    }
}