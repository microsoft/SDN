Param(
    [parameter(Mandatory = $false)] [string] $FileName = "dnsinfo.txt",
    [parameter(Mandatory = $false)] [int] $WaitTime = 1200, # In seconds
    [parameter(Mandatory = $false)] [int] $Interval = 3, # interval (in seconds) to query DNS rules
    [parameter(Mandatory = $false)] [bool] $VerifyVfpRules = $true
)

# Helper functions
function listDnsPolicies() {
    $dnsPolicies = ((Get-HnsPolicyList | where { $_.Policies.InternalPort -EQ 53 } | where { $_.Policies.ExternalPort -EQ 53 }) | Select Policies, ID, References)
    return $dnsPolicies
}

function dnsPoliciesToString($dnsPolicies) {
    $dnsPolicies | ForEach-Object {
        $dnsPoliciesString = $dnsPoliciesString + ("`nID: $($_.ID) `nReferences: $($_.References)`nPolicies:$($_.Policies)")
    }
    return $dnsPoliciesString
}

function getDnsRules($portGuid, $dnsServerIP) {
    $lbRulesRaw = cmd /c "vfpctrl /port $portGuid /list-rule /layer LB_DSR /group LB_DSR_IPv4_OUT"

    $lbRules = $lbRulesRaw |
    Where-Object { $_ -match ' ' } |
    ForEach-Object {
        $_ -replace ' ', ''
    }
    # Filter out DNS rule names
    $dnsRuleNames = $lbRules |
    Where-Object { $_ -like "RULE:LB_DSR_*_*_$($dnsServerIP)_53_53_6" -or $_ -like "RULE:LB_DSR_*_*_$($dnsServerIP)_53_53_17" }

    $dnsRules = @()
    $dnsRuleNames | 
    ForEach-Object {
        $fields = $_ -split ":"
        $dnsRules += cmd /c "vfpctrl /port $portGuid /get-rule-counter /layer LB_DSR /group LB_DSR_IPv4_OUT /rule $($fields[1])"
    }
    return $dnsRuleNames, $dnsRules
}


function consistentDnsRules($oldDnsRules, $currentDnsRules) {
    if (($currentDnsRules.Count -ne 2) -or ($oldDnsRules.Count -ne 2)) {
        return $false
    }
    for ($i = 0; $i -le (2); $i++) {
        if ($oldDnsRules[$i] -ne $currentDnsRules[$i]) {
            return $false
        }
    }
    return $true
}

function getPortGuidMap() {
    $rawPortsOutput = cmd /c "vfpctrl /list-vmswitch-port"
    # Some very case specific parsing
    $rawPortsOutput = $rawPortsOutput |
    Where-Object { $_ -match ' ' } |
    ForEach-Object {
        $_ -replace ' ', ''
    }

    #  Port names and MACs
    $portMacs = $rawPortsOutput |
    Where-Object { $_ -like 'Portname:*' -or $_ -like 'MACaddress:*' }

    $port = ""
    $mac = ""
    $macToPortGuids = @{}
    $portMacs | 
    ForEach-Object {
        $fields = $_ -split ":"
        Switch ($fields[0]) {
            "Portname" { $port = $fields[1] }
            "MACaddress" { $mac = $fields[1] }
        }
        $macToPortGuids[$mac] = $port
    }
    return $macToPortGuids
}

function getDnsRulesAll($endpoints, $dnsServerIP, $verbose = $false) {
    $endpointDnsRules = @{}
    $endpointLbRules = @{}
    $macToPortGuids = getPortGuidMap
    $expectedDnsRuleCount = ($endpoints).Count * 2
    $dnsRulesCount = 0
    $endpoints |
    ForEach-Object {
        $dnsRules, $lbRules = getDnsRules $macToPortGuids[$_.MACaddress] $dnsServerIP
        $endpointDnsRules[$_.IPAddress] = $dnsRules
        $endpointLbRules[$_.IPAddress] = $lbRules
        $dnsRulesCount = $dnsRulesCount + $dnsRules.Count
        if ($verbose) {
            Write-Output "Found DNS rules for pod $($_.IPAddress):`n$($dnsRules)" >> $FileName
            Write-Output "Found LB rules for pod $($_.IPAddress):`n$($lbRules)" >> $FileName
        }
    }
    if ($dnsRulesCount -ne $expectedDnsRuleCount) {
        Write-Output "Unexpected DNS rule count! Expected: $($expectedDnsRuleCount)`nActual: $($dnsRulesCount)." >> $FileName
    }
    else {
        Write-Output "[OK] Found $($dnsRulesCount) DNS rules across all pods." >> $FileName
    }
    return $endpointDnsRules, $endpointLbRules
}

# Main
Remove-Item $FileName -ErrorAction SilentlyContinue
while ((listDnsPolicies).Count -ne 2) {
    Write-Output "Waiting for DNS policies..."
    start-sleep 5
}
Write-Output "Monitoring DNS rules in $FileName..."

$oldDnsPolicies = listDnsPolicies
$dnsServerIP = $oldDnsPolicies[0].Policies.VIPs
Write-Output "[OK] Found DNS Server VIP $($dnsServerIP)" >> $FileName
Write-Output "[OK] Starting DNS policy: $(dnsPoliciesToString $oldDnsPolicies)" >> $FileName

if ($VerifyVfpRules) {
    # Get starting VFP DNS rules
    $endpoints = (get-hnsendpoint | ? IsRemoteEndpoint -ne True) | Select-Object MACaddress, IPAddress
    Write-Output "[OK] Querying starting DNS rules..." >> $FileName
    $oldEndpointDnsRules, $oldEndpointLbRules = getDnsRulesAll $endpoints $dnsServerIP $true
}

for ($i = 0; $i -le ($WaitTime / $Interval); $i++) {
    $timeNow = Get-Date
    Write-Output "#====== Iteration : $i . Time : $timeNow " >> $FileName
    $iterationHealth = $true
    # Verify HNS DNS policies are consistent
    $currentDnsPolicies = listDnsPolicies
    if (($currentDnsPolicies).Count -ne 2) {
        Write-Output "DNS policies not found!`nOld: $(dnsPoliciesToString $oldDnsPolicies).`nNew: $(dnsPoliciesToString $currentDnsPolicies)" >> $FileName
        # Skip analyzing the VFP rules until DNS policies are present again. 
        $iterationHealth = $false
        Write-Output "#====== Iteration $i Completed. Health: $iterationHealth." >> $FileName
        Start-Sleep -Seconds $Interval
        continue
    }
    elseif ($currentDnsPolicies[0].ID -ne $oldDnsPolicies[0].ID) {
        Write-Output "DNS policies have changed!`nOld: $(dnsPoliciesToString $oldDnsPolicies).`nNew: $(dnsPoliciesToString $currentDnsPolicies)" >> $FileName
        Write-Output "Updating new DNS policy to $($currentDnsPolicies.ID)..." >> $FileName
        $oldDnsPolicies = $currentDnsPolicies
        $iterationHealth = $false
    }
    else {
        Write-Output "[OK] DNS policies are consistent. Current: $($currentDnsPolicies.ID)" >> $FileName
    }
    
    if ($VerifyVfpRules) {
        # Verify DNS VFP rules are consistent across all endpoints
        $endpoints = (get-hnsendpoint | ? IsRemoteEndpoint -ne True) | Select-Object MACaddress, IPAddress
        $endpointDnsRules, $endpointLbRules = getDnsRulesAll $endpoints $dnsServerIP
        # IP address in $endpoints currently exists. If it exists in old table, then pod was always here.
        # If it does not exist in old table, then it is a new pod. Need to add it there.
        $endpoints |
        ForEach-Object {
            if (-not ($endpointDnsRules.Keys.Contains($_.IPAddress))) {
                Write-Output "DNS rules not found for pod $($_.IPAddress)!" >> $FileName
                # Skip, DNS rules are not found...
                $iterationHealth = $false
                continue
            }
            elseif ( $endpointDnsRules[$_.IPAddress].Count -ne 2 ) {
                Write-Output "DNS rules partially missing for pod $($_.IPAddress)!" >> $FileName
                $iterationHealth = $false
            }
            elseif (-not ($oldEndpointDnsRules.Keys -contains $_.IPAddress)) {
                # New pod
                Write-Output "Found new pod with IP $($_.IPAddress)." >> $FileName
                Write-Output "Found DNS rules for pod $($_.IPAddress):`n$($endpointDnsRules[$_.IPAddress])" >> $FileName
                Write-Output "Found LB rules for pod $($_.IPAddress):`n$($endpointLbRules[$_.IPAddress])" >> $FileName
                $oldEndpointDnsRules[$_.IPAddress] = $endpointDnsRules[$_.IPAddress]
                $oldEndpointLbRules[$_.IPAddress] = $endpointLbRules[$_.IPAddress]
            }
            # If current != old, then something has changed. Print the rules.
            if ((consistentDnsRules $oldEndpointDnsRules[$_.IPAddress] $endpointDnsRules[$_.IPAddress])) {
                Write-Output "[OK] DNS rules are consistent for pod $($_.IPAddress)." >> $FileName
            }
            else {
                Write-Output "DNS rules have changed for pod $($_.IPAddress)!.`nOld:`n$($oldEndpointLbRules[$_.IPAddress])`nNew:`n$($endpointLbRules[$_.IPAddress])" >> $FileName
                Write-Output "Updating new DNS rules for pod $($_.IPAddress) to: $($endpointDnsRules[$_.IPAddress])..." >> $FileName
                $iterationHealth = $false
                $oldEndpointDnsRules[$_.IPAddress] = $endpointDnsRules[$_.IPAddress]
                $oldEndpointLbRules[$_.IPAddress] = $endpointLbRules[$_.IPAddress]
            }
        }
    }
    Write-Output "Iteration $i Completed. Health: $iterationHealth." >> $FileName
    Start-Sleep -Seconds $Interval
}