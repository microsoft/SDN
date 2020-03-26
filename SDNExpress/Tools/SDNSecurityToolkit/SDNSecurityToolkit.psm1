function Invoke-SDNVipScan
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, HelpMessage="Path to SdnExpress network resource file if available")]
        $sdnNetworkResourceFile,
        [Parameter(Mandatory=$false, HelpMessage='SDN Connection URI, required if sdnExpressConfig not set')]
        $URI,
        [Parameter(Mandatory=$true, HelpMessage="Path to NMAP exe")]
        $nmapPath,
        [Parameter(Mandatory=$false, HelpMessage="Path to save JSON output")]
        $jsonoutput,
        [Parameter(Mandatory=$false, HelpMessage="Path to save HTML report")]
        $htmloutput,
        [Parameter(Mandatory=$false, HelpMessage="Scan entire logical network list with nmap -Pn, extremely slow but more thorough")]
        $deepScan

    )
    #Validate URI or sdnNetworkResourceFile set
    if($URI -eq $null -and $sdnNetworkResourceFile -eq $null)
    {
        Write-Error "Either sdnNetworkResourceFile or URI must be set"
        return
    }

    #NMAP validations
    $oldestsupported = 7.00
    $nmapOutput = cmd /c ($nmapPath)
    $nmapOutput = $nmapOutput.split('`n')
    $nmapOutput = $nmapOutput.split(' ')
    $nmapVersion = [float] $nmapOutput[1]

    if($nmapOutput[0] -ne 'Nmap')
    {
        Write-Error "Nmap executable not recognized"
        return
    }
    if($nmapVersion -lt $oldestsupported)
    {
        Write-Error "Nmap executable provided is older than " $oldestsupported
        return
    }

    if([System.IO.File]::Exists($sdnNetworkResourceFile))
    {
        $payload = get-content -Path $sdnNetworkResourceFile -raw
        $config = convertfrom-json $payload
    }

    if($uri -eq $null)
    {
        $uri = $config.NetworkControllerRestName
    }

    #Retrieve logical network lists
    $PublicSubnets = (get-networkcontrollerlogicalnetwork -ConnectionUri $uri).properties.subnets | where-object {$_.Properties.IsPublic -eq $true}
    $ManagementSubnets = (Get-networkcontrollerlogicalnetwork -ConnectionUri $uri).properties.subnets | where-object {$_.ResourceRef -like '*GreVIP*'}
    
    $TestSubnets = new-object system.collections.arraylist
    $TestSubnets += $PublicSubnets
    $TestSubnets += $ManagementSubnets

    $TestIpPools = $TestSubnets.properties.IpPools.properties
    $testIPs = $TestSubnets.properties.AddressPrefix
    $IpConfigurations = $TestSubnets.properties.IpConfigurations.ResourceRef
    
    #Get VIPs in Loadbalancer
    $exposedIps = @{}
    $exposedIpList = new-object system.collections.arraylist

    $LoadBalancers = get-networkcontrollerloadbalancer -connectionuri $uri

    $outputObj = @{}
    $htmlObj = new-object system.collections.arraylist

    $outputObj.ExposedIps = new-object system.collections.arraylist

    Write-Verbose "Gathering public VIPs registered accross load balancers:"
    foreach($LoadBalancer in $LoadBalancers)
    {
        $frontendIPCs = $LoadBalancer.Properties.FrontendIPConfigurations
        Write-Verbose ("Searching for frontend IP configurations in loadbalancer " + $LoadBalancer.resourceId)
        foreach($IPC in $frontendIPCS)
        {
            $exposedIpsObj = @{
                Ip = $IPC.properties.privateIPAddress
                PortStatus = new-object system.collections.arraylist
            }
            $exposedIpsHtmlObj = @{
                IP = $IPC.properties.privateIPAddress
                PortStatus = ""
                AssociatedRules = ""
            }
            Write-Verbose ("Found frontend IP configuration " + $IPC.resourceId + " (" + $IPC.Properties.privateIPAddress + ") ") 
            $rules = $LoadBalancer.Properties.loadbalancingrules | where-object {$_.properties.FrontendIPConfigurations.ResourceRef -contains $IPC.resourceRef}
            $inbound = $LoadBalancer.Properties.InboundNatRules | where-object {$_.properties.FrontendIPConfigurations.ResourceRef -contains $IPC.resourceRef}
            $outbound = $LoadBalancer.Properties.OutboundNatRules | where-object {$_.properties.FrontendIPConfigurations.ResourceRef -contains $IPC.resourceRef}

            if($rules -ne $null)
            {
                Write-Verbose ("Associated loadbalancing rule: " + $rules.resourceref)
                $ports = $rules.Properties.FrontendPort
            
                if( $exposedIps.($IPC.properties.privateIPAddress) -eq $null)
                {
                    $exposedIps.($IPC.properties.privateIPAddress) = $ports
                    $exposedIpList += $IPC.properties.privateIPAddress
                }  
                else
                {
                    $exposedIps.($IPC.properties.privateIPAddress) += $ports
                }      
                $exposedIpsObj.AssociatedRules = $rules.resourceRef
                foreach($ref in $rules.resourceref)
                {
                $exposedIpsHtmlObj.AssociatedRules += ($ref + '<br/>')
                }
            }
            if($inbound -ne $null)
            {
                Write-Verbose ("Associated inbound NAT: " + $inbound.resourceref)
                $exposedIpsObj.InboundNAT = $inbound.resourceref
                $exposedIpsHtmlObj.AssociatedRules += $inbound.resourceref
            }
            if($outbound -ne $null)
            {
                Write-Verbose ("Associated outbound NAT: " + $outbound.resourceref)
                $exposedIpsObj.OutboundNAT = $outbound.resourceref
                $exposedIpsHtmlObj.AssociatedRules += $outbound.resourceref
            }
            $outputObj.ExposedIps += $exposedIpsObj
            $htmlObj += $exposedIpsHtmlObj
        }
    }

    Write-Verbose 'Scanning Loadbalanced IPs using nmap:'


    foreach($ip in $exposedIpList)
    {
        Write-Verbose ("Scanning $ip, expect " + ($exposedIps.$ip) + " to be open")
        $commaseparatedPorts = $exposedIps.$ip -join ","
        Write-Verbose ("$nmapPath $ip -Pn -pT:" + $commaseparatedPorts)
        $nmapoutput = (cmd /c ("$nmapPath $ip -Pn -pT:" + $commaseparatedPorts) 2> $null)
  
        $nmapoutput = $nmapoutput.split("`n")

        $exposedIpsObj = $outputObj.ExposedIps | where-object Ip -eq $ip
        $exposedIpsHtmlObj = $htmlObj | where-object Ip -eq $ip
        #parse nmap output to get exposed ports
        $exposedPorts
        $nmapindex = $nmapoutput.length - $exposedIps.$ip.length - 2

        foreach($port in $exposedIps.$ip) {
            #parse nmap output to determine port status
            $nmapline = $nmapoutput[$nmapindex]
            $nmapindex++
            Write-Verbose $nmapline
            $state = $nmapline.split(' ')[1]
            $exposedIpsObj.PortStatus += @{
                port = $port
                state = $state
            }

            $exposedIpsHtmlObj.PortStatus += "$port : $state <br/>"
        }
    }

    Write-Verbose 'Scanning ranges from logical network lists for inconsistencies:' 

    $outputObj.Alert = new-object system.collections.arraylist
    foreach($testip in $testips)
    {
        Write-Verbose ("Scanning " + $testip)
        $nmapOutput = $null
        if( -not $deepscan) {
            $nmapoutput = cmd /c("$nmapPath $testip") 2>$null
        } else {
            $nmapoutput = cmd /c("$nmapPath $testip -Pn") 2>$null
        }

        #regex for matching (roughly) against any ipv4 address
        $ipPattern = '\d+\.\d+\.\d+\.\d+'

        $matches = $nmapoutput | select-string $ipPattern -AllMatches
        $matchedIps = $matches.Matches.value

        if($mathedIps -ne $null) {
            Write-Verbose "Found open IPs: " $matchedIps
        } else {
            Write-Verbose 'No open IPs, you may perform a deep scan on these ranges using nmap [IP range] -Np, or rerunning this tool with -DeepScan $true but this will be very slow.'
        }

        foreach($ip in $matchedIps)
        {
            if($ip -in $outputObj.ExposedIps.Ip)
            {
                Write-Verbose ($ip + " expected to be open under existing rules")
            } else {
                Write-Verbose ("Warning: " + $ip + " not expected to be open under existing rules")
                $outputObj.alert += @{
                    ip = $ip
                    nmapoutput = $nmapoutput
                }
                $outputObj.alert += $ip
            }
        }

    }


    if($jsonoutput -ne $null)
    {
        $outputObj | convertto-json -depth 100 | out-file $jsonoutput
    }

    if($htmloutput -ne $null)
    {
        $htmltext = "<html><style>
    table, td, th {
        border: 1px solid black;
    };
    th {
        text-align: left;
    };
    </style>
    <h1>SLB Public VIP Scanner Results: </h1><table><colgroup><col><col><col></colgroup>"
        $htmltext += "<tr>"
        $keys = $htmlObj[0].keys
        foreach($heading in $keys)
        {
            $htmltext += "<th><h3>$heading</h3></th>"
        }
        $htmltext += "</tr>"
        foreach($ipEntry in $htmlObj)
        {
            $htmltext += "<tr>"
            foreach($key in $keys)
            {
                $htmltext += "<th>" + $ipEntry.$key + "</th>"
            }
            $htmltext += "</tr>"
        }
        $htmltext += "</table>"

        $htmltext += "<br/><h3>IP addresses detected open despite being unregistered in the load balancer: </h3>"
        if($outputobj.alert.length -lt 1)
        {
            $htmltext += "<p>None</p>"
        }
        else
        {
            foreach($alert in $outputobj.alert)
            {
                $htmltext += "<p>" + $outputobj.alert.ip + "<br/>" + $outputobj.alert.nmapoutput + "</p>"
            }
        }

        $htmltext += "</html>"

        $htmltext | out-file $htmloutput
    }

    return $outputObj
}