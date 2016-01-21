<#
    .COPYRIGHT 
        File="NCDiagnostics.ps1" Company="Microsoft"
        Copyright (c) Microsoft Corporation.  All rights reserved.        
    .SYNOPSIS 
      Script to configure logging on Network Controller setup and collect diagnostics data.
    .EXAMPLE
        # To Setup logging on all NC Nodes and hosts.
        .\NCDiagnostics.ps1 NC-0.contoso.cloud.com -SetupDiagnostics
        
        # To collect diagnostics data and Logs from all NC Nodes and hosts.
        $cred = Get-Credential                                                                                                                                                                   
        .\NCDiagnostics.ps1 -NetworkController NC-0.contoso.cloud.com -Credential $cred -OutputDirectory C:\DiagnosticsData

        # To collect only diagnostics data
        .\NCDiagnostics.ps1 -NetworkController NC-0.contoso.cloud.com -Credential $cred -OutputDirectory C:\DiagnosticsData -IncludeTraces $false
#>
param(
    [string][parameter(Mandatory=$true, HelpMessage="One Network controller Node Name/IP")]$NetworkController,
    [Switch][parameter(Mandatory=$false, HelpMessage="Setup Diagnostics. Will retrieve diagnostics information by default.")]$SetupDiagnostics = $false,
    [bool][parameter(Mandatory=$false, HelpMessage="Include Host Agent and NC Traces")]$IncludeTraces = $true,
    [string][parameter(Mandatory=$false,HelpMessage="Complete Path to the Output Directory")]$OutputDirectory = (Get-Location).Path,
    [System.Management.Automation.PSCredential][parameter(Mandatory=$false, HelpMessage="Credential to use for Network Controller. Specify in case of Kerberos deployment.")]$Credential = $null,
    [String][parameter(Mandatory=$false, HelpMessage="The URI to be used for Network Controller REST APIs. Specify in case of wild card certificate deployment.")]$RestURI = $null,
	[String][parameter(Mandatory=$false, HelpMessage="Certificate thumbprint to use for Network Controller. Specify in case of certificate deployment.")]$CertificateThumbprint = $null,
	[String][parameter(Mandatory=$false, HelpMessage="Complete path to the directory where NC Diagnostics tools are present. This should have ovsdb-client.exe")]$ToolsDirectory = (Get-Location).Path
)

#region Utility functions
function GetPSSession
{
    param($computerName)
    $psSession = $null
    if($Global:Credential -ne $null)
    {
        $psSession = New-PSSession -ComputerName $computerName -Credential $Global:Credential
    }
    elseif($Global:CertificateThumbprint -ne $null -and $Global:CertificateThumbprint -ne "")
    {
        $psSession = New-PSSession -ComputerName $computerName -CertificateThumbprint $Global:CertificateThumbprint
    }
    else
    {
        $psSession = New-PSSession -ComputerName $computerName 
    }
    return $psSession
}

function GetSystemDrive
{
    param ($psSession)
    $systemDrive = Invoke-Command -Session $psSession -ScriptBlock{ 
                        $s = Get-WMIObject -class Win32_OperatingSystem | select-object SystemDrive
                        return $s.SystemDrive
                        }
    return $systemDrive
}

function RemovePSSession
{
    param($session)
    Remove-PSSession $session
}

function RemovePSDrive
{
    Remove-PSDrive -Name S -ErrorAction SilentlyContinue
}
	
function GetAllManagementIPs
{
    param($resources)
    
    $ips = @()

    foreach($resource in $resources.value)
    {
        $connections = $resource.properties.connections.Where{$_.managementAddresses -ne $null -and $_.managementAddresses.Count -gt 0}
        if($connections -ne $null -and $connections.Count -gt 0)
        {
            $connection = $connections.Where{$_.credentialType -eq 'UsernamePassword'}
            if($connection -eq $null -or $connection.Count -eq 0)
            {
                $connection = $connections[0]
            }
            else
            {
                $connection = $connection[0]
            }

            $managementIPAddress = $connection.managementAddresses[0]
            if(-not $ips.Contains($managementIPAddress))
            {
                $ips += $managementIPAddress
            }
        }
    }
    return $ips
}

function GetRESTOutput
{
    param( [parameter(Mandatory=$true)][string]$Url)

    if($Global:Credential -ne $null)
    {
        $restOutput = Invoke-RestMethod "$Url" -Credential $Global:Credential -UseBasicParsing
    }
    elseif($Global:ClientCert -ne $null)
    {
        $restOutput = Invoke-RestMethod "$Url" -CertificateThumbprint $Global:ClientCert -UseBasicParsing
    }
    else
    {
        $restOutput = Invoke-RestMethod "$Url" -UseBasicParsing
    }
    return $restOutput
}

function InvokeREST
{
    param
    (
        [parameter(Mandatory=$true)]
        [string] $BaseUrl,
        [parameter(Mandatory=$true)]
        [string] $BaseType,
        [parameter(Mandatory=$true)]
        [string] $OutputFolder,
        [parameter(Mandatory=$false)]
        [string] $ResourceId
    ) 

    $_baseType = $BaseType;
    if ($ResourceId -ne $nul)
    {
        $_baseType += "/$ResourceId"
    }

    $URL = "$BaseUrl/$_baseType"

    $restOutput = GetRESTOutput $URL
    
    $restOutput | ConvertTo-Json -Depth 10 >> "$OutputFolder/$BaseType.Json"
}

function CollectRESTDataFromNC
{
    param($NCURI, $Destination)
    
    md $Destination -ErrorAction SilentlyContinue

    $BaseUrl = "$NCURI/Networking/v1"

    InvokeREST -BaseUrl $BaseUrl -BaseType "accessControlLists" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "credentials" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "servers" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "virtualServers" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "logicalnetworks" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "macPools" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "virtualnetworks" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "networkinterfaces" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "publicIpAddresses" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "loadBalancerMuxes" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "loadBalancers" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "gatewaypools" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "gateways" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "virtualgateways" -OutputFolder $Destination
    InvokeREST -BaseUrl $BaseUrl -BaseType "virtualnetworkmanager" -ResourceId  "configuration" -OutputFolder $Destination
}

function CollectNetworkControllerState
{
    param($NCURI)

    $headers = @{"Accept"="application/json"}
    $content = "application/json; charset=UTF-8"
    $network = "https://$NCURI/Networking/v1"
    $timeout = 10

    $method = "Put"
    $uri = "$network/diagnostics/networkcontrollerstate"
    $body = '{"properties": { }}'
 
    try
    {
        if($Global:Credential -ne $null)
        {
            Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -Body $body -DisableKeepAlive -Credential $Global:Credential -UseBasicParsing
        }
        elseif($Global:ClientCert -ne $null)
        {
            Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -Body $body -DisableKeepAlive -CertificateThumbprint $Global:ClientCert -UseBasicParsing
        }
        else
        {
            Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -Body $body -DisableKeepAlive -UseBasicParsing
        }
    }
    catch
    {
      Write-Host "Failed to retrieve Network Controller State"
    }
}

function CollectDiagnosticsDataFromGateway
{
    param ($gateway, $DestinationPath, $IncludeTraces)
    
    $psSession = GetPSSession $gateway

    if($psSession -eq $null)
    {
        Write-Host "Cannot connect to Gateway " $gateway
        return
    }
    
    $sys = GetSystemDrive $psSession
    
    $path = "\\$gateway\" + $sys.Replace(":","$")

    if($Global:Credential -ne $null)
    {
        New-PSDrive -Name S -PSProvider filesystem -Root $path -Credential $Global:Credential
    }
    else
    { 
        New-PSDrive -Name S -PSProvider filesystem -Root $path
    }
    
    Write-Host "Collecting Diagnostics data from Gateway " $gateway

    md $DestinationPath -ErrorAction SilentlyContinue
    
    Invoke-Command -Session $psSession -ArgumentList $IncludeTraces,$sys -ScriptBlock  {
        param 
        (
            [bool][parameter(Mandatory=$false)]$IncludeTraces = $true,
            [string]$sys
        )

        if($IncludeTraces -eq $true)
        {
            try
            {
                # Reset Logman
                logman stop GatewayTrace
                logman start GatewayTrace
            }
            catch
            {
                # do nothing
            }
        }
        
        $OutDirectory = "$sys\NCDiagnostics"
        md $OutDirectory -ErrorAction SilentlyContinue
        
        # Collect information
        Get-NetCompartment | fl * > "$OutDirectory\NetCompartment.txt"
        Get-NetIpInterface –IncludeAllCompartments | fl * > "$OutDirectory\NetIpInterface.txt"
        Get-NetRoute -IncludeAllCompartments | fl * > "$OutDirectory\NetRoutes.txt"
        Get-NetIpAddress -IncludeAllCompartments | fl * > "$OutDirectory\NetIPAddress.txt"
        Get-VpnS2SInterface | fl * > "$OutDirectory\VpnS2SInterface.txt"
        Get-RemoteAccess| fl * > "$OutDirectory\RemoteAccess.txt"
        netsh wfp show state > "$OutDirectory\wfpState.txt"
    }
    
    if($IncludeTraces)
    {
        Copy-Item  -Recurse -Path S:\Windows\tracing -Destination $DestinationPath -ErrorAction SilentlyContinue
    }

    Copy-Item -Path S:\NCDiagnostics -Destination $DestinationPath -Recurse -ErrorAction SilentlyContinue
    RemovePSDrive
    RemovePSSession $psSession
}

function CollectDiagnosticsDataFromGateways
{
    param($Gateways, $includeTraces)
    
    Write-Host "Collecting Diagnostics data from Gateways"

    foreach($Gateway in $Gateways)
    {
        $DestinationPath = [System.IO.Path]::Combine($OutputDirectory, "Gateway-$Gateway")
        CollectDiagnosticsDataFromServer $Gateway $DestinationPath $includeTraces
    }
}

function CollectDiagnosticsDataFromServer
{
    param ($server, $DestinationPath, $IncludeTraces)
    
    $psSession = GetPSSession $server

    if($psSession -eq $null)
    {
        Write-Host "Cannot connect to Host " $server
        return
    }

    Write-Host "Collecting Diagnostics data from Host " $server

    md $DestinationPath -ErrorAction SilentlyContinue
    
    $sys = GetSystemDrive $psSession
        
    $path = "\\$server\" + $sys.Replace(":","$")

    if($Global:Credential -ne $null)
    {
        New-PSDrive -Name S -PSProvider filesystem -Root $path -Credential $Global:Credential
    }
    else
    { 
        New-PSDrive -Name S -PSProvider filesystem -Root $path
    }
    
    md "S:\NCDiagnosticsTools" -ErrorAction SilentlyContinue

    Get-ChildItem $global:ToolsDirectory -Recurse -Filter *.exe | Where-Object { $_.PSIsContainer -eq $False } | ForEach-Object {Copy-Item -Path $_.Fullname -Destination "S:\NCDiagnosticsTools" -Force} 

    Invoke-Command -Session $psSession -ArgumentList $IncludeTraces, $sys -ScriptBlock  {
        param 
        (
            [bool][parameter(Mandatory=$false)]$IncludeTraces = $true,
            [string]$sys
        )

        function CollectPortPolicies
        {
            $vfpCtrlExe = "$sys\windows\system32\vfpctrl.exe"
            $switches = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualEthernetSwitch
            foreach ($switch in $switches) 
            {
                try
                {
                    $ports = $switch.GetRelated("Msvm_EthernetSwitchPort", "Msvm_SystemDevice", $null, $null, $null, $null, $false, $null)
                    echo "Policy for Switch : " $switch.ElementName
                    foreach ($port in $ports) 
                    {
                        $portGuid = $port.Name
                        echo "Policy for port : " $portGuid
                        & $vfpCtrlExe /list-space  /port $portGuid
                        & $vfpCtrlExe /list-mapping  /port $portGuid
                        & $vfpCtrlExe /list-rule  /port $portGuid
                        & $vfpCtrlExe /port $portGuid /get-port-state
                    }
                }
                catch
                {
                    # do nothing
                }
            }
        }
        
        if($IncludeTraces -eq $true)
        {
            try
            {
                # Reset Logman
                logman stop HostAgentTrace
                logman start HostAgentTrace
            }
            catch
            {
                # do nothing
            }
        }

        $OutDirectory = "$sys\NCDiagnostics"
        md $OutDirectory -ErrorAction SilentlyContinue

        $service=Get-Service NCHostAgent
        
        if ($service.Status -ne "Stopped") 
        { 
            & $sys\NCDiagnosticsTools\ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep > "$OutDirectory\ovsdb_ms_vtep.txt" 
            & $sys\NCDiagnosticsTools\ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall > "$OutDirectory\ovsdb_ms_firewall.txt" 
            & $sys\NCDiagnosticsTools\ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion > "$OutDirectory\ovsdb_ms_service_insertion.txt"
        }
        

        # Collect VFP Port policies
        CollectPortPolicies > "$OutDirectory\vfp_policy.txt"

        # Collect additional information
        ipconfig /allcompartments /all > "$OutDirectory\ipconfigall.txt"
        Get-NetAdapter > "$OutDirectory\networkadapters.txt"
        Get-NetAdapter | fl * >> "$OutDirectory\networkadapters.txt"
        Get-VMNetworkAdapter -All > "$OutDirectory\vmnetworkadapters.txt"
        Get-netipaddress -IncludeAllCompartments > "$OutDirectory\netipaddress.txt"
        Get-netroute -IncludeAllCompartments > "$OutDirectory\netroute.txt"
        Get-VMNetworkAdapterVlan > "$OutDirectory\vmnetworkadaptersvlan.txt"
        Get-vm | Get-VMNetworkAdapter | fl * >> "$OutDirectory\vmnetworkadapters.txt"
        Get-VMNetworkAdapterIsolation | fl * > "$OutDirectory\vmnetworkadapterisolation.txt"
        Get-VMSwitch  > "$OutDirectory\vmswitches.txt"
        Get-VMSwitch | fl * >> "$OutDirectory\vmswitches.txt"
    }
    
    if($IncludeTraces)
    {
        Copy-Item  -Recurse -Path S:\Windows\tracing -Destination $DestinationPath -ErrorAction SilentlyContinue
    }

    Copy-Item -Path S:\NCDiagnostics -Destination $DestinationPath -Recurse -ErrorAction SilentlyContinue
    RemovePSDrive
    RemovePSSession $psSession
}

function CollectDiagnosticsDataFromServers
{
    param($Servers, $includeTraces)
    
    Write-Host "Collecting Diagnostics data from Hosts"

    foreach($Server in $Servers)
    {
        $DestinationPath = [System.IO.Path]::Combine($OutputDirectory, "Host-$Server")
        CollectDiagnosticsDataFromServer $Server $DestinationPath $includeTraces
    }
}

function CollectDiagnosticsDataFromNCNode
{
    param ($node, $DestinationPath, $includeTraces)
    
    $psSession = GetPSSession $node
    
    if($psSession -eq $null)
    {
        Write-Host "Cannot connect to NC Node " $node
        return
    }
    
    Write-Host "Collecting Diagnostics data from NC Node " $node
    
    $sys = GetSystemDrive $psSession
        
    $path = "\\$node\" + $sys.Replace(":","$")

    if($Global:Credential -ne $null)
    {
        New-PSDrive -Name S -PSProvider filesystem -Root $path -Credential $Global:Credential
    }
    else
    { 
        New-PSDrive -Name S -PSProvider filesystem -Root $path
    }
    
    md $DestinationPath -ErrorAction SilentlyContinue

    Invoke-Command -Session $psSession -ArgumentList $includeTraces, $sys -ScriptBlock{ 
        param ($includeTraces, $sys)

        function GetSLBConfigState
        {
            param($NCIP)

            cd $sys\Windows\NetworkController\SDNCTLR
                        
            $LogPath = "$sys\NCDiagnostics\SlbConfigState.txt"
            "SLBM Config State" > $LogPath

            try
            {
                unregister-event *
                . .\slbclientWin.ps1
            }
            catch
            {
                $_ >> $LogPath
            }
            
            $slbclient = New-Object Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbClient
            
            $connectionPoint = new-object System.Net.IPEndPoint([ipaddress]::parse($NCIP), 8550)
            $Global:slbmConnection = $slbclient.ConnectToSlbManager($connectionPoint, $null, $null) 

            try
            {
                $slbmVip = slb-GetSlbmVips
                $slbmVip >> $LogPath

                $MuxInfo = slb-GetMuxStateDriverInfo
                $MuxInfo >> $LogPath
            }
            catch
            {
                $_ >> $LogPath
            }

            try
            {
                $hostInfo = slb-GetConnectedHosts
                $hostInfo >> $LogPath
            }
            catch
            {
                $_ >> $LogPath
            }

            try
            {
                $RouterInfo = slb-GetRouterConfiguration
                $RouterInfo >> $LogPath

                $muxRoutes = slb-GetMuxAdvertisedRoutes -DisplayAsTable
                $muxRoutes >> $LogPath
            }
            catch
            {
                $_ >> $LogPath
            }

            try
            {
                $vips = slb-GetAllVipsGS
                $vips | fl * >> $LogPath

                $vipRange = slb-GetVipRanges
                $vipRange >> $LogPath

                foreach($key in $vips.keys)
                {
                    $Vip = $key.IPAddressToString
                    "Vip is :$Vip" >> $LogPath
    
                    try
                    {
                        $VipState = slb-GetVipState -vip:$Vip -detail | fl
                        $VipState >> $LogPath
                    }
                    catch
                    {
                        $_ >> $LogPath
                    }
                }
            }
            catch
            {
                $_ >> $LogPath
            }
        }

        function IsReplicaLocal ([string]$ReplicaName)
        {
            [IpAddress]$parsedIp = $null
            if ([IpAddress]::TryParse($ReplicaName, [ref]$parsedIp)) 
            {
                $localIps = @(Get-NetIPAddress)
        
                foreach ($entry in $localIps) 
                {
                    $addr = [IpAddress]::Parse($entry.IPAddress)
                    if ($addr.Equals($parsedIp)) 
                    {
                        return $true
                    }
                }
            } 
            else 
            {
                if (($ReplicaName -ieq [Net.Dns]::GetHostName()) -or ($ReplicaName -ieq "localhost")) 
                {
                    return $true
                }
            }
    
            return $false
        }

        if($includeTraces -eq $true)
        {
            try
            {
                # Reset Logman
                logman stop NetworkControllerTrace
                logman start NetworkControllerTrace
            }
            catch
            {
                # do nothing
            }
        }

        md $sys\NCDiagnostics -ErrorAction SilentlyContinue

        ipmo WindowsFabric; 
        $clus = Connect-WindowsFabricCluster;
        $manifest =  Get-WindowsFabricClusterManifest ;
        $manifest > "$sys\NCDiagnostics\Manifest.xml" 
        $services = Get-WindowsFabricApplication fabric:/NetworkController | Get-WindowsFabricService
        
        "Service Replica state" > "$sys\NCDiagnostics\ServiceReplicas.txt" 

        foreach ($service in $services) 
        {
            $replicas = Get-WindowsFabricPartition $service.ServiceName | Get-WindowsFabricReplica    
            $replica = $replicas | where {$_.ReplicaRole -eq "Primary"}
            $service.ServiceName >> "$sys\NCDiagnostics\ServiceReplicas.txt" 
            $replica | Select-Object ReplicaRole,NodeName,ReplicaStatus | fl >> "$sys\NCDiagnostics\ServiceReplicas.txt" 

            # check if SLB service is primary
            if($service.ServiceName -eq "fabric:/NetworkController/SlbManagerService")
            {
                $replicaIP = $replica.ReplicaAddress.Split(':')[0]
                $isLocal = IsReplicaLocal $replicaIP 
                if($isLocal -eq $true)
                {
                    GetSLBConfigState $replicaIP
                }
            }
        }
    }
    
    Copy-Item  -Path "S:\NCDiagnostics" -Destination $Global:OutputDirectory -Recurse -ErrorAction SilentlyContinue
    Copy-Item  -Path "S:\SDNDiagnostics" -Destination $Global:OutputDirectory -Recurse -ErrorAction SilentlyContinue

    if($includeTraces -eq $true)
    {
        Copy-Item  -Path "S:\Windows\tracing" -Destination $DestinationPath -Recurse -ErrorAction SilentlyContinue
        Copy-Item  -Path "S:\ProgramData\Service Fabric\Log\ApplicationCrashDumps" -Destination "$DestinationPath\ApplicationCrashDumps" -Recurse -ErrorAction SilentlyContinue
        Copy-Item  -Path "S:\ProgramData\Service Fabric\Log\CrashDumps" -Destination "$DestinationPath\CrashDumps" -Recurse -ErrorAction SilentlyContinue
    }
    
    RemovePSDrive
    RemovePSSession $psSession
}

function CollectDiagnosticsDataFromNC
{
    param($nodes, $includeTraces)
    Write-Host "Collecting Diagnostics data from NC Nodes"
    
    CollectNetworkControllerState $global:NCURL
    
    foreach($node in $nodes)
    {
        $DestinationPath = [System.IO.Path]::Combine($Global:OutputDirectory, "NCNode-$node")
        CollectDiagnosticsDataFromNCNode $node $DestinationPath $includeTraces
    }
    
    $RestDestinationPath = [System.IO.Path]::Combine($Global:OutputDirectory, "NCDiagnostics")
    CollectRESTDataFromNC $global:NCURL $RestDestinationPath
}

function StartLogmanGateway
{
    param($gateway)
    $psSession = GetPSSession $gateway
    if($psSession -eq $null)
    {
        Write-Host "Cannot connect to Gateway " $gateway
        return
    }

    Write-Host "Enabling Logging on Gateway " $gateway

    Invoke-Command -Session $psSession -ScriptBlock{
        $flags=0x0
    
        #Critical = 1, Error = 2, Warning = 3, Information = 4, Verbose = 5
        $level=3

        $guids = (pwd).path+"\guids.txt"

        # BGPProvider
        Out-File -InputObject "{EB171376-3B90-4169-BD76-2FB821C4F6FB} $flags $level" -FilePath $guids -Encoding ascii
        # RRASProvider
        Out-File -InputObject "{24989972-0967-4E21-A926-93854033638E} $flags $level" -FilePath $guids -Append -Encoding ascii
        # GwmHealthMonitorProvider
        Out-File -InputObject "{F3F35A3B-6D33-4C32-BC81-21513D8BD708} $flags $level" -FilePath $guids -Append -Encoding ascii
        
        $sys = (Get-WMIObject -class Win32_OperatingSystem | select-object SystemDrive).SystemDrive

        try { logman stop GatewayTrace } catch {}
        try { logman delete GatewayTrace } catch {}
        logman create trace GatewayTrace -pf $guids -bs 10000 -f bincirc -Max 100 --v -ow -o $sys\windows\Tracing\GatewayTrace
        logman start GatewayTrace
    }
    RemovePSSession $psSession
}

function StartLogmanHostAgent
{
    param($server)
    $psSession = GetPSSession $server
    if($psSession -eq $null)
    {
        Write-Host "Cannot connect to Server " $server
        return
    }

    Write-Host "Enabling Logging on Host " $server

    Invoke-Command -Session $psSession -ScriptBlock{
        $flags=0x0
    
        #Critical = 1, Error = 2, Warning = 3, Information = 4, Verbose = 5
        $level=3

        $guids = (pwd).path+"\guids.txt"

        # HostAgentProvider
        Out-File -InputObject "{28F7FB0F-EAB3-4960-9693-9289CA768DEA} $flags $level" -FilePath $guids -Encoding ascii
        # HostAgentVNetPluginProvider
        Out-File -InputObject "{A6527853-5B2B-46E5-9D77-A4486E012E73} $flags $level" -FilePath $guids -Append -Encoding ascii
        
        $sys = (Get-WMIObject -class Win32_OperatingSystem | select-object SystemDrive).SystemDrive

        try { logman stop HostAgentTrace } catch {}
        try { logman delete HostAgentTrace } catch {}
        logman create trace HostAgentTrace -pf $guids -bs 10000 -f bincirc -Max 100 --v -ow -o $sys\windows\Tracing\HostAgentTrace
        logman start HostAgentTrace
    }
    RemovePSSession $psSession
}

function StartLogmanNC
{
    param($node)
    $psSession = GetPSSession $node
    if($psSession -eq $null)
    {
        Write-Host "Cannot connect to NC Node " $node
        return
    }

    Write-Host "Enabling Logging on NC Node " $node

    Invoke-Command -Session $psSession -ScriptBlock{
        $flags=0x0
    
        #Critical = 1, Error = 2, Warning = 3, Information = 4, Verbose = 5
        $level=3

        $guids = (pwd).path+"\guids.txt"

        # FrameworkProvider
        Out-File -InputObject "{80355850-c8ed-4336-ade2-6595f9ca821d} $flags $level" -FilePath $guids -Encoding ascii
        # SlbManagerServiceProvider
        Out-File -InputObject "{d304a717-2718-4580-a155-458f8ac12091} $flags $level" -FilePath $guids -Append -Encoding ascii
        # TopologyServiceProvider
        Out-File -InputObject "{90399F0C-AE84-49AF-B46A-19079B77B6B8} $flags $level" -FilePath $guids -Append -Encoding ascii
        # SlbMuxServiceProvider
        Out-File -InputObject "{6c2350f8-f827-4b74-ad0c-714a92e22576} $flags $level" -FilePath $guids -Append -Encoding ascii
        # FirewallServiceProvider
        Out-File -InputObject "{ea2e4e95-2b14-462d-bb78-dee94170804f} $flags $level" -FilePath $guids -Append -Encoding ascii
        # SDNMonServiceProvider
        Out-File -InputObject "{d79293d5-78ba-4687-8cef-4492f1e3abf9} $flags $level" -FilePath $guids -Append -Encoding ascii
        # SDNFNMServiceProvider
        Out-File -InputObject "{77494040-1F07-499D-8553-03DB545C031C} $flags $level" -FilePath $guids -Append -Encoding ascii
        # VSwitchServiceProvider
        Out-File -InputObject "{5C8E3932-E6DF-403D-A3A3-EC6BF6D7977D} $flags $level" -FilePath $guids -Append -Encoding ascii
        # ApiServiceProvider
        Out-File -InputObject "{A1EA8728-5700-499E-8FDD-64954D8D3578} $flags $level" -FilePath $guids -Append -Encoding ascii
        # GatewayManagerProvider
        Out-File -InputObject "{8B0C6DD7-B6D8-48C2-B83E-AFCBBA5B57E8} $flags $level" -FilePath $guids -Append -Encoding ascii
        # ServiceInsertionProvider
        Out-File -InputObject "{C755849B-CF02-4F21-B82B-D92D26A91069} $flags $level" -FilePath $guids -Append -Encoding ascii
        # HelperServiceProvider
        Out-File -InputObject "{f1107188-2054-4758-8a89-8fe5c661590f} $flags $level" -FilePath $guids -Append -Encoding ascii
        # DeploymentProvider
        Out-File -InputObject "{93e14ac2-289b-45b7-b654-db51e293bf52} $flags $level" -FilePath $guids -Append -Encoding ascii
        
        $sys = (Get-WMIObject -class Win32_OperatingSystem | select-object SystemDrive).SystemDrive

        try { logman stop NetworkControllerTrace } catch {}
        try { logman delete NetworkControllerTrace } catch {}
        logman create trace NetworkControllerTrace -pf $guids -bs 10000 -f bincirc -Max 1000 --v -ow -o $sys\windows\Tracing\NetworkControllerTrace
        logman start NetworkControllerTrace
    }
    RemovePSSession $psSession
}

function SetupDiagnosticsDataForGateways
{
    param($gateways)
    Write-Host "Enabling Logging on Gateways"
    foreach($gateway in $gateways)
    {
        StartLogmanGateway $gateway
    }
}

function SetupDiagnosticsDataForServers
{
    param($Servers)
    Write-Host "Enabling Logging on Servers"
    foreach($Server in $Servers)
    {
        StartLogmanHostAgent $Server
    }
}

function SetupDiagnosticsDataForNC
{
    param($nodes)
    Write-Host "Enabling Logging on NC Nodes"
    foreach($node in $nodes)
    {
        StartLogmanNC $node
    }
}

#endregion

#region Execution begins here

# Set up eventing

try { Stop-Transcript -ErrorAction Ignore | Out-Null } catch {}

$logfile = $global:OutputDirectory + "\NCDiagnostics.log"
Start-Transcript -Path $logFile -Append -ErrorAction Ignore

$Global:Credential = $Credential
$Global:CertificateThumbprint = $CertificateThumbprint
$Global:RestURI = $RestURI
$Global:ToolsDirectory = $ToolsDirectory
$Global:OutputDirectory = $OutputDirectory

#region Get NC Properties
# Connect to the NC machine and gather deployment info
$psSession = GetPSSession $NetworkController
if($psSession -eq $null)
{
    Write-Host "Cannot connect to Network Controller " $NetworkController
    return
}

$NCInfo = Invoke-Command -Session $psSession -ScriptBlock {
    Import-Module NetworkController -Force -ErrorAction SilentlyContinue
    $Details = Get-NetworkController
    $Nodes = Get-NetworkControllerNode | Select-Object Server -ExpandProperty Server
    [pscustomobject]@{Nodes=$Nodes;Details=$Details}
    
}
RemovePSSession $psSession

# get the client certificate thumbprint which is present on the machine
$Global:clientCert = $null
$Global:NCURL = $null
if(($NCInfo.Details.ClientCertificateThumbprint -ne $null) -and ($NCInfo.Details.ClientCertificateThumbprint.Count -gt 0))
{
	$machineCerts = Get-ChildItem Cert:\CurrentUser\My
    if(($machineCerts -ne $null) -and ($machineCerts.Count -gt 0))
    {
	    foreach($cert in $NCInfo.Details.ClientCertificateThumbprint)
	    {
		    if($machineCerts.Where{$_.ThumbPrint -eq $cert}.Count -gt 0)
		    {
			    $clientCert = $cert
			    break
		    }
	    }	
    }

	if($clientCert -eq $null)
	{
		$str = "Client authentication certificate not found for current user." + [Environment]::UserName
		Write-Host $str
		return
	}
}

$global:NCURL = $null

if($global:RestURI -eq $null -or $global:RestURI -eq "")
{
    # get the floating IP
    $floatingIP = @()
    $RestIPAddress = $NCInfo.Details.RestIPAddress
						
    if(($RestIPAddress -eq $null) -or ($RestIPAddress -eq ""))
    {
	    # case of a single machine NC deployment

	    # get the ip of the machine to create the URL
	    $ips = Resolve-DnsName -Name $NetworkController -ErrorAction SilentlyContinue -Type A
	    if(($ips -eq $null) -or ($ips.Count -eq 0))
	    {
		    $str = "Machine cannot be reached. " + $NetworkController
		    Write-Host $str
		    return $false
	    }
        
        if($ips.Count -gt 1)
	    {
            $floatingIP = @($ips.Where{$_.IPAddress -ne $null -and $_.IPAddress -ne ""}.ForEach{$_.IPAddress})
	    }
        else
        {
            $floatingIP = @($NetworkController)
        }
    }
    else
    {
	    $splits = $RestIPAddress.Split('/') # the ip is of the form ip/networkaddress
	    if (($splits -ne $null) -and ($splits.Count -gt 1))
	    {
		    $floatingIP = @($splits[0])
	    }
    }

    if(($NCInfo.Details.ServerCertificate -ne $null) -and ($NCInfo.Details.ServerCertificate.DnsNameList -ne $null) -and ($NCInfo.Details.ServerCertificate.DnsNameList.Count -gt 0))
    {
	    # in case of SSL certificate the URL must be the internationalized common name of the certificate
	    # we need to see which DnsName in this list is valid and resolve to the floating IP
	    $validURLfound = $false
	    foreach($dnsName in $NCInfo.Details.ServerCertificate.DnsNameList)
	    {
		    $ips = Resolve-DnsName -Name $dnsName.Punycode -ErrorAction SilentlyContinue
		    if(($ips -ne $null) -and ($ips.Count -gt 0) -and ($ips.Where{$floatingIP.Contains($_.IPAddress)}.Count -gt 0))
		    {
			    $Global:NCURL = "https://" + $dnsName.Punycode	
			    $validURLfound = $true
			    break
		    }
	    }
					
	    if($validURLfound -eq $false)
	    {
		    $str = "Failed to discover Connection URI for Network Controller on computer " + $NetworkController + " Use RestURI parameter."
		    Write-Host $str
		    return $false
	    }
    }
    else
    {
	    $Global:NCURL = "http://" + $floatingIP[0]
    }
}
else
{
	if($RestURI.StartsWith("http"))
	{
		$Global:NCURL = $RestURI	
	}
	else
	{					
		$str = "Connection URI entered is invalid. " + $global:RestURI
		Write-Host $str
		return
	}
}

# get hosts connected to NC.
$hosts = GetRESTOutput "$Global:NCURL/networking/v1/servers"
$hosts = GetAllManagementIPs $hosts

# get gateways connected to NC.
$gateways = GetRESTOutput "$Global:NCURL/networking/v1/Gateways"
$gateways = GetAllManagementIPs $gateways

#endregion

RemovePSDrive

if($SetupDiagnostics -eq $true)
{
    # Setup Diagnostics data on all NC nodes
    SetupDiagnosticsDataForNC $NCInfo.Nodes
    
    # Setup Diagnostics data on all hosts
    SetupDiagnosticsDataForServers $hosts

    # Setup Diagnostics data on all Gateways
    SetupDiagnosticsDataForGateways $gateways
}
else
{
    # Get Diagnostics data from all NC nodes
    CollectDiagnosticsDataFromNC $NCInfo.Nodes $IncludeTraces

    # Get Diagnostics data from all hosts
    CollectDiagnosticsDataFromServers $hosts $IncludeTraces

    # Get Diagnostics data from all Gateways
    CollectDiagnosticsDataFromGateways $gateways
}

Stop-Transcript
Exit 0
#endregion