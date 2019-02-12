function DownloadFile()
{
    param(
    [parameter(Mandatory = $true)] $Url,
    [parameter(Mandatory = $true)] $Destination
    )

    if (Test-Path $Destination)
    {
        Write-Host "File $Destination already exists."
        return
    }

    $secureProtocols = @() 
    $insecureProtocols = @([System.Net.SecurityProtocolType]::SystemDefault, [System.Net.SecurityProtocolType]::Ssl3) 
    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType])) 
    { 
        if ($insecureProtocols -notcontains $protocol) 
        { 
            $secureProtocols += $protocol 
        } 
    } 
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols
    
    try {
        (New-Object System.Net.WebClient).DownloadFile($Url,$Destination)
        Write-Host "Downloaded $Url=>$Destination"
    } catch {
        Write-Error "Failed to download $Url"
	    throw
    }
}

function CleanupOldNetwork($NetworkName)
{
    $hnsNetwork = Get-HnsNetwork | ? Name -EQ $NetworkName.ToLower()

    if ($hnsNetwork)
    {
        # Cleanup all containers
        docker ps -q | foreach {docker rm $_ -f} 

        Write-Host "Cleaning up old HNS network found"
        Write-Host ($hnsNetwork | ConvertTo-Json -Depth 10) 
        Remove-HnsNetwork $hnsNetwork
    }
}

function WaitForNetwork($NetworkName)
{
    # Wait till the network is available
    while( !(Get-HnsNetwork -Verbose | ? Name -EQ $NetworkName.ToLower()) )
    {
        Write-Host "Waiting for the Network to be created"
        Start-Sleep 1
    }
}


function IsNodeRegistered()
{
    c:\k\kubectl.exe --kubeconfig=c:\k\config get nodes/$($(hostname).ToLower())
    return (!$LASTEXITCODE)
}

function RegisterNode()
{
    if (!(IsNodeRegistered))
    {
        $argList = @("--hostname-override=$(hostname)","--pod-infra-container-image=kubeletwin/pause","--resolv-conf=""""", "--cgroups-per-qos=false", "--enforce-node-allocatable=""""","--kubeconfig=c:\k\config")
        $process = Start-Process -FilePath c:\k\kubelet.exe -PassThru -ArgumentList $argList

        # Wait till the 
        while (!(IsNodeRegistered))
        {
            Write-Host "waiting to discover node registration status"
            Start-Sleep -sec 1
        }

        $process | Stop-Process | Out-Null
    }
    else 
    {
        Write-Host "Node $(hostname) already registered"
    }
}

function StartFlanneld($ipaddress, $NetworkName)
{
    CleanupOldNetwork $NetworkName

    # Start FlannelD, which would recreate the network.
    # Expect disruption in node connectivity for few seconds
    pushd 
    cd C:\flannel\
    [Environment]::SetEnvironmentVariable("NODE_NAME", (hostname).ToLower())
    start C:\flannel\flanneld.exe -ArgumentList "--kubeconfig-file=C:\k\config --iface=$ipaddress --ip-masq=1 --kube-subnet-mgr=1" -NoNewWindow
    popd

    WaitForNetwork $NetworkName
}

function GetSourceVip($ipaddress, $NetworkName)
{
    $hnsNetwork = Get-HnsNetwork | ? Name -EQ $NetworkName.ToLower()
    $subnet = $hnsNetwork.Subnets[0].AddressPrefix

    $ipamConfig = @"
        {"cniVersion": "0.2.0", "name": "vxlan0", "ipam":{"type":"host-local","ranges":[[{"subnet":"$subnet"}]],"dataDir":"/var/lib/cni/networks"}}
"@

    $ipamConfig | Out-File "C:\k\sourceVipRequest.json"

    $env:CNI_COMMAND="ADD"
    $env:CNI_CONTAINERID="dummy"
    $env:CNI_NETNS="dummy"
    $env:CNI_IFNAME="dummy"
    $env:CNI_PATH="c:\k\cni" #path to host-local.exe

    If(!(Test-Path c:/k/sourceVip.json)){
        Get-Content sourceVipRequest.json | .\cni\host-local.exe | Out-File sourceVip.json
    }

    Remove-Item env:CNI_COMMAND
    Remove-Item env:CNI_CONTAINERID
    Remove-Item env:CNI_NETNS
    Remove-Item env:CNI_IFNAME
    Remove-Item env:CNI_PATH
}

function Get-PodCIDR()
{
    return c:\k\kubectl.exe --kubeconfig=c:\k\config get nodes/$($(hostname).ToLower()) -o custom-columns=podCidr:.spec.podCIDR --no-headers
}

function Get-PodCIDRs()
{
    return c:\k\kubectl.exe  --kubeconfig=c:\k\config get nodes -o=custom-columns=Name:.status.nodeInfo.operatingSystem,PODCidr:.spec.podCIDR --no-headers
}

function Get-PodGateway($podCIDR)
{
    # Current limitation of Platform to not use .1 ip, since it is reserved
    return $podCIDR.substring(0,$podCIDR.lastIndexOf(".")) + ".1"
}

function Get-PodEndpointGateway($podCIDR)
{
    # Current limitation of Platform to not use .1 ip, since it is reserved
    return $podCIDR.substring(0,$podCIDR.lastIndexOf(".")) + ".2"
}

function Get-MgmtIpAddress()
{
    Param (
        [Parameter(Mandatory=$false)] [String] $InterfaceName = "Ethernet"
    )
    $na = Get-NetAdapter | ? Name -Like "vEthernet ($InterfaceName*" | ? Status -EQ Up
    return (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4).IPAddress
}

function ConvertTo-DecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Net.IPAddress] $IPAddress
  )
  $i = 3; $DecimalIP = 0;
  $IPAddress.GetAddressBytes() | % {
    $DecimalIP += $_ * [Math]::Pow(256, $i); $i--
  }

  return [UInt32]$DecimalIP
}

function ConvertTo-DottedDecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Uint32] $IPAddress
  )

    $DottedIP = $(for ($i = 3; $i -gt -1; $i--)
    {
      $Remainder = $IPAddress % [Math]::Pow(256, $i)
      ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
      $IPAddress = $Remainder
    })

    return [String]::Join(".", $DottedIP)
}

function ConvertTo-MaskLength
{
  param(
    [Parameter(Mandatory = $True, Position = 0)]
    [Net.IPAddress] $SubnetMask
  )
    $Bits = "$($SubnetMask.GetAddressBytes() | % {
      [Convert]::ToString($_, 2)
    } )" -replace "[\s0]"
    return $Bits.Length
}


function Get-MgmtSubnet
{
    Param (
        [Parameter(Mandatory=$false)] [String] $InterfaceName = "Ethernet"
    )
    $na = Get-NetAdapter | ? Name -Like "vEthernet ($InterfaceName*" | ? Status -EQ Up

    if (!$na) {
      throw "Failed to find a suitable network adapter, check your network settings."
    }
    $addr = (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4).IPAddress
    $mask = (Get-WmiObject Win32_NetworkAdapterConfiguration | ? InterfaceIndex -eq $($na.ifIndex)).IPSubnet[0]
    $mgmtSubnet = (ConvertTo-DecimalIP $addr) -band (ConvertTo-DecimalIP $mask)
    $mgmtSubnet = ConvertTo-DottedDecimalIP $mgmtSubnet
    return "$mgmtSubnet/$(ConvertTo-MaskLength $mask)"
}

function Get-MgmtDefaultGatewayAddress()
{
    Param (
        [Parameter(Mandatory=$false)] [String] $InterfaceName = "Ethernet"
    )
    $na = Get-NetAdapter | ? Name -Like "vEthernet ($InterfaceName*"
    return  (Get-NetRoute -InterfaceAlias $na.ifAlias -DestinationPrefix "0.0.0.0/0").NextHop
}

function CreateDirectory($Path)
{
    if (!(Test-Path $Path))
    {
        md $Path
    }
}

function
Update-CNIConfig
{
    Param(
        $CNIConfig,
        $clusterCIDR,
        $KubeDnsServiceIP,
        $serviceCIDR,
        $KubeDnsSuffix,
        $InterfaceName,
        $NetworkName,
        [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode
    )
    if ($NetworkMode -eq "l2bridge")
    {
        $jsonSampleConfig = '{
            "cniVersion": "0.2.0",
            "name": "<NetworkMode>",
            "type": "flannel",
            "delegate": {
               "type": "win-bridge",
                "dns" : {
                  "Nameservers" : [ "10.96.0.10" ],
                  "Search": [ "svc.cluster.local" ]
                },
                "policies" : [
                  {
                    "Name" : "EndpointPolicy", "Value" : { "Type" : "OutBoundNAT", "ExceptionList": [ "<ClusterCIDR>", "<ServerCIDR>", "<MgmtSubnet>" ] }
                  },
                  {
                    "Name" : "EndpointPolicy", "Value" : { "Type" : "ROUTE", "DestinationPrefix": "<ServerCIDR>", "NeedEncap" : true }
                  },
                  {
                    "Name" : "EndpointPolicy", "Value" : { "Type" : "ROUTE", "DestinationPrefix": "<MgmtIP>/32", "NeedEncap" : true }
                  }
                ]
              }
          }'
              #Add-Content -Path $CNIConfig -Value $jsonSampleConfig
          
              $configJson =  ConvertFrom-Json $jsonSampleConfig
              $configJson.name = $NetworkName
              $configJson.delegate.type = "win-bridge"
              $configJson.delegate.dns.Nameservers[0] = $KubeDnsServiceIP
              $configJson.delegate.dns.Search[0] = $KubeDnsSuffix
          
              $configJson.delegate.policies[0].Value.ExceptionList[0] = $clusterCIDR
              $configJson.delegate.policies[0].Value.ExceptionList[1] = $serviceCIDR
              $configJson.delegate.policies[0].Value.ExceptionList[2] = Get-MgmtSubnet($InterfaceName)
          
              $configJson.delegate.policies[1].Value.DestinationPrefix  = $serviceCIDR
              $configJson.delegate.policies[2].Value.DestinationPrefix  = ((Get-MgmtIpAddress($InterfaceName)) + "/32")
            
    }
    elseif ($NetworkMode -eq "overlay"){
        $jsonSampleConfig = '{
            "cniVersion": "0.2.0",
            "name": "<NetworkMode>",
            "type": "flannel",
            "delegate": {
               "type": "win-overlay",
                "dns" : {
                  "Nameservers" : [ "11.0.0.10" ],
                  "Search": [ "default.svc.cluster.local" ]
                },
                "Policies" : [
                  {
                    "Name" : "EndpointPolicy", "Value" : { "Type" : "OutBoundNAT", "ExceptionList": [ "<ClusterCIDR>", "<ServerCIDR>" ] }
                  },
                  {
                    "Name" : "EndpointPolicy", "Value" : { "Type" : "ROUTE", "DestinationPrefix": "<ServerCIDR>", "NeedEncap" : true }
                  }
                ]
              }
          }'
              #Add-Content -Path $CNIConfig -Value $jsonSampleConfig
          
              $configJson =  ConvertFrom-Json $jsonSampleConfig
              $configJson.name = $NetworkName
              $configJson.type = "flannel"
              $configJson.delegate.type = "win-overlay"
              $configJson.delegate.dns.Nameservers[0] = $KubeDnsServiceIp
              $configJson.delegate.dns.Search[0] = "default.svc.cluster.local" # TODO: $KubeDnsSuffix
          
              $configJson.delegate.Policies[0].Value.ExceptionList[0] = $clusterCIDR
              $configJson.delegate.Policies[0].Value.ExceptionList[1] = $serviceCIDR
          
              $configJson.delegate.Policies[1].Value.DestinationPrefix  = $serviceCIDR
    }
    
    if (Test-Path $CNIConfig) {
        Clear-Content -Path $CNIConfig
    }

    Write-Host "Generated CNI Config [$configJson]"

    Add-Content -Path $CNIConfig -Value (ConvertTo-Json $configJson -Depth 20)
}

Export-ModuleMember DownloadFile
Export-ModuleMember CleanupOldNetwork
Export-ModuleMember IsNodeRegistered
Export-ModuleMember RegisterNode
Export-ModuleMember WaitForNetwork
Export-ModuleMember StartFlanneld
Export-ModuleMember GetSourceVip
Export-ModuleMember Get-MgmtSubnet
Export-ModuleMember Get-MgmtIpAddress
Export-ModuleMember Get-PodCIDR
Export-ModuleMember Get-PodCIDRs
Export-ModuleMember Get-PodEndpointGateway
Export-ModuleMember Get-PodGateway
Export-ModuleMember Get-MgmtDefaultGatewayAddress
Export-ModuleMember CreateDirectory
Export-ModuleMember Update-CNIConfig