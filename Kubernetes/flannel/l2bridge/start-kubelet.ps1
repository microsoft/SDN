Param(
    [parameter(Mandatory = $false)] $clusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $serviceCIDR="10.96.0.0/12",
    [parameter(Mandatory = $false)] $KubeDnsSuffix="svc.cluster.local",
    [parameter(Mandatory = $false)] $InterfaceName="Ethernet",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    [parameter(Mandatory = $false)] $KubeletFeatureGates = "",
    [ValidateSet("process", "hyperv")] $IsolationType="process",
    $NetworkName = "cbr0",
    [switch] $RegisterOnly
)

$NetworkMode = "L2Bridge"
# Todo : Get these values using kubectl

$WorkingDir = "c:\k"
$CNIPath = [Io.path]::Combine($WorkingDir , "cni")
$CNIConfig = [Io.path]::Combine($CNIPath, "config", "cni.conf")

$endpointName = "cbr0"
$vnicName = "v$InterfaceName ($endpointName)"

function
IsNodeRegistered()
{
    c:\k\kubectl.exe --kubeconfig=c:\k\config get nodes/$($(hostname).ToLower())
    return (!$LASTEXITCODE)
}

function
RegisterNode()
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
}

function
Get-MgmtIpAddress()
{
    return (Get-HnsNetwork | ? Name -EQ $NetworkName.ToLower()).ManagementIP
}

function
ConvertTo-DecimalIP
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

function
ConvertTo-DottedDecimalIP
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

function
ConvertTo-MaskLength
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

function
Get-MgmtSubnet
{
    $na = Get-NetAdapter | ? Name -Like "v$InterfaceName (Ethernet*"
    if (!$na) {
      throw "Failed to find a suitable network adapter, check your network settings."
    }
    $addr = (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4).IPAddress
    $mask = (Get-WmiObject Win32_NetworkAdapterConfiguration | ? InterfaceIndex -eq $($na.ifIndex)).IPSubnet[0]
    $mgmtSubnet = (ConvertTo-DecimalIP $addr) -band (ConvertTo-DecimalIP $mask)
    $mgmtSubnet = ConvertTo-DottedDecimalIP $mgmtSubnet
    return "$mgmtSubnet/$(ConvertTo-MaskLength $mask)"
}

function
Update-CNIConfig($podCIDR)
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
    $configJson.name = "cbr0"
    $configJson.delegate.type = "win-bridge"
    $configJson.delegate.dns.Nameservers[0] = $KubeDnsServiceIP
    $configJson.delegate.dns.Search[0] = $KubeDnsSuffix

    $configJson.delegate.policies[0].Value.ExceptionList[0] = $clusterCIDR
    $configJson.delegate.policies[0].Value.ExceptionList[1] = $serviceCIDR
    $configJson.delegate.policies[0].Value.ExceptionList[2] = Get-MgmtSubnet

    $configJson.delegate.policies[1].Value.DestinationPrefix  = $serviceCIDR
    $configJson.delegate.policies[2].Value.DestinationPrefix  = "$(Get-MgmtIpAddress)/32"

    if (Test-Path $CNIConfig) {
        Clear-Content -Path $CNIConfig
    }

    Write-Host "Generated CNI Config [$configJson]"

    Add-Content -Path $CNIConfig -Value (ConvertTo-Json $configJson -Depth 20)
}

if ($RegisterOnly.IsPresent)
{
    RegisterNode
    exit
}

Update-CNIConfig $podCIDR

$kubeletArgs = @(
    "--hostname-override=$(hostname)"
    '--v=6'
    '--pod-infra-container-image=kubeletwin/pause'
    '--resolv-conf=""'
    "--cluster-dns=$KubeDnsServiceIp"
    '--cluster-domain=cluster.local'
    '--kubeconfig=c:\k\config'
    '--hairpin-mode=promiscuous-bridge'
    '--image-pull-progress-deadline=20m'
    '--cgroups-per-qos=false'
    "--log-dir=$LogDir"
    '--logtostderr=false'
    '--enforce-node-allocatable=""'
    '--network-plugin=cni'
    '--cni-bin-dir="c:\k\cni"'
    '--cni-conf-dir="c:\k\cni\config"'
    "--node-ip=$(Get-MgmtIpAddress)"
)

$featureGates = $KubeletFeatureGates

if ($IsolationType -ieq "hyperv")
{
  if ($featureGates -ne "") {
    $featureGates += ","
  }
  $featureGates += "HyperVContainer=true"
}

if ($featureGates -ne "") {
  $kubeletArgs += "--feature-gates=$featureGates"
}

& c:\k\kubelet.exe $kubeletArgs
