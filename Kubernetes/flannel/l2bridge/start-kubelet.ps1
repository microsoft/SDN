Param(
    [parameter(Mandatory = $false)] $clusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $serviceCIDR="10.96.0.0/12",
    [parameter(Mandatory = $false)] $KubeDnsSuffix="svc.cluster.local",
    [parameter(Mandatory = $false)] $InterfaceName="Ethernet",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    $NetworkName = "cbr0",
    [switch] $RegisterOnly
)

# Todo : Get these values using kubectl
$WorkingDir = "c:\k"
$CNIPath = [Io.path]::Combine($WorkingDir , "cni")
$CNIConfig = [Io.path]::Combine($CNIPath, "config", "cni.conf")

$endpointName = "cbr0"
$vnicName = "v$InterfaceName ($endpointName)"

ipmo $WorkingDir\helper.psm1

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
    $configJson.name = $NetworkName
    $configJson.delegate.type = "win-bridge"
    $configJson.delegate.dns.Nameservers[0] = $KubeDnsServiceIP
    $configJson.delegate.dns.Search[0] = $KubeDnsSuffix

    $configJson.delegate.policies[0].Value.ExceptionList[0] = $clusterCIDR
    $configJson.delegate.policies[0].Value.ExceptionList[1] = $serviceCIDR
    $configJson.delegate.policies[0].Value.ExceptionList[2] = Get-MgmtSubnet($InterfaceName)

    $configJson.delegate.policies[1].Value.DestinationPrefix  = $serviceCIDR
    $mgmtSubnet = Get-MgmtIpAddress($InterfaceName)
    $configJson.delegate.policies[2].Value.DestinationPrefix  = ((Get-MgmtIpAddress($InterfaceName)) + "/32")
  
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

  c:\k\kubelet.exe --hostname-override=$(hostname) --v=6 `
      --pod-infra-container-image=kubeletwin/pause --resolv-conf="" `
      --allow-privileged=true --enable-debugging-handlers `
      --cluster-dns=$KubeDnsServiceIp --cluster-domain=cluster.local `
      --kubeconfig=c:\k\config --hairpin-mode=promiscuous-bridge `
      --image-pull-progress-deadline=20m --cgroups-per-qos=false `
      --log-dir=$LogDir --logtostderr=false --enforce-node-allocatable="" `
      --network-plugin=cni --cni-bin-dir="c:\k\cni" --cni-conf-dir "c:\k\cni\config"
