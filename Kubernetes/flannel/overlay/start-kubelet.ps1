Param(
    [parameter(Mandatory = $false)] $clusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $serviceCIDR="10.96.0.0/12",
    [parameter(Mandatory = $false)] $KubeDnsSuffix="default.svc.cluster.local",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    $NetworkName = "vxlan0",
    [switch] $RegisterOnly
)

# Todo : Get these values using kubectl
# Needed until win-overlay sets namespaces dynamically
$KubeDnsSuffix ="default.svc.cluster.local"

$WorkingDir = "c:\k"
$CNIPath = [Io.path]::Combine($WorkingDir , "cni")
$CNIConfig = [Io.path]::Combine($CNIPath, "config", "cni.conf")

ipmo $WorkingDir\helper.psm1

function
Update-CNIConfig($podCIDR)
{
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
    $configJson.delegate.dns.Search[0] = $KubeDnsSuffix

    $configJson.delegate.Policies[0].Value.ExceptionList[0] = $clusterCIDR
    $configJson.delegate.Policies[0].Value.ExceptionList[1] = $serviceCIDR

    $configJson.delegate.Policies[1].Value.DestinationPrefix  = $serviceCIDR

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
