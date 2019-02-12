Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,
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

ipmo $WorkingDir\helper.psm1

if ($RegisterOnly.IsPresent)
{
    RegisterNode
    exit
}

Update-CNIConfig $CNIConfig $clusterCIDR $KubeDnsServiceIP $serviceCIDR $KubeDnsSuffix $InterfaceName $NetworkName $NetworkMode

  c:\k\kubelet.exe --hostname-override=$(hostname) --v=6 `
      --pod-infra-container-image=kubeletwin/pause --resolv-conf="" `
      --allow-privileged=true --enable-debugging-handlers `
      --cluster-dns=$KubeDnsServiceIp --cluster-domain=cluster.local `
      --kubeconfig=c:\k\config --hairpin-mode=promiscuous-bridge `
      --image-pull-progress-deadline=20m --cgroups-per-qos=false `
      --log-dir=$LogDir --logtostderr=false --enforce-node-allocatable="" `
      --network-plugin=cni --cni-bin-dir="c:\k\cni" --cni-conf-dir "c:\k\cni\config"
