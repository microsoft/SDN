Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,
    [parameter(Mandatory = $true)] $NetworkName,  
    [parameter(Mandatory = $false)] $clusterCIDR="10.244.0.0/16",  
    [parameter(Mandatory = $false)] $LogDir = "C:\k"
)

$networkName = $NetworkName.ToLower()
$networkMode = $NetworkMode.ToLower()

ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList

if ($NetworkMode -eq "l2bridge")
{
    $env:KUBE_NETWORK=$networkName
    c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$(hostname) --kubeconfig=c:\k\config --cluster-cidr=$clusterCIDR --log-dir=$LogDir --logtostderr=false
}
elseif ($NetworkMode -eq "overlay")
{
    if((Test-Path c:/k/sourceVip.json)) 
    {
        $sourceVipJSON = Get-Content sourceVip.json | ConvertFrom-Json 
        $sourceVip = $sourceVipJSON.ip4.ip.Split("/")[0]
    }
    # Needs Kubernetes v1.14 or above.
    c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --feature-gates="WinOverlay=true" --hostname-override=$(hostname) --kubeconfig=c:\k\config --network-name=$networkName --source-vip=$sourceVip --enable-dsr=false --cluster-cidr=$clusterCIDR --log-dir=$LogDir --logtostderr=false
}