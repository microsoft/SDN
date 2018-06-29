Param(
    $NetworkName = "cbr0",
    $HostnameOverride = $(hostname),
    $ClusterCIDR = "192.168.0.0/16"
)

$env:KUBE_NETWORK=$NetworkName.ToLower()
ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList

c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$HostnameOverride --kubeconfig=c:\k\config --cluster-cidr=$ClusterCIDR
