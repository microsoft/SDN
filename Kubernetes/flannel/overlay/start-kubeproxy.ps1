Param(
    $NetworkName = "vxlan0",
    $ManagementIP

)

$env:KUBE_NETWORK=$NetworkName.ToLower()

$sourceVipJSON = Get-Content sourceVip.json | ConvertFrom-Json 
$env:SOURCE_VIP= $sourceVipJSON.ip4.ip.Split("/")[0]

$env:HOST_MAC=(Get-NetAdapter -InterfaceAlias (Get-NetIPAddress -IPAddress $ManagementIP).InterfaceAlias).MacAddress

ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList
c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$(hostname) --kubeconfig=c:\k\config
