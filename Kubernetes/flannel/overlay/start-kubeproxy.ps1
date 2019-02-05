Param(
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    $NetworkName = "vxlan0",
)
$networkName = $NetworkName.ToLower()

If((Test-Path c:/k/sourceVip.json)) {
    $sourceVipJSON = Get-Content sourceVip.json | ConvertFrom-Json 
    $sourceVip = $sourceVipJSON.ip4.ip.Split("/")[0]
}

ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList
c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --feature-gates="WinOverlay=true,WinDSR=false" --hostname-override=$(hostname) --kubeconfig=c:\k\config --network-name=$networkName --source-vip=$sourceVip --enable-dsr=false --log-dir=$LogDir --logtostderr=false