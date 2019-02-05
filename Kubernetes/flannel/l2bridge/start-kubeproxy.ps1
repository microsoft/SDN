Param(
    [parameter(Mandatory = $false)] $LogDir = "C:\k",    
    $NetworkName = "cbr0"
)

$networkName = $NetworkName.ToLower()
ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList

c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --feature-gates="WinDSR=false" --hostname-override=$(hostname) --kubeconfig=c:\k\config --network=$networkName --enable-dsr=false --log-dir=$LogDir --logtostderr=false