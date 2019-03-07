Param(
    [parameter(Mandatory = $false)] $LogDir = "C:\k",    
    $NetworkName = "cbr0"
)

$networkName = $NetworkName.ToLower()
ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList

$env:KUBE_NETWORK=$networkName
c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$(hostname) --kubeconfig=c:\k\config --log-dir=$LogDir --logtostderr=false
