Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,    
    [parameter(Mandatory = $false)] $LogDir = "C:\k",    
    $NetworkName = "cbr0"
)

$networkName = $NetworkName.ToLower()
ipmo c:\k\hns.psm1
Get-HnsPolicyList | Remove-HnsPolicyList

if ($NetworkMode -eq "l2bridge")
{
    c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$(hostname) --kubeconfig=c:\k\config --network=$networkName --enable-dsr=false --log-dir=$LogDir --logtostderr=false
}
elseif ($NetworkMode -eq "overlay"){
    if((Test-Path c:/k/sourceVip.json)) {
        $sourceVipJSON = Get-Content sourceVip.json | ConvertFrom-Json 
        $sourceVip = $sourceVipJSON.ip4.ip.Split("/")[0]
    }
    # Needs Kubernetes v1.14 or above.
    c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --feature-gates="WinOverlay=true" --hostname-override=$(hostname) --kubeconfig=c:\k\config --network-name=$networkName --source-vip=$sourceVip --enable-dsr=false --log-dir=$LogDir --logtostderr=false
}