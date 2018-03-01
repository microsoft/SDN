
$BaseDir = "c:\k"


taskkill /im kubelet.exe /f
taskkill /im kube-proxy.exe /f

ipmo $BaseDir\hns.psm1
Get-HnsPolicyLists | Remove-HnsPolicyList
Get-HnsNetworks | Remove-HnsNetwork


