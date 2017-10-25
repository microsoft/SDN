c:\k\kubectl --kubeconfig C:\k\config delete deployment --all

Stop-Service KubeProxy
Stop-Service Kubelet

get-hnsendpoints | Remove-HNSEndpoint 
Get-HNSPolicyLists | Remove-HnsPolicyList

$na = Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*"
netsh in ipv4 set int $na.ifIndex fo=en

Echo "Modify KubeproxyStartup.ps1 to Userspace"
pause

$hnsnetwork =get-hnsnetworks | ? Name -EQ l2tunnel
$hnsendpoint = new-hnsendpoint -NetworkId $hnsnetwork.Id -Name forwarder
Attach-HnsHostEndpoint -EndpointID $hnsendpoint.Id  -CompartmentID 1

Start-Service KubeProxy

sleep 5 
New-HnsLoadBalancer -Endpoints $hnsendpoint.Id -InternalPort 60000 -ExternalPort 60000 -Vip 1.1.1.1

ipconfig /all
