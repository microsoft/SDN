$uri = "https://10.127.132.211"

#EXAMPLE2: Outbound NAT

$vipip = "10.127.132.34"
$lbid = "5290ff9c-b854-4d3d-a747-c220dd396181_10.127.132.34"
$publicvipln = get-networkcontrollerlogicalnetwork -ConnectionUri $uri -resourceid "5290ff9c-b854-4d3d-a747-c220dd396181"

$lb = Get-NetworkControllerLoadBalancer -Connectionuri $uri -ResourceId $lbid
$fe = Get-NetworkControllerLoadBalancerFrontendIPConfiguration -ConnectionUri $uri -LoadBalancerId $lbid
$backend = Get-NetworkControllerLoadBalancerBackendAddressPool -ConnectionUri $uri -LoadBalancerId $lbid

$onat = @{}
$onat.ResourceId = "onat1"
$onat.properties = @{}
$onat.properties.frontendipconfigurations = @()
$onat.properties.frontendipconfigurations += $fe
$onat.properties.backendaddresspool = $backend
$onat.properties.protocol = "ALL"
$lb.properties.OutboundNatRules += $onat

New-NetworkControllerLoadBalancer -ConnectionUri $uri -ResourceId $lbid -Properties $lb.properties

#Give a network interface outbound NAT access.  Repeat for each NIC.
$lb = Get-NetworkControllerLoadBalancer -Connectionuri $uri -ResourceId $lbid

$nic = get-networkcontrollernetworkinterface  -connectionuri $uri -resourceid "f5539fc6-d389-42ab-a450-74c738019cba"
$nic.properties.IpConfigurations[0].properties.LoadBalancerBackendAddressPools += $lb.properties.backendaddresspools[0]

new-networkcontrollernetworkinterface  -connectionuri $uri -resourceid $nic.resourceid -properties $nic.properties -force


