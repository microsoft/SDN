$uri = "https://10.127.132.211"

$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties  
$ruleproperties.Protocol = "TCP"  
$ruleproperties.SourcePortRange = "0-65535"  
$ruleproperties.DestinationPortRange = "80"  
$ruleproperties.Action = "Allow"  
$ruleproperties.SourceAddressPrefix = "10.1.1.0/24"  
$ruleproperties.DestinationAddressPrefix = "10.1.1.0/24"  
$ruleproperties.Priority = "100"  
$ruleproperties.Type = "Inbound"  
$ruleproperties.Logging = "Enabled"  

$aclrule1 = new-object Microsoft.Windows.NetworkController.AclRule  
$aclrule1.Properties = $ruleproperties  
$aclrule1.ResourceId = "AllowTCP80_Inbound"  

$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties  
$ruleproperties.Protocol = "All" 
$ruleproperties.SourcePortRange = "0-65535"  
$ruleproperties.DestinationPortRange = "0-65535"  
$ruleproperties.Action = "Deny"  
$ruleproperties.SourceAddressPrefix = "*"  
$ruleproperties.DestinationAddressPrefix = "*"  
$ruleproperties.Priority = "110"  
$ruleproperties.Type = "Inbound"  
$ruleproperties.Logging = "Enabled"  

$aclrule2 = new-object Microsoft.Windows.NetworkController.AclRule  
$aclrule2.Properties = $ruleproperties  
$aclrule2.ResourceId = "BlockAll_Inbound"  

$acllistproperties = new-object Microsoft.Windows.NetworkController.AccessControlListProperties  
$acllistproperties.AclRules = @($aclrule1, $aclrule2)
$acl = New-NetworkControllerAccessControlList -ResourceId "VNet1_Subnet1_ACL" -Properties $acllistproperties -ConnectionUri $uri 

$vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri | where { $_.properties.AddressSpace.AddressPrefixes[0] -eq "10.1.1.0/24" }
$vmsubnet = Get-NetworkControllerVirtualSubnet -ConnectionUri $uri -VirtualNetworkId $vnet.ResourceId | where { $_.Properties.AddressPrefix -eq "10.1.1.0/24" }

$vmsubnet.properties.AccessControlList = $acl

New-NetworkControllerVirtualSubnet -ConnectionUri $uri -VirtualNetworkId $vnet.ResourceId -ResourceId $vmsubnet.ResourceId -Properties $vmsubnet.properties



#$nic = get-networkcontrollernetworkinterface -ConnectionUri $uri -ResourceId "MyVM_Ethernet1"
#$acl = get-networkcontrolleraccesscontrollist -ConnectionUri $uri -resourceid "AllowAllACL"
#$nic.properties.ipconfigurations[0].properties.AccessControlList = $acl
#new-networkcontrollernetworkinterface -ConnectionUri $uri -Properties $nic.properties -ResourceId $nic.resourceid
