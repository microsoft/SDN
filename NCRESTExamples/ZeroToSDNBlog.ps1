Import-Module NetworkController

$uri = "<NC FQDN or IP>" # Replace with the URI of the Network Controller REST IP or FQDN

# Reference AllowAll ACL
$acl_allowall_resourceid = "e32a6d3c-7082-0000-1111-9bd5fa05bbc9"  # Default AllowAcl Created by SDNExpressTenant.ps1

### Create Limited ACLs for Web Tier

# Allow Inbound TCP:80 from Internet to web tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “80”
$ruleproperties.Action = “Allow”
$ruleproperties.SourceAddressPrefix = “Internet”
$ruleproperties.DestinationAddressPrefix = “24.30.1.0/24”
$ruleproperties.Priority = “100”
$ruleproperties.Type = “Inbound”
$ruleproperties.Logging = “Enabled”

$aclrule1 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule1.Properties = $ruleproperties
$aclrule1.ResourceId = “AllowWeb_From_Internet_Inbound”

# Allow Outbound TCP:4500 from web tier IP prefix to app tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “4500”
$ruleproperties.Action = “Allow”
$ruleproperties.SourceAddressPrefix = “24.30.1.0/24”
$ruleproperties.DestinationAddressPrefix = “24.30.2.0/24”
$ruleproperties.Priority = “110”
$ruleproperties.Type = “Outbound”
$ruleproperties.Logging = “Enabled”

$aclrule2 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule2.Properties = $ruleproperties
$aclrule2.ResourceId = “Allow4500_Outbound”

# Deny Inbound TCP:80 from app tier IP prefix to web tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “80”
$ruleproperties.Action = “Deny”
$ruleproperties.SourceAddressPrefix = “24.30.2.0/24”
$ruleproperties.DestinationAddressPrefix = “24.30.1.0/24”
$ruleproperties.Priority = “110”
$ruleproperties.Type = “Inbound”
$ruleproperties.Logging = “Enabled”

$aclrule3 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule3.Properties = $ruleproperties
$aclrule3.ResourceId = “Block_Web_From_AppTier”

# Deny Inbound TCP:80 from DB tier IP prefix to web tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “80”
$ruleproperties.Action = “Deny”
$ruleproperties.SourceAddressPrefix = “24.30.3.0/24”
$ruleproperties.DestinationAddressPrefix = “24.30.1.0/24”
$ruleproperties.Priority = “120”
$ruleproperties.Type = “Inbound”
$ruleproperties.Logging = “Enabled”

$aclrule4 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule4.Properties = $ruleproperties
$aclrule4.ResourceId = “Block_Web_From_DBTier”

# Group ACL Rules together to create ACL List for Web Tier
$acllistproperties = new-object Microsoft.Windows.NetworkController.AccessControlListProperties
$acllistproperties.AclRules = @($aclrule1, $aclrule2, $aclrule3, $aclrule4)
New-NetworkControllerAccessControlList -ResourceId "WebTierACLs" -Properties $acllistproperties -ConnectionUri $uri

### Create Limited ACLs for Middle Tier

# Allow Inbound TCP:4500 from web tier IP prefix to app tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “4500”
$ruleproperties.Action = “Allow”
$ruleproperties.SourceAddressPrefix = “24.30.1.0/24”
$ruleproperties.DestinationAddressPrefix = “24.30.2.0/24”
$ruleproperties.Priority = “100”
$ruleproperties.Type = “Inbound”
$ruleproperties.Logging = “Enabled”

$aclrule1 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule1.Properties = $ruleproperties
$aclrule1.ResourceId = “AllowTCP4500_Inbound”

# Allow Outbound TCP:1433 from app tier IP prefix to DB tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “1433”
$ruleproperties.Action = “Allow”
$ruleproperties.SourceAddressPrefix = “24.30.2.0/24”
$ruleproperties.DestinationAddressPrefix = “24.30.3.0/24”
$ruleproperties.Priority = “100”
$ruleproperties.Type = “Outbound”
$ruleproperties.Logging = “Enabled”

$aclrule2 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule2.Properties = $ruleproperties
$aclrule2.ResourceId = “AllowTCP1433_Outbound”

# Group ACL Rules together to create ACL List for App Tier
$acllistproperties = new-object Microsoft.Windows.NetworkController.AccessControlListProperties
$acllistproperties.AclRules = @($aclrule1, $aclrule2)
New-NetworkControllerAccessControlList -ResourceId "AppTierACLs" -Properties $acllistproperties -ConnectionUri $uri

### Create Limited ACLs for Backend Tier

# Allow Inbound TCP:1433 from app tier IP prefix to DB tier IP prefix
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Protocol = “TCP”
$ruleproperties.SourcePortRange = “0-65535”
$ruleproperties.DestinationPortRange = “1433”
$ruleproperties.Action = “Allow”
$ruleproperties.SourceAddressPrefix = “24.30.2.0/24”
$ruleproperties.DestinationAddressPrefix = “24.30.3.0/24”
$ruleproperties.Priority = “100”
$ruleproperties.Type = “Inbound”
$ruleproperties.Logging = “Enabled”

$aclrule1 = new-object Microsoft.Windows.NetworkController.AclRule
$aclrule1.Properties = $ruleproperties
$aclrule1.ResourceId = “AllowTCP1433_Inbound”

# Group ACL Rules together to create ACL List for DB Tier
$acllistproperties = new-object Microsoft.Windows.NetworkController.AccessControlListProperties
$acllistproperties.AclRules = @($aclrule1)
New-NetworkControllerAccessControlList -ResourceId "DatabaseTierACLs" -Properties $acllistproperties -ConnectionUri $uri


### Create Fabrikam_VNet1 Virtual Network 

# Find the HNV Provider Logical Network
$logicalnetworks = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri
foreach ($ln in $logicalnetworks) {
   if ($ln.Properties.NetworkVirtualizationEnabled -eq "True") {
      $HNVProviderLogicalNetwork = $ln
      break
   }
} 

# Get a reference to Allow All ACL (TESTING ONLY)
$acllist = Get-NetworkControllerAccessControlList –ConnectionUri $uri –ResourceId $acl_allowall_resourceid

# VNet previously created by SDNExpressTenant.ps1
$vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri -ResourceId "Fabrikam_VNet1"

$vnet.properties.AddressSpace.AddressPrefixes += "24.30.0.0/22"
$vnet.properties.Subnets += $vsubnet

# Update Address Prefixes
New-NetworkControllerVirtualNetwork -ResourceId "Fabrikam_VNet1" -ConnectionUri $uri –Properties $vnet.properties

# Create Frontend_WebTier_Subnet Virtual Subnet
$vsubnet = new-object Microsoft.Windows.NetworkController.VirtualSubnet
$vsubnet.ResourceId = "Frontend_WebTier_Subnet"
$vsubnet.Properties = new-object Microsoft.Windows.NetworkController.VirtualSubnetProperties
$vsubnet.Properties.AccessControlList = $acllist
$vsubnet.Properties.AddressPrefix = “24.30.1.0/24”

# Create Middle_ApplicationTier_Subnet Virtual Subnet
$vsubnet = new-object Microsoft.Windows.NetworkController.VirtualSubnet
$vsubnet.ResourceId = "Middle_ApplicationTier_Subnet"
$vsubnet.Properties = new-object Microsoft.Windows.NetworkController.VirtualSubnetProperties
$vsubnet.Properties.AccessControlList = $acllist
$vsubnet.Properties.AddressPrefix = “24.30.2.0/24”

$vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri -ResourceId "Fabrikam_VNet1"
$vnet.properties.Subnets += $vsubnet

#Update
New-NetworkControllerVirtualNetwork -ResourceId "Fabrikam_VNet1" -ConnectionUri $uri –Properties $vnet.properties

# Create Backend_Tier_Subnet Virtual Subnet
$vsubnet = new-object Microsoft.Windows.NetworkController.VirtualSubnet
$vsubnet.ResourceId = "Backend_DatabaseTier_Subnet"
$vsubnet.Properties = new-object Microsoft.Windows.NetworkController.VirtualSubnetProperties
$vsubnet.Properties.AccessControlList = $acllist
$vsubnet.Properties.AddressPrefix = “24.30.3.0/24”

$vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri -ResourceId "Fabrikam_VNet1"
$vnet.properties.Subnets += $vsubnet

#Update
New-NetworkControllerVirtualNetwork -ResourceId "Fabrikam_VNet1" -ConnectionUri $uri –Properties $vnet.properties



### Create VM NIC and IP Configurations ###

# Web Tier VM NICs and IP Configurations
$webtier_vsubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId Fabrikam_VNet1 -ResourceId "Frontend_WebTier_Subnet" -ConnectionUri $uri

# WebTier_VM1_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5501"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_1_101"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.1.101"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $webtier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "WebTier_VM1_NIC1" -Properties $vmnicproperties -ConnectionUri $uri

# WebTier_VM2_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5502"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_1_102"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.1.102"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $webtier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "WebTier_VM2_NIC1" -Properties $vmnicproperties -ConnectionUri $uri

$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5503"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_1_103"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.1.103"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $webtier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "WebTier_VM3_NIC1" -Properties $vmnicproperties -ConnectionUri $uri



# Application Tier VM NICs and IP Configurations
$apptier_vsubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId Fabrikam_VNet1 -ResourceId "Middle_ApplicationTier_Subnet" -ConnectionUri $uri

# AppTier_VM1_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5601"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_2_151"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.2.151"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $apptier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "AppTier_VM1_NIC1" -Properties $vmnicproperties -ConnectionUri $uri

# AppTier_VM2_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5602"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_2_152"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.2.152"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $apptier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "AppTier_VM2_NIC1" -Properties $vmnicproperties -ConnectionUri $uri

# AppTier_VM3_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5603"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_2_153"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.2.153"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $apptier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "AppTier_VM3_NIC1" -Properties $vmnicproperties -ConnectionUri $uri




# Database Tier VM NICs and IP Configurations
$databasetier_vsubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId Fabrikam_VNet1 -ResourceId "Backend_DatabaseTier_Subnet" -ConnectionUri $uri

# DatabaseTier_VM1_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5701"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_3_181"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.3.181"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $databasetier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "DatabaseTier_VM1_NIC1" -Properties $vmnicproperties -ConnectionUri $uri

# DatabaseTier_VM2_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5702"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_3_182"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.3.182"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $databasetier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "DatabaseTier_VM2_NIC1" -Properties $vmnicproperties -ConnectionUri $uri

# DatabaseTier_VM3_NIC1
$vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
$vmnicproperties.PrivateMacAddress = "00155D3A5703"
$vmnicproperties.PrivateMacAllocationMethod = "Static"
$vmnicproperties.IsHostVirtualNetworkInterface = $false

$vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
$vmnicproperties.DnsSettings.DnsServers = @("24.30.1.99")

$ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
$ipconfiguration.ResourceId = "IP_24_30_3_183"
$ipconfiguration.Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
$ipconfiguration.Properties.PrivateIPAddress = "24.30.3.183"
$ipconfiguration.Properties.PrivateIPAllocationMethod = "Static"

$ipconfiguration.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
$ipconfiguration.Properties.Subnet.ResourceRef = $databasetier_vsubnet.ResourceRef

$vmnicproperties.IpConfigurations = @($ipconfiguration)
New-NetworkControllerNetworkInterface -ResourceId "DatabaseTier_VM3_NIC1" -Properties $vmnicproperties -ConnectionUri $uri



### Create Load Balancer for Passport Expeditor Front-end Web Tier ###

# Using old REST Wrappers here since the PowerShell for SLB had bugs in TP5
$username = "<REPLACE>"
$securepass =  convertto-securestring "<REPLACE>" -asplaintext -force
$Cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username,$securepass
$NCRestFQDNorIP ="<REPLACE>"
. .\NetworkControllerRESTWrappers.ps1 -ComputerName $NCRestFQDNorIP -Credential $cred 

# Get reference to web tier VMNICs' IP Configurations
$WebTier_NICS = @("WebTier_VM1_NIC1", "WebTier_VM2_NIC1", "WebTier_VM3_NIC1")
$ips = @()    
foreach ($nic in $WebTier_NICs)
{
   $vnic = Get-NetworkControllerNetworkInterface -resourceId $nic -ConnectionUri $uri
   $ips += $vnic.properties.ipConfigurations[0]
}

#Add a Tenant VIP
$VIPIP = "<REPLACE>"                      #Example: 10.124.132.35
$VIP_LN = Get-NetworkControllerLogicalNetwork -ResourceID "f8f67956-3906-4303-94c5-09cf91e7e311" -ConnectionUri $uri

$lbfe = @()
$lbfe += New-NCLoadBalancerFrontEndIPConfiguration -PrivateIPAddress $VIPIP -Subnet ($VIP_LN.properties.Subnets[0]) 
                                      
$lbbe = @()
$lbbe += New-NCLoadBalancerBackendAddressPool -IPConfigurations $ips

# Create LB rule to map VIP:80 to web tier IP configs
$rules = @()
$rules += New-NCLoadBalancerLoadBalancingRule -protocol "TCP" -frontendPort 80 -backendport 80 -enableFloatingIP $False -frontEndIPConfigurations $lbfe -backendAddressPool $lbbe

$onats = @()
$onats += New-NCLoadBalancerOutboundNatRule -frontendipconfigurations $lbfe -backendaddresspool $lbbe 
$lb = New-NCLoadBalancer -ResourceID "Fabrikam_PassportExpeditor_SLB" -frontendipconfigurations $lbfe -backendaddresspools $lbbe -loadbalancingrules $rules -outboundnatrules $onats -ComputerName localhost


# Create VMs and Port Profiles
# ... Reference ZeroToSDNBlog-VMPolicy.ps1





