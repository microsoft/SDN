$logicalNetwork = Get-SCLogicalNetwork -ID "9c89d0d7-8e08-4022-823b-4924b7207847" # HNV Provider


$max_vnets = 25
$max_subnets = 5

foreach ($i in 1..$max_vnets)
{
   # Create VM Network
   $vnetname = "vnet$i"
   $vmNetwork = New-SCVMNetwork -Name $vnetname -LogicalNetwork $logicalNetwork -IsolationType "WindowsNetworkVirtualization" -CAIPAddressPoolType "IPV4" -PAIPAddressPoolType "IPV4"
   #Write-Output $vmNetwork
   
   foreach ($j in 1..$max_subnets)
   {
      # Create VM Subnet
      $prefix = "10.$i.$j.0/24"
      $subnet = New-SCSubnetVLan -Subnet $prefix
      $vmsubnet = New-SCVMSubnet -Name "Vnet$i-Subnet_$prefix" -VMNetwork $vmNetwork -SubnetVLan $subnet
      #Write-Output $vmsubnet

      # Create VM Subnet IP Pool
      $allGateways = @()
      $allDnsServer = @()
      $allDnsSuffixes = @()
      $allWinsServers = @()

      New-SCStaticIPAddressPool -Name "Vnet$i-Subnet_$prefix IP Pool" -VMSubnet $vmSubnet -Subnet $prefix -IPAddressRangeStart "10.$i.$j.4" -IPAddressRangeEnd "10.$i.$j.254" -DefaultGateway $allGateways -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -RunAsynchronously
    }
}

sleep 5

# Remove VNets
foreach ($i in 1..$max_vnets)
{
   $vmnetwork = Get-SCVMNetwork -Name "vnet$i"

   foreach ($j in 1..$max_subnets)
   {
      $prefix = "10.$i.$j.0/24"
      $vmsubnet = Get-SCVMSubnet -Name "Vnet$i-Subnet_$prefix" -VMNetwork $vmnetwork
      $ippool =  Get-SCStaticIPAddressPool -Name "Vnet$i-Subnet_$prefix IP Pool" -VMSubnet $vmsubnet
      Remove-SCStaticIPAddressPool -StaticIPAddressPool $ippool

#      $vmsubnet = Get-SCVMSubnet -Name "Subnet_$prefix"
      Remove-SCVMSubnet $vmsubnet
   }

 #  $vmnetwork = Get-SCVMNetwork -Name "vnet$i"
   Remove-SCVMNetwork $vmnetwork
}