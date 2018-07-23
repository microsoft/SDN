function SetPortProfile()
{
   param (
        [Parameter(mandatory=$true)]
        [string] $VMName,
        [Parameter(mandatory=$false)]
        [string] $VMNetworkAdapterName,
        [Parameter(mandatory=$true)]
        [string] $PortProfileID,
        [Parameter(mandatory=$false)]
        [int] $ProfileData = 1
   )
   
   $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
   $NcVendorId  = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"

   $vmnic = Get-VMNetworkAdapter -VMName $VMName -Name $VMNetworkAdapterName
   $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic
   
   if ( $currentProfile -eq $null) 
   {
      $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
      $portProfileDefaultSetting.SettingData.ProfileId = "{$PortProfileID}"
      $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
      $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
      $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
      $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
      $portProfileDefaultSetting.SettingData.VendorId = $NcVendorId 
      $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
      $portProfileDefaultSetting.SettingData.ProfileData = $ProfileData      
      
      Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vmNic | out-null

   } 
   else 
   {
      $currentProfile.SettingData.ProfileId = "{$PortProfileID}"
      $currentProfile.SettingData.ProfileData = $ProfileData
      Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentProfile  -VMNetworkAdapter $vmNic
   }
}

# Host 1 (SA18N30-1)
New-VM -Generation 2 -Name "WebTier_VM1" -Path "C:\VM\WebTier_VM1" -MemoryStartupBytes 2GB -VHDPath "C:\VM\WebTier_VM1\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "WebTier_VM1" -ProcessorCount 2 
Set-VMNetworkAdapter -VMName "WebTier_VM1" -Name -StaticMacAddress "00-15-5D-3A-55-01"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "WebTier_VM1_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "Web_VM1 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "WebTier_VM1" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

New-VM -Generation 2 -Name "AppTier_VM1"  -Path "C:\VM\AppTier_VM1" -MemoryStartupBytes 2GB -VHDPath "C:\VM\AppTier_VM1\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "AppTier_VM1" -ProcessorCount 2 
Set-VMNetworkAdapter -VMName "AppTier_VM1" -StaticMacAddress "00-15-5D-3A-56-01"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "AppTier_VM1_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "App_VM1 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "AppTier_VM1" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

# Host 2 (SA18N30-2)
New-VM -Generation 2 -Name "WebTier_VM2"  -Path "C:\VM\WebTier_VM2" -MemoryStartupBytes 2GB -VHDPath "C:\VM\WebTier_VM2\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "WebTier_VM2" -ProcessorCount 2 
Set-VMNetworkAdapter -VMName "WebTier_VM2" -StaticMacAddress "00-15-5D-3A-55-02"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "WebTier_VM2_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "Web_VM2 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "WebTier_VM2" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

New-VM -Generation 2 -Name "WebTier_VM3"  -Path "C:\VM\WebTier_VM3" -MemoryStartupBytes 2GB -VHDPath "C:\VM\WebTier_VM3\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "WebTier_VM3" -ProcessorCount 2 
Set-VMNetworkAdapter -VMName "WebTier_VM3" -StaticMacAddress "00-15-5D-3A-55-03"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "WebTier_VM3_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "Web_VM3 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "WebTier_VM3" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

New-VM -Generation 2 -Name "AppTier_VM2"  -Path "C:\VM\AppTier_VM2" -MemoryStartupBytes 2GB -VHDPath "C:\VM\AppTier_VM2\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "AppTier_VM2" -ProcessorCount 2
Set-VMNetworkAdapter -VMName "AppTier_VM2" -StaticMacAddress "00-15-5D-3A-56-02"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "AppTier_VM2_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "App_VM2 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "AppTier_VM2" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

# Host 3 (SA18N30-3)
New-VM -Generation 2 -Name "AppTier_VM3"  -Path "C:\VM\AppTier_VM3" -MemoryStartupBytes 2GB -VHDPath "C:\VM\AppTier_VM3\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "AppTier_VM3" -ProcessorCount 2
Set-VMNetworkAdapter -VMName "AppTier_VM3" -StaticMacAddress "00-15-5D-3A-56-03"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "AppTier_VM3_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "App_VM3 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "AppTier_VM3" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

New-VM -Generation 2 -Name "DatabaseTier_VM1"  -Path "C:\VM\DatabaseTier_VM1" -MemoryStartupBytes 2GB -VHDPath "C:\VM\DatabaseTier_VM1\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "DatabaseTier_VM1" -ProcessorCount 2
Set-VMNetworkAdapter -VMName "DatabaseTier_VM1" -StaticMacAddress "00-15-5D-3A-57-01"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "DatabaseTier_VM1_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "DB_VM1 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "DatabaseTier_VM1" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

New-VM -Generation 2 -Name "DatabaseTier_VM2"  -Path "C:\VM\DatabaseTier_VM2" -MemoryStartupBytes 2GB -VHDPath "C:\VM\DatabaseTier_VM2\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "DatabaseTier_VM2" -ProcessorCount 2
Set-VMNetworkAdapter -VMName "DatabaseTier_VM2" -StaticMacAddress "00-15-5D-3A-57-02"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "DatabaseTier_VM2_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "DB_VM2 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "DatabaseTier_VM2" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}

New-VM -Generation 2 -Name "DatabaseTier_VM3"  -Path "C:\VM\DatabaseTier_VM3" -MemoryStartupBytes 2GB -VHDPath "C:\VM\DatabaseTier_VM3\Virtual Hard Disks\WindowsServer2016.vhdx" -SwitchName "sdnswitch"
Set-VM -Name "DatabaseTier_VM3" -ProcessorCount 2
Set-VMNetworkAdapter -VMName "DatabaseTier_VM3" -StaticMacAddress "00-15-5D-3A-57-03"

$instanceid = (Get-NetworkControllerNetworkInterface -ResourceId "DatabaseTier_VM3_NIC1" -ConnectionUri $uri).InstanceId.ToString()
Write-Output "DB_VM3 InstanceId: $instanceId"
if (-Not ($instanceid -eq ""))
{
   SetPortProfile -VMName "DatabaseTier_VM3" -VMNetworkAdapterName "Network Adapter" -PortProfileID $instanceid
}