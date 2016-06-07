$PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"

$vmNics = (Get-VMNetworkAdapter *)
foreach ($vmNic in $vmNics) 
{
    write-output ("Getting port profile for VM NIC $($vmNic.Name) on VM $($vmNic.VMName)")
    $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic
    if ( $currentProfile -eq $null) 
    {
        write-output "WARNING: $vmNic.Name does not have a port profile"
    } else 
    {
        write-output ("Port Profile Id:   $($currentProfile.SettingData.ProfileId)")
        write-output ("Port Profile Data: $($currentProfile.SettingData.ProfileData)")
    }
}
    