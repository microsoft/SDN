# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [boolean] $createVMs=$true,
    [Switch] $Undo
)

$VerbosePreference = "Continue"

#VIP for web tier.  Must come from VIP subnet passed into SDNExpress.
$VIPIP = "10.127.134.163"

$ConfigData = @{

    AllNodes = 
    @(
        @{ 
            NodeName="*"              # * indicates this section applies to all nodes.  Don't change it.
            
            VHDSrcLocation="Images"              
            ConfigurationSrcLocation="TenantApps"

            #locations on destination

            VMLocation="C:\ClusterStorage\Volume1\VMs"                                                 #Destination on HyperVHost
            MountDir="C:\temp"                                                                #Temp dir on HyperVHost
            vSwitchName = "SDNSwitch"

            #Password to assign to the local administrator of created VMs
            VMLocalAdminPassword = 'P@ssw0rd'

            # This contains the name of the server and share for the deployment infrastructure.  This must be shared with read/write for everyone.
            InstallSrcDir="\\$env:Computername\SDNExpress"
            
            # Name of the VHDX to use for VM creation. must exist in the images path under InstallSrcDir
            VHDName="10586.0.amd64fre.th2_release.151029-1700_server_ServerDataCenter_en-us_vl.vhdx"              
            
            # ProductKey can be blank if using a volume license, or you are deploying in eval mode.  (Don't forget to press "skip").
            ProductKey=""                                                                               

            # Network controller computer name with FQDN
            NetworkControllerRestIP = "SDNNCREST.$env:USERDNSDOMAIN"                                     # Must be FQDN for SSL
            
            # User credentials for communicating with the network controller.  Must contain domain.  Example:: Contoso\Greg
            #NCUsername = 'SA19\greg'
            #NCPassword = '!!123abc'
            
            #Virtual network information.  You don't need to change this, unless you want to.
            Network = @{
                GUID  = "2089e2a0-6c3b-43cf-8797-2cd47238beee"
                DNSServers = @("10.60.34.9")
                Subnets = @(
                    @{
                       Guid = "bf244e5e-31b4-42db-a59c-0ec9c7e2c7f4"
                       AddressSpace = "192.168.0.0"
                       Gateway = "192.168.0.1"
                       Mask = "24"
                       ACLGuid = "d7ae4460-694d-466f-b966-4943211728a9"
                     },
                    @{
                       Guid = "ec574ff3-f99c-41e5-b6db-7c89ca6c6d05"
                       AddressSpace = "192.168.1.0"
                       Gateway = "192.168.1.1"
                       Mask = "24"
                       AclGuid = "e32a6d3c-7082-4ca8-be78-9bd5fa05bbc9"
                     }
                )
                HNVLN_GUID = "bb6c6f28-bad9-441b-8e62-57d2be255904"  
                
             }          
         },
         @{
            NodeName="localhost"
            Role="RestHost"
         },
        
        @{ 
            # Host to create a web tier VM on.
            NodeName="Administrator3"
            Role="HyperVHost"
            VMLocation="d:\VMs"                                                 #Destination on HyperVHost

            VMs=@(
                @{ 
                # Customization information for WebTier VM.  You don't need to change this  unless you changed the virtual network information above.
                 VMName="WebTier-VM1"
                 PortProfileID="6daca142-7d94-41dd-81f0-c38c0141be06" 
                 Subnet=0
                 IPAddress="192.168.0.6"
                 MacAddress="001DC8B73E00"
                 PageColor="green"
                 Role="WebTier"
                 }
                )

         },
         @{ 
            # Host to create additoinal VMs on.
            NodeName="Administrator2"
            Role="HyperVHost"
            VMLocation="d:\VMs"                                                 #Destination on HyperVHost

            VMs=@(
                # Customization information for WebTier and DB Tier VMs.  You don't need to change this  unless you changed the virtual network information above.
                @{ 
                 VMName="WebTier-VM2"
                 PortProfileID="e8425781-5f40-477e-aa9b-88b7bc7620ca" 
                 Subnet=0
                 IPAddress="192.168.0.7"
                 MacAddress="001DC8B73D01"
                 PageColor="blue"
                 Role="WebTier"
                 },
                @{ 
                 VMName="DBTier-VM1"
                 PortProfileID="334b8585-e6c7-4f01-9f69-ccb84a842922" 
                 Subnet=1
                 IPAddress="192.168.1.6"
                 MacAddress="001DC8B73D02"
                PageColor="white"
                 Role="DBTier"
                 }
                 )
          }
     )
}


Configuration DeleteTenantVMs  {    
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        foreach ($VMInfo in $node.VMs) {
            script "RemoveVM-$($VMInfo.VMName)"
            {
                SetScript = {
                    write-verbose "Getting VM"
                    $vm = get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}
                    if ($vm -ne $null) {
                        write-verbose "Stopping VM"
                        $vm | stop-vm -force -TurnOff
                        sleep 1
                        write-verbose "Removing VM"
                        $vm | remove-vm -force
                        sleep 1
                    }
            
                }
                TestScript = {
                      return (get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}) -eq $null
                }
                GetScript = {
                    return @{ result = $true }
                }
            }  
            script "DismountImage-$($VMInfo.VMName)"
            {
                SetScript = {
                    $mountpath = $using:node.MountDir+$($using:VMInfo.VMName)

                    Write-verbose "Dis-Mounting image [$mountpath]"
                    DisMount-WindowsImage -Save -path $mountpath
                }
                TestScript = {
                    $exist = (Test-Path ($using:node.MountDir+$using:vminfo.vmname+"\Windows")) -eq $False

                    return $exist
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            } 
            script "DeleteVMDir-$($VMInfo.VMName)"
            {
                SetScript = {

                    write-verbose "Removing VM directory"
                    rm -recurse -force ("$($Using:node.VMLocation)\$($Using:VMInfo.VMName)")
                }
                TestScript = {
                       $exist = (Test-Path ("$($Using:node.VMLocation)\$($Using:VMInfo.VMName)")) -eq $False

                    return $exist
                }
                GetScript = {
                    return @{ result = $true }
                }
            } 
            script "DeleteMountPoint-$($VMInfo.VMName)"
            {
                SetScript = {
                    write-verbose "Removing vm mount directory"
                    rm -recurse -force ("c:\Temp$($Using:VMInfo.VMName)")
                }
                TestScript = {
                       $exist = (Test-Path ("c:\Temp$($Using:VMInfo.VMName)")) -eq $False

                    return $exist
                }
                GetScript = {
                    return @{ result = $true }
                }
            } 
        }

    }
}

Configuration CreateTenantVMs  {    
 
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        foreach ($VMInfo in $node.VMs) {
            
            ###This first section is general VM creation and customization.  Replace with process of your choice.###
            
            File "CreateVMDirectory_$($VMInfo.VMName)"
            {
                Type = "Directory"
                Ensure = "Present"
                Force = $True
                DestinationPath = $node.VMLocation+"\"+$($VMInfo.VMName)
                    
            }

            File "CopyOSVHD_$($VMInfo.VMName)"
            {
                Type = "File"
                Ensure = "Present"
                Force = $True
                SourcePath = $node.installSrcDir+"\"+$node.VHDSrcLocation+"\"+$node.VHDName
                DestinationPath = $node.VMLocation+"\"+$($VMInfo.VMName)+"\"+$node.VHDName
            }

            Script "MountImage_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    mkdir ($using:node.MountDir+$($using:VMInfo.VMName))

                    $imagepath = $using:node.VMLocation+"\"+$using:vminfo.VMName+"\"+$using:node.VHDName
                    $mountpath = $using:node.MountDir+$($using:VMInfo.VMName)

                    Write-verbose "Mounting image [$imagepath] to [$mountpath]"
                    Mount-WindowsImage -ImagePath $imagepath -Index 1 -path $mountpath
                }
                TestScript = {
                    if ((get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}) -ne $null) {
                        return $true
                    }

                    return ((Test-Path (($using:node.MountDir+$($using:VMInfo.VMName)) + "\Windows")))
                }
                GetScript = {
                    return @{ result = Test-Path (($using:node.MountDir+$using:vminfo.vmname) + "\Windows") }
                }
            }

            Script "CustomizeUnattend_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    $Network = $using:node.network

                    #$srcfile = "$($node.installSrcDir)\$($node.UnattendSrcLocation)\tenant.unattend.xml"
                    $dstfile = $node.MountDir+$($Using:VMInfo.VMName)+"\unattend.xml"
                    
                    $templateUnattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <Identifier>Ethernet</Identifier>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">{0}/{1}</IpAddress>
                    </UnicastIpAddresses>
                    <Routes>
                        <Route wcm:action="add">
                            <Identifier>0</Identifier>
                            <Prefix>0.0.0.0/0</Prefix>
                            <Metric>20</Metric>
                            <NextHopAddress>{2}</NextHopAddress>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
         <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">{3}</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>{4}</ComputerName>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand>
                    <Order>1</Order>
                    <Path>c:\config\rundsc.cmd</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>{5}</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <TimeZone>Pacific Standard Time</TimeZone>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <SkipUserOOBE>true</SkipUserOOBE>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
            </OOBE>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserLocale>en-US</UserLocale>
            <SystemLocale>en-US</SystemLocale>
            <InputLocale>0409:00000409</InputLocale>
            <UILanguage>en-US</UILanguage>
        </component>
    </settings>
    <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@

                    $finalUnattend = ($templateunattend -f $($Using:vminfo.ipaddress), $($Network.subnets[$using:vminfo.subnet].mask), $($Network.subnets[$using:vminfo.subnet].gateway), $($Network.DNSServers[0]), $($Using:vminfo.vmname), $($Using:Node.VMLocalAdminPassword))
                    write-verbose $finalunattend
                    write-verbose "Copying unattend to: $dstfile"
                    set-content -value $finalUnattend -path $dstfile
                }
                TestScript = {
                    return $false
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            } 
            File "PushwebData_$($VMInfo.VMName)"
            {
                Type = "Directory"
                Ensure = "Present"
                Force = $True
                Recurse = $True
                SourcePath = "$($node.InstallSrcDir)\$($node.ConfigurationSrcLocation)\WebTier"
                DestinationPath = "$($node.MountDir)$($VMInfo.VMName)\inetpub\wwwroot"
            }
            Script "PushUnique_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    $Network = $using:node.network

                    $srcfile = "$($node.installSrcDir)\$($node.ConfigurationSrcLocation)\unique.htm"
                    $dstfile = "$($node.MountDir)$($VMInfo.VMName)\inetpub\wwwroot\unique.htm"
                    
                    $templateUnattend = get-content $srcfile
                    $finalUnattend = ($templateunattend -f $($using:vminfo.vmname), $($Using:vminfo.ipaddress), $($using:vminfo.pagecolor))
                    write-verbose $finalunattend
                    write-verbose "Copying unique file to: $dstfile"
                    set-content -value $finalUnattend -path $dstfile
                }
                TestScript = {
                    return $false
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            } 
            File "PushConfig_$($VMInfo.VMName)"
            {
                Type = "File"
                Ensure = "Present"
                Force = $True
                SourcePath = "$($node.installSrcDir)\$($node.ConfigurationSrcLocation)\$($VMInfo.Role).ps1"
                DestinationPath = "$($node.MountDir)$($VMInfo.VMName)\Config\config.ps1"
            }
            File "PushRunDSC_$($VMInfo.VMName)"
            {
                Type = "File"
                Ensure = "Present"
                Force = $True
                SourcePath = "$($node.installSrcDir)\$($node.ConfigurationSrcLocation)\rundsc.cmd"
                DestinationPath = "$($node.MountDir)$($VMInfo.VMName)\Config\rundsc.cmd"
            }
            Script "DisMountImage_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname)
                    remove-item ($using:node.MountDir+$using:vminfo.vmname) -force -recurse
                }
                TestScript = {
                    $exist = (Test-Path ($using:node.MountDir+$using:vminfo.vmname+"\Windows")) -eq $False

                    return $exist
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            }   

            Script "NewVM_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    New-VM -Generation 2 -Name $using:VMInfo.VMName -Path ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)) -MemoryStartupBytes 8GB -VHDPath ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)+"\"+$using:node.VHDName) -SwitchName $using:node.vSwitchName 
                    set-vm  -Name $using:VMInfo.VMName -ProcessorCount 4
                    set-vmnetworkadapter -vmname $using:VMInfo.VMName  -staticmacaddress $using:VMInfo.macaddress

                }
                TestScript = {
                    if ((get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}) -ne $null) {
                        return $true
                    }
                    return $false
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            }                    
                         
            Script "SetPortProfile_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"

                    set-PortProfileId -resourceID ($using:VMInfo.PortProfileId) -VMName ($using:vmInfo.VMName)
                }
                TestScript = {
                    $vmNic = Get-VMNetworkAdapter $using:vminfo.VMName
                    $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"

                    $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic
                    if ($currentProfile -eq $null) {
                        return $false
                    }
                    return ($currentProfile.SettingData.ProfileId -eq "{$($using:vminfo.PortProfileId)}")

                }
                GetScript = {
                    return @{ result = $true }
                }
            }
            
            Script "AttachToVNET_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    $verbosepreference = "Continue"
                    write-verbose "loading NC helpers"
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -Username $node.ncUsername -Password $node.ncpassword

                    $network = $node.Network

                    write-verbose "Network guid is $($network.Guid)"
                    $vnet = Get-NCVirtualNetwork -ResourceId ($network.Guid) 
                    write-verbose "VNet retrived $vnet"
                    
                    $vsubnet = Get-ncvirtualsubnet -VirtualNetwork $vnet -ResourceId $Network.Subnets[$using:vminfo.subnet].Guid

                    $vnics += New-NCNetworkInterface -resourceId $using:vminfo.PortProfileId -Subnet $vsubnet -IPAddress $using:vminfo.IPAddress -MACAddress $using:vminfo.MACAddress  -DNSServers @("10.60.34.9") 
                }
                TestScript = {
                    return $false;
                }
                GetScript = {
                    return @{ result = $true }
                }
            }

            ### you can start the VM at any time after the above two script block have  been set, however until the 
            ### policy has propagated to the host, the VM will not communicate.  In current builds this can take several minutes!
                                      
            Script "StartVM_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    Get-VM -Name $using:vminfo.VMName | Start-VM
                }
                TestScript = {
                    $vm = Get-VM -Name $using:vminfo.VMName | Select-Object -First 1 
                    if($vm -ne $null -and $vm[0].State -eq "Running")
                    {
                        return $true
                    }

                    return $false
                }
                GetScript = {
                    return @{ result = (Get-VM -Name $using:vminfo.VMName)[0] }
                }
            }                
        }
    }
}

Configuration CreateNetwork  {    
 
    Node $AllNodes.Where{$_.Role -eq "RESTHost"}.NodeName
    {
            Script "CreateAllowAllACL"
            {                                      
                SetScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

                    $aclRules = @()
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Inbound" -Logging $true -Priority 100
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Outbound" -Logging $true -Priority 101
                    $acl = New-NCAccessControlList -resourceId $node.Network.subnets[1].ACLGUID -AccessControlListRules $aclRules
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -Username $node.ncUsername -Password $node.ncpassword

                    $acl = Get-NCAccessControlList -resourceId $using:node.Network.subnets[1].ACLGUID
                    return ($acl -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            } 
            Script "CreateLimitedACL"
            {                                      
                SetScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

                    $aclRules = @()
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "192.168.0.0/24" -destinationAddressPrefix "*" -Action "Deny" -ACLType "Inbound" -Logging $true -Priority 100
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "192.168.0.0/24" -Action "Deny" -ACLType "Outbound" -Logging $true -Priority 101
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Inbound" -Logging $true -Priority 102
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Outbound" -Logging $true -Priority 103
                    $acl = New-NCAccessControlList -resourceId $using:node.network.subnets[0].ACLGUID -AccessControlListRules $aclRules
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

                    $acl = Get-NCAccessControlList -resourceId $using:node.network.subnets[0].ACLGUID
                    return ($acl -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            } 
            Script "CreateVNet"
            {                                      
                SetScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

                    $network = $node.network
                    $HNV_LN = get-NCLogicalNetwork -resourceId $network.HNVLN_GUID

                    $vSubnets = @()
                    $prefixes = @()
                    foreach ($subnet in $network.subnets) {
                        $acl = get-NCAccessControlList -resourceId $subnet.ACLGUID
                        $prefix = "$($subnet.AddressSpace)/$($subnet.Mask)"
                        $prefixes += $prefix
                        $vSubnets += New-NCVirtualSubnet -ResourceId $subnet.guid -AddressPrefix $prefix -AccessControlList $acl
                    }
                    $vnet = New-NCVirtualNetwork -resourceID $network.guid -addressPrefixes $prefixes -LogicalNetwork $HNV_LN  -VirtualSubnets $vSubnets
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

                    $result = get-NCVirtualNetwork -resourceId $using:node.Network.guid
                    return ($result -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            } 
      }                                                                    
}

Configuration CreateVIP  {    
 
    Node $AllNodes.Where{$_.Role -eq "RESTHost"}.NodeName
    {
            Script "CreateVIP"
            {                                      
                SetScript = {
                    $vipip = $using:VIPIP
                    $node = $using:node

                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

                    $vnics = @()
                    $vnics += get-NCNetworkInterface -resourceId "6daca142-7d94-41dd-81f0-c38c0141be06" 
                    $vnics += get-NCNetworkInterface -resourceId "e8425781-5f40-477e-aa9b-88b7bc7620ca" 
                    #$vnics += get-NCNetworkInterface -resourceId "334b8585-e6c7-4f01-9f69-ccb84a842922"

                    #Add a LB VIPs
                    $VIP_LN = get-NCLogicalNetwork -resourceId "f8f67956-3906-4303-94c5-09cf91e7e311"

                    # Port 80 to first tier
                    $lbfe = @()
                    $lbfe += New-NCLoadBalancerFrontEndIPConfiguration -PrivateIPAddress $VIPIP -Subnet ($VIP_LN.properties.Subnets[0]) 

                    $ips = @()    
                    $ips += $vnics[0].properties.ipConfigurations[0]
                    $ips += $vnics[1].properties.ipConfigurations[0]

                    $lbbe = @()
                    $lbbe += New-NCLoadBalancerBackendAddressPool -IPConfigurations $ips

                    $rules = @()
                    $rules += New-NCLoadBalancerLoadBalancingRule -protocol "TCP" -frontendPort 80 -backendport 80 -enableFloatingIP $False -frontEndIPConfigurations $lbfe -backendAddressPool $lbbe

                    $onats = @()
                    $onats += New-NCLoadBalancerOutboundNatRule -frontendipconfigurations $lbfe -backendaddresspool $lbbe 
                    $lb = New-NCLoadBalancer -ResourceID "60323a46-a438-429e-a825-9ba25c5cb139" -frontendipconfigurations $lbfe -backendaddresspools $lbbe -loadbalancingrules $rules -outboundnatrules $onats

                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -Username $node.ncUsername -Password $node.ncpassword

                    $lb = get-NCLoadBalancer -ResourceID "60323a46-a438-429e-a825-9ba25c5cb139"
                    return ($lb -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            }
      }
}

         
         

if ($undo.ispresent -eq $false) {

    Remove-Item .\CreateNetwork -Force -Recurse 2>$null
    Remove-Item .\CreateTenantVMs -Force -Recurse 2>$null
    Remove-Item .\CreateVIP -Force -Recurse 2>$null

    CreateNetwork -ConfigurationData $ConfigData -verbose
    Start-DscConfiguration -Path .\CreateNetwork -Wait -Force -Verbose

    CreateTenantVMs -ConfigurationData $ConfigData -verbose
    Start-DscConfiguration -Path .\CreateTenantVMs -Wait -Force -Verbose

    read-host 'Press <Enter> to add VIP'

    CreateVIP -ConfigurationData $ConfigData -verbose
    Start-DscConfiguration -Path .\CreateVIP -Wait -Force -Verbose
}
else 
{
    $node = $ConfigData.AllNodes[0]
    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

    Remove-Item .\DeleteTenantVMs -Force -Recurse 2>$null

    Remove-NCLoadBalancer -ResourceID "60323a46-a438-429e-a825-9ba25c5cb139"

    Remove-NCNetworkInterface -resourceId "6daca142-7d94-41dd-81f0-c38c0141be06"
    Remove-NCNetworkInterface -resourceId "e8425781-5f40-477e-aa9b-88b7bc7620ca"
    Remove-NCNetworkInterface -resourceId "334b8585-e6c7-4f01-9f69-ccb84a842922"
<#    
    remove-NCVirtualNetwork -resourceID $node.Network.guid
    remove-NCAccessControlList -resourceId $node.Network.subnets[0].ACLGUID 
    remove-NCAccessControlList -resourceId $node.Network.subnets[1].ACLGUID 
    #>
    DeleteTenantVMs -ConfigurationData $ConfigData -verbose
    Start-DscConfiguration -Path .\DeleteTenantVMs -Wait -Force -Verbose
}
