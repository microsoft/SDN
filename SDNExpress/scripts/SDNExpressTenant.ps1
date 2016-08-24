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
[CmdletBinding(DefaultParameterSetName="NoParameters")]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null,
    [Parameter(mandatory=$false)]
    [boolean] $createVMs=$true,
    [Parameter(mandatory=$false)]
    [Switch] $Undo
)

# Script version, should be matched with the config files
$ScriptVersion = "1.0"

$VerbosePreference = "Continue"

Configuration DeleteTenantVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration' 

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

Configuration CreateTenantVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'    
 
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
                        <DhcpEnabled>{7}</DhcpEnabled>
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
            {6}
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

                    $key = ""
                    if ($($Using:node.productkey) -ne "" ) {
                        $key = "<ProductKey>$($Using:node.productkey)</ProductKey>"
                    }
		     if ($Using:node.UseIDns -eq $true) {
                    write-verbose "Using iDNS"
                    $finalUnattend = ($templateunattend -f "", "", "", "", $($Using:vminfo.vmname), $($Using:Node.VMLocalAdminPassword), $key, "true")
                    }
                    else
                    {
                    write-verbose "NOT Using iDNS"
                    $finalUnattend = ($templateunattend -f $($Using:vminfo.ipaddress), $($Network.subnets[$using:vminfo.subnet].mask), $($Network.subnets[$using:vminfo.subnet].gateway), $($Network.DNSServers[0]), $($Using:vminfo.vmname), $($Using:Node.VMLocalAdminPassword), $key, "false")
                    }
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
                    New-VM -Generation 2 -Name $using:VMInfo.VMName -Path ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)) -MemoryStartupBytes $using:VMInfo.VMMemory -VHDPath ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)+"\"+$using:node.VHDName) -SwitchName $using:node.vSwitchName 
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
        }
    }
}

Configuration AttachToVirtualNetwork
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'    
 
    Node $AllNodes.Where{$_.Role -eq "RestHost"}.NodeName
    {
        foreach($hostNode in $AllNodes.Where{$_.Role -eq "HyperVHost"})
        {
            foreach ($VMInfo in $hostNode.VMs) {
 
                Script "AttachToVNET_$($VMInfo.VMName)"
                {                                      
                    SetScript = {
                        $verbosepreference = "Continue"
                        write-verbose "loading NC helpers"
                        $node = $using:node

                        . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword

                        $network = $node.Network

                        write-verbose "Network ResourceID is $($node.TenantName)_$($network.ID)"
                        $vnet = Get-NCVirtualNetwork -ResourceId "$($node.TenantName)_$($network.ID)" 
                        write-verbose "VNet retrieved $vnet"
                    
                        $vsubnet = Get-NCVirtualSubnet -VirtualNetwork $vnet -ResourceId $Network.Subnets[$using:VMInfo.subnet].ID 
                    
                        #Use iDNS
                        if ($Using:node.UseIDns -eq $true) {
                        write-verbose "Using iDNS"
                        $vnic = New-NCNetworkInterface -resourceId $using:VMInfo.ResourceId -Subnet $vsubnet -IPAddress $using:VMInfo.IPAddress -MACAddress $using:VMInfo.MACAddress
                        }
                        else
                        {    
                        write-verbose "NOT Using iDNS"                
                        $vnic = New-NCNetworkInterface -resourceId $using:VMInfo.ResourceId -Subnet $vsubnet -IPAddress $using:VMInfo.IPAddress -MACAddress $using:VMInfo.MACAddress -DNSServers $network.DNSServers
                        }
                    }
                    TestScript = {
                        return $false
                    }
                    GetScript = {
                        return @{ result = $true }
                    }
                }

                Script "SetPortProfile_$($VMInfo.VMName)"
                {                                      
                    SetScript = {
                        $node = $using:node

                        . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword
                        $vnicInstanceId = Get-NCNetworkInterfaceInstanceId -ResourceId $using:VMInfo.ResourceId

                        Set-PortProfileId -resourceID ($vnicInstanceId) -VMName ($using:vmInfo.VMName) -ComputerName $using:hostNode.NodeName
                    }
                    TestScript = {
						return $false
                    }
                    GetScript = {
                        return @{ result = $true }
                    }
                }
            }
        }
    }
}

Configuration StartVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'    
 
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        foreach ($VMInfo in $node.VMs) {
                                     
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

Configuration CreateNetwork
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'   
 
    Node $AllNodes.Where{$_.Role -eq "RESTHost"}.NodeName
    {
            Script "CreateAllowAllACL"
            {                                      
                SetScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $aclRules = @()
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Inbound" -Logging $true -Priority 100
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Outbound" -Logging $true -Priority 101
                    $acl = New-NCAccessControlList -resourceId $node.Network.subnets[1].ACLGUID -AccessControlListRules $aclRules
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

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
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $aclRules = @()
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "192.168.0.0/24" -destinationAddressPrefix "*" -Action "Deny" -ACLType "Inbound" -Logging $true -Priority 100
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "192.168.0.0/24" -Action "Deny" -ACLType "Outbound" -Logging $true -Priority 101
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Inbound" -Logging $true -Priority 102
                    $aclRules += New-NCAccessControlListRule -Protocol "ALL" -SourcePortRange "0-65535" -DestinationPortRange "0-65535" -sourceAddressPrefix "*" -destinationAddressPrefix "*" -Action "Allow" -ACLType "Outbound" -Logging $true -Priority 103
                    $acl = New-NCAccessControlList -resourceId $using:node.network.subnets[0].ACLGUID -AccessControlListRules $aclRules
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

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
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $network = $node.network
                    $HNV_LN = get-NCLogicalNetwork -resourceId $network.HNVLN_GUID

                    $vSubnets = @()
                    $prefixes = @()
                    foreach ($subnet in $network.subnets) {
                        $acl = get-NCAccessControlList -resourceId $subnet.ACLGUID
                        $prefix = "$($subnet.AddressSpace)/$($subnet.Mask)"
                        $prefixes += $prefix
                        $vSubnets += New-NCVirtualSubnet -ResourceId $subnet.ID -AddressPrefix $prefix -AccessControlList $acl
                    }
                    $vnet = New-NCVirtualNetwork -resourceID "$($using:node.TenantName)_$($network.ID)" -addressPrefixes $prefixes -LogicalNetwork $HNV_LN  -VirtualSubnets $vSubnets
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $result = get-NCVirtualNetwork -resourceId "$($using:node.TenantName)_$($using:node.Network.ID)"
                    return ($result -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            } 
      }                                                                    
}

Configuration CreateVIP
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'    
 
    Node $AllNodes.Where{$_.Role -eq "RESTHost"}.NodeName
    {
            Script "CreateVIP"
            {                                      
                SetScript = {
                    $vipip = $using:node.VIPIP
                    $node = $using:node

                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                    
                    $vnics = @()    
                    foreach ($nic in $using:node.NetworkInterfaces.WebTier)
                    {
                        $vnic = Get-NCNetworkInterface -resourceId $nic 
                        $vnics += $vnic.resourceId
                    }

                    #Add a LB VIPs
                    $VIP_LN = Get-NCLogicalNetwork -resourceId $using:node.VIPLN_GUID

                    # Port 80 to first tier
                    $lbfe = @()
                    $lbfe += New-NCLoadBalancerFrontEndIPConfiguration -PrivateIPAddress $VIPIP -Subnet ($VIP_LN.properties.Subnets[0]) 
                                      
                    $lbbe = @()
                    $lbbe += New-NCLoadBalancerBackendAddressPool

                    $rules = @()
                    $rules += New-NCLoadBalancerLoadBalancingRule -protocol "TCP" -frontendPort 80 -backendport 80 -enableFloatingIP $False -frontEndIPConfigurations $lbfe -backendAddressPool $lbbe

                    $onats = @()
                    $onats += New-NCLoadBalancerOutboundNatRule -frontendipconfigurations $lbfe -backendaddresspool $lbbe 
                    $lb = New-NCLoadBalancer -ResourceID "$($node.TenantName)_SLB" -frontendipconfigurations $lbfe -backendaddresspools $lbbe -loadbalancingrules $rules -outboundnatrules $onats -ComputerName localhost

		    Add-LoadBalancerToNetworkAdapter -LoadBalancerResourceID $lb.ResourceID -VMNicResourceIds $vnics
                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $lb = Get-NCLoadBalancer -ResourceID "$($node.TenantName)_SLB"
                    return ($lb -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            }
      }
}

Configuration ConfigureVirtualGateway
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'    
 
    Node $AllNodes.Where{$_.Role -eq "RestHost"}.NodeName
    {
            Script "ConfigVirtualGW"
            {                                      
                SetScript = {
                    $node = $using:node

                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $virtualGateway = @{}

                    # Get the first virtual Network control subnet to use it with the Virtual Gateway Rest Object
                    $ipv4SubnetResourceRef = "/virtualNetworks/$($node.TenantName)_$($node.Network.ID)/subnets/$($node.Network.Subnets[0].ID)"

                    $policyMaps = @()
                    $bgpRouters = @()
                    $bgpPeers = @()

                    if ($node.RoutingType -eq "Dynamic")
                    {
                        # Get the Routing Policy Map Json
                        foreach ($policyMap in $node.PolicyMaps)
                        {
                            $policyObj = @()
                            foreach ($policy in $policyMap.PolicyList)
                            {
                                $policyObj += (New-NCBgpRoutingPolicy -PolicyName $policy.PolicyName -PolicyType $policy.PolicyType -MatchCriteriaList $policy.MatchCriteria -Actions $policy.SetAction)
                            }
                            $policyMaps += (New-NCBgpRoutingPolicyMap -PolicyMapName $policyMap.PolicyMapName -PolicyList $policyObj)
                        }        

                        # Get the BgpPeer Json
                        foreach ($bgpPeer in $node.BgpPeers)
                        {
                            $inMapResourceRef = $null
                            $outMapResourceRef = $null

                            # using First PolicyMap as Inbound and 2nd as outbound
                            if ($policyMaps.count -eq 2)
                            {
                                $inMapResourceRef = "/VirtualGateways/$($node.TenantName)/PolicyMaps/$($policyMaps[0].ResourceId)"
                                $outMapResourceRef = "/VirtualGateways/$($node.TenantName)/PolicyMaps/$($policyMaps[1].ResourceId)"
                            }

                            $bgpPeers += (New-NCBgpPeer -PeerName "$($node.TenantName)_$($bgpPeer.PeerName)" -PeerIP $bgpPeer.PeerIP -PeerASN $bgpPeer.PeerASN.ToString() -IngressPolicyMapResourceRef $inMapResourceRef -EgressPolicyMapResourceRef $outMapResourceRef)
                        }

                        $bgpRouter = (New-NCBgpRouter -RouterName "$($node.TenantName)_$($node.BgpRouter.RouterId)" -LocalASN $node.BgpRouter.LocalASN.ToString() -BgpPeers $bgpPeers)
                        $bgpRouters += $bgpRouter
                    }


                    # Get the network connections
                    $nwConnections = @()

                    foreach ($connection in $node.NetworkConnections)
                    {
                        switch ($connection.TunnelType)
                        {
                            "IPSec" {
                                    $nwConnections += (New-NCIPSecTunnel -ResourceId $connection.TunnelName -OutboundCapacity $connection.OutboundCapacity -InboundCapacity $connection.InboundCapacity `
                                                                        -DestinationIPAddress $connection.DestinationIPAddress -SharedSecret $connection.SharedSecret -IPv4Subnets $connection.Routes )
                                    break
                                }
                            "GRE" {
                                    $nwConnections += (New-NCGreTunnel -ResourceId $connection.TunnelName -OutboundCapacity $connection.OutboundCapacity -InboundCapacity $connection.InboundCapacity `
                                                                        -DestinationIPAddress $connection.DestinationIPAddress -GreKey $connection.GreKey -IPv4Subnets $connection.Routes )
                                    break
                                }
                            "L3" {
                                    # Post a Logical network subnet for L3 Tunnel
                                    $ipAddresses = @()

                                    $l3Network = $connection.Network
                                    $l3Subnets = $connection.Network.Subnets
                                    $l3IPAddresses = $connection.IPAddresses

                                    $subnet = @()
                                    if ($l3Subnets -ne $null -and $l3Subnets.count -gt 0)
                                    {
                                        foreach ($l3Subnet in $l3Subnets)
                                        {
                                            $subnet += New-NCLogicalNetworkSubnet -ResourceID $l3Subnet.Guid -AddressPrefix "$($l3Subnet.AddressSpace)/$($l3Subnet.Mask)" -defaultGateway $l3Subnet.DefaultGateway -VLANid $l3Subnet.VlanId 
                                        }
                                        $logicalNetwork = New-NCLogicalNetwork -ResourceID "$($node.TenantName)_$($connection.Network.GUID)" -LogicalNetworkSubnets @($subnet)
                                    }
                                    elseif ($l3Network -ne $null)
                                    {
                                        $logicalNetwork = Get-NCLogicalNetwork -ResourceID "$($node.TenantName)_$($l3Network.GUID)"
                                    }

                                    foreach ($l3IP in $l3IPAddresses)
                                    {
                                        $obj = @{}
                                        $obj.ipAddress = $l3IP.IPAddress
                                        $obj.prefixLength = $l3IP.Mask
                                        $ipAddresses += $obj
                                    }

                                    if ($logicalNetwork -ne $null)
                                    {
                                        $vlanSubnetResourceRef = $logicalNetwork.properties.subnets[0].resourceRef
                
                                        if (![string]::IsNullOrEmpty($vlanSubnetResourceRef))
                                        {
                                            $nwConnections += (New-NCL3Tunnel -ResourceId $connection.TunnelName -OutboundCapacity $connection.OutboundCapacity -InboundCapacity $connection.InboundCapacity `
                                                                            -VlanSubnetResourceRef $vlanSubnetResourceRef -L3IPAddresses $ipAddresses -PrefixLength $connection.PrefixLength `
                                                                            -L3PeerIPAddresses @($connection.PeerIPAddresses) -IPv4Subnets $connection.Routes)
                                        }
                                    }
                                    break
                                }
                        }      
                    }

                    $invalidGwPoolCombination = $false

                    if ($node.GatewayPools.count -gt 1)
                    {
                        # check if the GW Pools violate the condition of "mutually exclusive types"
                        $gwPoolTypes = @()

                        foreach ($gwPool in $node.GatewayPools)
                        {
                            $GatewayPoolObj = Get-NCGatewayPool -ResourceId $gwPool
                            if ($GatewayPoolObj -eq $null)
                            {
                                Write-Warning "Gateway Pool '$gwPool' not found, skipping."
                            }
                            else
                            {
                                if ($GatewayPoolObj.properties.type -eq "All" -or $gwPoolTypes.Contains($GatewayPoolObj.properties.type))
                                {
                                    $invalidGwPoolCombination = $true
                                    break
                                }
                                else
                                {
                                    $gwPoolTypes += $GatewayPoolObj.properties.type
                                    $gwPoolTypes = $gwPoolTypes | sort -Unique
                                }
                            }
                        }

                        if ($gwPoolTypes.count -ne $gateway.GatewayPools.count -or $invalidGwPoolCombination)
                        {
                            Write-Warning "Invalid Gateway Pool combinations specified. Gateway Pool can either be 'All', or a set of mutually exclusive individual types (maximum one each from 'S2sIpSec', 'Gre' or 'Forwarding')"
                            return 
                        }

                    }

                    $virtualGateway = New-NCVirtualGateway -resourceID $node.TenantName -GatewayPools $node.GatewayPools -vNetIPv4SubnetResourceRef $ipv4SubnetResourceRef `
                                                           -NetworkConnections $nwConnections -BgpRouters $bgpRouters -PolicyMaps $policyMaps -RoutingType $node.RoutingType

                }
                TestScript = {
                    $node = $using:node
                    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                    $virtualGateway = Get-NCVirtualGateway -resourceID $node.TenantName

                    return ($virtualGateway -ne $null)
                }
                GetScript = {
                    return @{ result = "" }
                }
            }
      }
}

function CheckCompatibility
{
param(
    [String] $ScriptVer,
    [String] $ConfigVer
)

    write-verbose ("Script version is $ScriptVer and FabricConfig version is $ConfigVer")

    if ($scriptVer -ine $ConfigVer) {
        $error = "The Tenant configuration file which was provided is not compatible with this version of the script. "
        $error += "To avoid compatibility issues, please use only the version of TenantConfig.psd1 which came with this version of the SDNExpressTenant.ps1 script"

        throw $error
    }
}

function CleanupMOFS
{  
    Remove-Item .\DeleteTenantVMs -Force -Recurse 2>$null
    Remove-Item .\CreateTenantVMs -Force -Recurse 2>$null
    Remove-Item .\AttachToVirtualNetwork -Force -Recurse 2>$null
    Remove-Item .\StartVMs -Force -Recurse 2>$null
    Remove-Item .\CreateNetwork -Force -Recurse 2>$null
    Remove-Item .\CreateVIP -Force -Recurse 2>$null
    Remove-Item .\ConfigureVirtualGateway  -Force -Recurse 2>$null
} 

Set-ExecutionPolicy Bypass -Scope Process

write-verbose "Cleaning up previous MOFs"
CleanupMOFS

if ($psCmdlet.ParameterSetName -ne "NoParameters") 
{
    switch ($psCmdlet.ParameterSetName) 
    {
        "ConfigurationFile" {
            Write-Verbose "Using configuration from file [$ConfigurationDataFile]"
            $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
        }
        "ConfigurationData" {
            Write-Verbose "Using configuration passed in from parameter"
            $configdata = $configurationData 
        }
    }

    write-verbose "Checking compatibility of Script and Tenant Config file"
    CheckCompatibility -ScriptVer $ScriptVersion -ConfigVer $configData.AllNodes[0].ConfigFileVersion

    if ($undo.IsPresent -eq $false)
    {
        CreateNetwork -ConfigurationData $ConfigData -verbose
        Start-DscConfiguration -Path .\CreateNetwork -Wait -Force -Verbose

        if ($createVMs)
        {
            CreateTenantVMs -ConfigurationData $ConfigData -verbose
            AttachToVirtualNetwork -ConfigurationData $ConfigData -verbose
            StartVMs -ConfigurationData $ConfigData -verbose

            Start-DscConfiguration -Path .\CreateTenantVMs -Wait -Force -Verbose
            Start-DscConfiguration -Path .\AttachToVirtualNetwork -Wait -Force -Verbose
            Start-DscConfiguration -Path .\StartVMs -Wait -Force -Verbose
        }
    
        $vip_title = "Add a VIP for the Tenant VNET"
        $vgw_title = "Add a S2S Gateway for the Tenant"
        $vip_message = "Do you want to add a Public VIP for the Tenant Virtual Network?"
        $vgw_message = "Do you want to add a S2S Gateway for the Tenant?"
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Add"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skip"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        
        $vip_result = $host.ui.PromptForChoice($vip_title, $vip_message, $options, 0)
        if ($vip_result -eq 0)
        {
            CreateVIP -ConfigurationData $ConfigData -verbose
            Start-DscConfiguration -Path .\CreateVIP -Wait -Force -Verbose
        }    

        $vgw_result = $host.ui.PromptForChoice($vgw_title, $vgw_message, $options, 0)
        if ($vgw_result -eq 0)
        {
            ConfigureVirtualGateway -ConfigurationData $ConfigData -verbose
            Start-DscConfiguration -Path .\ConfigureVirtualGateway -Wait -Force -Verbose
        }    
    }
    else
    {
        $node = $ConfigData.AllNodes[0]
        . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword

        Remove-NCVirtualGateway -ResourceID $node.TenantName

        Remove-NCLoadBalancer -ResourceID "$($node.TenantName)_SLB"

        foreach ($wTNic in $node.NetworkInterfaces.WebTier)
        { Remove-NCNetworkInterface -resourceId $wTNic }

        foreach ($dbTNic in $node.NetworkInterfaces.DBTier)
        { Remove-NCNetworkInterface -resourceId $dbTNic }
    
        Remove-NCVirtualNetwork -resourceID "$($node.TenantName)_$($node.Network.ID)"
        foreach ($subnet in $node.Network.subnets)
        {
            Remove-NCAccessControlList -resourceId $subnet.ACLGUID 
        }
    
        DeleteTenantVMs -ConfigurationData $ConfigData -verbose
        Start-DscConfiguration -Path .\DeleteTenantVMs -Wait -Force -Verbose
    }
    
    write-verbose "Cleaning up MOFs"
    CleanupMOFS
}
