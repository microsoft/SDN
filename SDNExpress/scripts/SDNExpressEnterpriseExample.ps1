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


Configuration CreateEnterpriseVMs  
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
                    mkdir ($node.MountDir+$($VMInfo.VMName))
                    Write-verbose ("Mounting image: " + $using:node.VMLocation+"\"+$using:vminfo.VMName+"\"+$using:node.VHDName)
                    Mount-WindowsImage -ImagePath ($using:node.VMLocation+"\"+$using:vminfo.VMName+"\"+$using:node.VHDName) -Index 1 -path ($using:node.MountDir+$($VMInfo.VMName))
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
{3}        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>{4}</ComputerName>
            {6}
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

                    $dnsInfo = @"
         <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">{0}</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
"@

                    $dnsList = @()
                    try { $dnsList = $using:vminfo.DNSServers } catch { $dnsList = @() }

                    $finalDnsInfo = ""
                    if ($dnsList -ne $null -and $dnsList.count -gt 0)
                    { $finalDnsInfo = ($dnsInfo -f $($dnsList[0])) }
                    
                    $key = ""
                    if ($($Using:node.productkey) -ne "" ) {
                        $key = "<ProductKey>$($Using:node.productkey)</ProductKey>"
                    }

                    $finalUnattend = ($templateunattend -f $($Using:vminfo.ipaddress), $($Using:vminfo.mask), $($Using:vminfo.gateway), $finalDnsInfo, $($Using:vminfo.vmname), $($Using:Node.LocalAdminPassword), $key)
                    write-verbose $finalunattend
                    write-verbose "Copying unattend to: $dstfile"
                    set-content -value $finalUnattend -path $dstfile
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
            
            Script "DisMountImage_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname)
                    remove-item ($using:node.MountDir+$using:vminfo.vmname) -force -recurse
                }
                TestScript = {
                    if ((get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}) -ne $null) {
                        return $true
                    }
                    $exist = (Test-Path ($using:node.MountDir+$using:vminfo.vmname+"\Windows")) -eq $False

                    return $exist
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            }   

            Script "NewVMSwitch_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    if ($using:VMInfo.Role -eq "Gateway")
                    {
                        $entSwitchName = "$($using:node.TenantName)_$($using:VMInfo.EntNetwork.SwitchName)"

                        New-VMSwitch -Name $entSwitchName -SwitchType Internal -ErrorAction Stop
                    }                    
                }
                TestScript = {
                    if ($using:VMInfo.Role -eq "Gateway")
                    {
                        $entSwitchName = "$($using:node.TenantName)_$($using:VMInfo.EntNetwork.SwitchName)"

                        $testVMSwitch = (Get-VMSwitch -Name $entSwitchName -ErrorAction Ignore)
                        if ($testVMSwitch -eq $null -or $testVMSwitch.Name -ne $entSwitchName)
                        { return $false }
                    }
                    return $true
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            }   

            Script "NewVM_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    if ($using:VMInfo.Role -eq "Gateway")
                    {
                        $switchName = $using:VMInfo.vSwitchName 
                    }
                    else
                    {
                        $switchName = "$($using:node.TenantName)_$($using:VMInfo.vSwitchName)"
                    }

                    New-VM -Generation 2 -Name $using:VMInfo.VMName -Path ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)) -MemoryStartupBytes $using:VMInfo.VMMemory -VHDPath ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)+"\"+$using:node.VHDName) -SwitchName $switchName
                    set-vm  -Name $using:VMInfo.VMName -ProcessorCount 2
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
                         
            Script "SetPort_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"
                    if ($using:VMInfo.Role -eq "Gateway")
                    {
                        Set-VMNetworkAdapterVlan –VMName $using:vminfo.VMName –Access –VlanId $using:vminfo.vlanid
                        set-PortProfileId -resourceID ($using:VMInfo.PortProfileId) -VMName ($using:vmInfo.VMName)
                    }
                }
                TestScript = {
                    $vlans = Get-VMNetworkAdapterVlan –VMName $using:vminfo.VMName
                    if($vlans -eq $null) {
                        return $false
                    } 
                    else {
                        if(($vlans[0] -eq $null) -or ($vlans[0].AccessVlanId -eq $null) -or ($vlans[0].AccessVlanId -ne $using:vminfo.vlanid)) {
                            return $false
                        } 
                        return $true
                    }
                }
                GetScript = {
                    return @{ result = (Get-VMNetworkAdapterVlan –VMName $using:vminfo.VMName)[0] }
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
                    if($vm -ne $null -and $vm[0].State -eq "Running") {
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

Configuration DeleteEnterpriseVMs  {  
    
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

Configuration ConfigureEntNetworkAdapter
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $GatewayVMList = ($node.VMs | ? {$_.Role -eq "Gateway"})

        foreach ($VMInfo in $GatewayVMList) {
            Script "AddNetworkAdapter_$($VMInfo.VMName)"
            {
                SetScript = {                    
                        $vm = Get-VM -VMName $using:VMInfo.VMName -ErrorAction stop
                        $entSwitchName = "$($using:node.TenantName)_$($using:VMInfo.EntNetwork.SwitchName)"

                        Stop-VM $vm -ErrorAction stop

                        Add-VMNetworkAdapter -VMName $using:VMInfo.VMName -SwitchName $entSwitchName -Name "Enterprise" 

                        Start-VM -VMName $using:VMInfo.VMName -ErrorAction stop
                }
                TestScript = {                        
                    $adapters = @(Get-VMNetworkAdapter –VMName $using:VMInfo.VMName -Name "Enterprise" -ErrorAction Ignore)
                    if ($adapters.count -lt 1)
                    { return $false } 
                    else 
                    { return $true }
                }
                GetScript = {
                    return @{ result = @(Get-VMNetworkAdapter –VMName $using:VMInfo.VMName) }
                }
            }
        }
    }

}

Configuration ConfigureEntGateway
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $GatewayVMList = ($node.VMs | ? {$_.Role -eq "Gateway"})

        foreach ($VMInfo in $GatewayVMList) {           

            Script "ConfigureEntNetworkAdapter_$($VMInfo.VMName)"
            {
                SetScript = {   
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    # Get the mac address of enterprise NIC
                    $entNic = (Get-VMNetworkAdapter -VMName $using:VMInfo.VMName -Name Enterprise -ErrorAction Ignore)
                    if ($entNic -ne $null -and $entNic.Name -eq "Enterprise")
                    { $entNicMac = $entNic.MacAddress }

                    Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {                        
                        param ($entNicMac, $IPAddress, $Mask)
                        $adapters = @(Get-NetAdapter)

                        # Enable Ping
                        New-NetFirewallRule -Name Allow_Ping -DisplayName "Allow Ping" -Description "Packet Internet Groper ICMPv4" -Protocol ICMPv4 -IcmpType 8 -Enabled True -Profile Any -Action Allow 

                        foreach ($adapter in $adapters)
                        {
                            $mac = [System.Net.NetworkInformation.PhysicalAddress]::Parse($adapter.MacAddress)
                            if ($mac -eq $entNicMac)
                            {
                                Rename-NetAdapter -Name $adapter.Name -NewName Enterprise -Confirm:$false -ErrorAction stop
                                Remove-NetIPAddress -InterfaceAlias Enterprise -AddressFamily IPv4 -Confirm:$false -ErrorAction ignore
                                New-NetIPAddress -InterfaceAlias Enterprise -AddressFamily IPv4 -IPAddress $IPAddress -PrefixLength $Mask -Confirm:$false -ErrorAction stop
                                break
                            }
                        }
                    } -ArgumentList @($entNicMac, $using:VMInfo.EntNetwork.IPAddress, $using:VMInfo.EntNetwork.Mask)
                }
                TestScript = {
                    $entNic = (Get-VMNetworkAdapter -VMName $using:VMInfo.VMName -Name Enterprise -ErrorAction Ignore)
                    if ($entNic -ne $null -and $entNic.IPAddresses[0] -eq $using:VMInfo.EntNetwork.IPAddress)
                    { return $true }

                    return $false
                }
                GetScript = {
                    return @{ result = $true }
                }
            }

            Script "ConfigureRemoteAccess_$($VMInfo.VMName)"
            {
                SetScript = {   
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                        Add-WindowsFeature -Name RemoteAccess -IncludeAllSubFeature -IncludeManagementTools
                        try { $RemoteAccess = Get-RemoteAccess } catch{$RemoteAccess = $null}
                    
                        $hostname = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).physicalhostname

                        if($RemoteAccess -eq $null -or $RemoteAccess.VpnS2SStatus -ne "Installed")
                        {
                            Write-Verbose "Installing RemoteAccess on $hostname"
                            Install-RemoteAccess -VpnType VpnS2S
                        }

                        # Insert a little sleep for the Remote Access Service to start
                        Start-Sleep 10
                    }
                }
                TestScript = {
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    $result = Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                                    try { $RemoteAccess = Get-RemoteAccess } catch{$RemoteAccess = $null}
                                    if($RemoteAccess -eq $null -or $RemoteAccess.VpnS2SStatus -ne "Installed")
                                    { return $false } 
                                    else 
                                    { return $true }
                                }
                    return $result
                }
                GetScript = {
                    return @{ result = $true }
                }
            }

            Script "ConfigureVpnTunnel_$($VMInfo.VMName)"
            {
                SetScript = {   
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    $vpnTunnel = $using:VMInfo.VpnConnection
                    if ($vpnTunnel -eq $null) {return}

                    if ($vpnTunnel.TunnelType -eq "IPSec")
                    {
                        Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                            param ($TunnelName, $Destination, $SharedSecret, [string[]]$IPv4Subnets)

                            Add-VpnS2SInterface -Name $TunnelName -Destination $Destination -Protocol IKEV2 -AuthenticationMethod PSkOnly -SharedSecret $SharedSecret -CustomPolicy -IPv4Subnet $IPv4Subnets

                        }  -ArgumentList @($vpnTunnel.TunnelName, $vpnTunnel.Destination, $vpnTunnel.SharedSecret, $vpnTunnel.IPv4Subnets)
                    }

                    if ($vpnTunnel.TunnelType -eq "Gre")
                    {
                        Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                            param ($TunnelName, $Destination, $Source, $GreKey, [string[]]$IPv4Subnets)

                            Add-VpnS2SInterface -GreTunnel -Name $TunnelName -Destination $Destination -GreKey $GreKey -IPv4Subnet $IPv4Subnets -SourceIPAddress $Source

                        }  -ArgumentList @($vpnTunnel.TunnelName, $vpnTunnel.Destination, $using:VMInfo.IPAddress, $vpnTunnel.GreKey, $vpnTunnel.IPv4Subnets)
                    }

                    if ($vpnTunnel.TunnelType -eq "L3")
                    {
                        Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                            param ($SourceIPAddress, $DestinationIPAddress,  [string[]]$IPv4Subnets)

                            $dmzNic = $null

                            $adapters = @(Get-NetAdapter)
                            foreach ($adapter in $adapters)
                            {
                                # Enable Forwarding on Network Adapters
                                Set-NetIPInterface -InterfaceIndex $adapter.IfIndex -Forwarding Enabled

                                # check if DMZ Nic and get the Nic Name if yes
                                $dmzIPAddress = Get-NetIPAddress -InterfaceIndex $adapter.IfIndex -AddressFamily IPv4
                                if ($dmzIPAddress.IPAddress -eq $SourceIPAddress)
                                { $dmzNic = $adapter.IfIndex }
                            }

                            if ($dmzNic -ne $null)
                            {
                                # Plumb the route to VNET Subnets on the DMZ Interface
                                foreach ($subnet in $IPv4Subnets)
                                {
                                    New-NetRoute -InterfaceIndex $dmzNic -DestinationPrefix $subnet -NextHop $DestinationIPAddress -Confirm:$false -ErrorAction Ignore
                                }
                            }
                        }  -ArgumentList @($using:VMInfo.IPAddress, $vpnTunnel.Destination, $vpnTunnel.IPv4Subnets)
                    }

                }
                TestScript = {
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    if ($using:VMInfo.VpnConnection -eq $null) {return $true}

                    $result = Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                                    param($TunnelName)
                                                                        
                                    $isTunnel = @(Get-VpnS2SInterface)
                                    if ($isTunnel.count -le 0 -or $isTunnel.Name -notcontains $TunnelName)
                                    { return $false }
                                    else {return $true}
                                    
                                } -ArgumentList @($using:VMInfo.VpnConnection.TunnelName)
                    return $result
                }
                GetScript = {
                    return @{ result = $true }
                }
            }

            Script "ConfigureBgp_$($VMInfo.VMName)"
            {
                SetScript = {   
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    $bgpConfig = $using:VMInfo.BgpConfig

                    if ($bgpConfig -eq $null) {return}

                    Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                            param ($LocalASN, $PeerIP, $PeerASN)

                            # Get the Interface IP Address for BGP Router
                            $entAdapter = (Get-NetIPAddress -InterfaceAlias Enterprise -AddressFamily IPv4 -ErrorAction Ignore)

                            if ($entAdapter -eq $null) {return}
                            $entIPAddress = $entAdapter.IPAddress

                            #check BGP Router
                            $bgpRouter = $null
                            try  {$bgpRouter = (Get-BgpRouter) } catch {$isBgpRouter = $null}

                            if ($bgpRouter -eq $null)
                            {
                                # Add a new BGP Router on this interface
                                Add-BgpRouter -BgpIdentifier $entIPAddress -LocalASN $LocalASN
                            }
                            else
                            {
                                if ($bgpRouter.BgpIdentifier -ne $entIPAddress -or $bgpRouter.LocalASN -ne $LocalASN)
                                {
                                    Remove-BgpRouter -Force
                                    Add-BgpRouter -BgpIdentifier $entIPAddress -LocalASN $LocalASN
                                }
                            }

                            # Add the cloud BGP Router as its peer
                            Add-BgpPeer -Name "CloudPeer_$PeerIP" -LocalIPAddress $entIPAddress -PeerIPAddress $PeerIP -PeerASN $PeerASN -ErrorAction Ignore

                            # Add the Enterprise network for BGP advertisement to peers
                            Add-BgpCustomRoute -Interface Enterprise
                            
                    } -ArgumentList @($bgpConfig.LocalASN, $bgpConfig.PeerIP, $bgpConfig.PeerASN)
                }
                TestScript = {
                    $secPass = ConvertTo-SecureString -String $using:node.LocalAdminPassword -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PsCredential($using:node.LocalAdminUsername, $secPass)

                    if ($using:VMInfo.BgpConfig -eq $null) {return $true}

                    $result = Invoke-Command -VMName $using:VMInfo.VMName -Credential $cred -ScriptBlock {
                                    param([String]$PeerIP)
                                    try { $isBgpPeer = (Get-BgpPeer -PeerName "CloudPeer_$PeerIP") } catch {$isBgpPeer = $null}
                                    if ($isBgpPeer -eq $null)
                                    { return $false }
                                    else {return $true}                                    
                                } -ArgumentList @($using:VMInfo.BgpConfig.PeerIP)
                    return $result
                }
                GetScript = {
                    return @{ result = $true }
                }
            }
        }
    }

}

function GetOrCreate-PSSession
{
    param ([Parameter(mandatory=$false)][string]$ComputerName,
           [PSCredential]$Credential = $null )

    # Get or create PS Session to the HyperVHost
    $PSSessions = @(Get-PSSession | ? {$_.ComputerName -eq $ComputerName})

    foreach($session in $PSSessions)
    {
        if ($session.State -ne "Opened" -and $session.Availability -ne "Available")
        { $session | remove-pssession -Confirm:$false -ErrorAction ignore }
        else
        { return $session }
    }

    # No valid PSSession found, create a new one
    if ($Credential -eq $null)
    { return (New-PSSession -ComputerName $ComputerName) }
    else
    { return (New-PSSession -ComputerName $ComputerName -Credential $Credential) }
}

function WaitForComputerToBeReady
{
    param(
        [Object] $ConfigData,
        [string[]] $ComputerRole,
        [Switch]$CheckPendingReboot
    )

    $allHosts = @($configdata.AllNodes | ? {$_.Role -eq "HyperVHost"})

    foreach ($HostNode in $allHosts) {
        write-verbose "Attempting to contact $($HostNode.NodeName)"
        $HostPSSession = GetOrCreate-PSSession -ComputerName ($HostNode.NodeName)
        
        if ($HostPSSession -ne $null) {
            $password = ConvertTo-SecureString -String $configData.AllNodes[0].LocalAdminPassword -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PsCredential($configData.AllNodes[0].LocalAdminUsername, $password)

            # Get all the Enterprise GW VMs on this host
            $gatewayVMs = @($HostNode.VMs | ? {$_.Role -in $ComputerRole})

            foreach ($vmNode in $gatewayVMs)
            {
                write-verbose "Waiting for $($vmNode.VMName) to become active."
        
                $continue = $true
                while ($continue) {
                    try {
                        $result = ""

                        $result = Invoke-Command -Session $HostPSSession -ScriptBlock {
                                        param ($credential , $VMName)
                            
                                        if ($CheckPendingReboot.IsPresent) {                        
                                            $result = Invoke-Command -VMName $VMName -Credential $credential -ScriptBlock { 
                                                if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                                                    "Reboot pending"
                                                } 
                                                else {
                                                    hostname 
                                                }
                                            } -ErrorAction ignore
                                        }
                                        else {
                                            $result = Invoke-Command -VMName $VMName -Credential $credential -ScriptBlock { hostname }  -ErrorAction ignore
                                        }

                                        return $result
                                } -ArgumentList @($credential, $vmNode.VMName)

                        if ($result -eq $vmNode.VMName) {
                            $continue = $false
                            break
                        }
                        if ($result -eq "Reboot pending") {
                            write-verbose "Reboot pending on $($vmNode.VMName).  Waiting for restart."
                        }
                    }
                    catch 
                    {
                    }
                    write-verbose "$($vmNode.VMName) is not active, sleeping for 30 seconds."
                    sleep 30
                }
                write-verbose "$($vmNode.VMName) IS ACTIVE.  Continuing with deployment."
            }
        }
    }
}



function CleanupMOFS
{  
    Remove-Item .\CreateEnterpriseVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureEntNetworkAdapter -Force -Recurse 2>$null
    Remove-Item .\ConfigureEntGateway -Force -Recurse 2>$null
    Remove-Item .\DeleteEnterpriseVMs -Force -Recurse 2>$null
} 

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

    if ($undo.IsPresent -eq $false){
        write-verbose "STAGE 0.5: Compile DSC resources"
        ConfigureEntNetworkAdapter -ConfigurationData $ConfigData -verbose
        ConfigureEntGateway -ConfigurationData $ConfigData -verbose

        if ($createVMs)
        {
            CreateEnterpriseVMs -ConfigurationData $ConfigData -verbose
            write-verbose "STAGE 1.0: Create Enterprise VMs"
            Start-DscConfiguration -Path .\CreateEnterpriseVMs -Wait -Force -Verbose -Erroraction Stop
        }

        WaitForComputerToBeReady -ConfigData $ConfigData -ComputerRole @("Gateway") 

        write-verbose "STAGE 2.0: Add required network adapters to Enterprise Edge Gateways"
        Start-DscConfiguration -Path .\ConfigureEntNetworkAdapter -Wait -Force -Verbose -Erroraction Stop

        WaitForComputerToBeReady -ConfigData $ConfigData -ComputerRole @("Gateway") 

        write-verbose "STAGE 3.0: Configure Enterprise Gateways with VPN Tunnels, BGP Routing"
        Start-DscConfiguration -Path .\ConfigureEntGateway -Wait -Force -Verbose -Erroraction Stop
    }
    else 
    {
        DeleteEnterpriseVMs -ConfigurationData $ConfigData -verbose
        Start-DscConfiguration -Path .\DeleteEnterpriseVMs -Wait -Force -Verbose
    }
}
