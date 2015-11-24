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


$ConfigData = @{

    AllNodes = 
    @(
        @{ 
            NodeName="*"                                    # * indicates this section applies to all nodes.  Don't change it.

            # This contains the name of the server and share for the deployment infrastructure.  This must be shared with read/write for everyone.
            InstallSrcDir="\\$env:Computername\Deployment"
            
            # Name of the VHDX to use for VM creation. must exist in the images path under InstallSrcDir
            VHDName="10586.0.amd64fre.th2_release.151029-1700_server_ServerDataCenter_en-us_vl.vhdx"
            
            
            # ProductKey can be blank if using a volume license, or you are deploying in eval mode.  (Don't forget to press "skip").
            ProductKey=""
            
            #Source Files
            VHDSrcLocation="Images"                          # Must be under InstallSrcDir

            # Location on the hyper-v host where VMs will be located.  Update to a local path on the hyper-v hosts if local storage, or a UNC path for shared storage                                                        
            VMLocation="D:\VMs"    


            #These are locations that exist on the hyper-v host or in VMs that will get created as needed
            MountDir="C:\Temp"                                                                

            # Local administrator credentials for the newly created VMs.
            LocalAdminUsername = ".\Administrator"
            LocalAdminPassword = 'P@ssw0rd'

            TenantName = "Contoso"
         },
        @{ 
            NodeName="Administrator4"
            Role="HyperVHost"
            VMs=@(
                @{ 
                  # Computer Name to be assigned to the Enterprise GW used for IPSec S2S VPN
                  VMName = "ContosoIPSecGW"
                  PortProfileID = "00000000-0000-0000-0000-000000000000"
                  
                  # Enterprise Gateway's Internet /DMZ IP Address and network details
                  IPAddress   = "10.127.134.115"
                  Mask        = 25
                  Gateway     = "10.127.134.1" # Default Gateway IP Address
                  DNSServers  = @()
                  vSwitchName = "SDNSwitch"    # "<<Switch for internet connection>>"
                  VLANID      = 1001           # VLAN Tag

                  # Enterprise network details behind the Enterprise Gateway                  
                  EntNetwork = @{
                      SwitchName     = "ContosoA"
                      IPAddressSpace = "14.1.10.0"
                      IPAddress      = "14.1.10.1"
                      Mask           = 24
                  }
                  
                  # Enterprise Gateway's IPSec S2S VPN connection details
                  # Make sure you refer to the configuration in SDNExpressTenantGW for correct information
                  VpnConnection = @{
                      TunnelName   = "ToCloud"
                      TunnelType   = "IPSec"
                      Destination  = "10.127.134.180"             # This must be the GatewayPublicIPAddress as specified in GatewayConfig.psd1
                      SharedSecret = "111_aaa"
                      IPv4Subnets  = @("192.168.0.2/32:10")   # This can be all of the HNV Subnets (& route Metric) for static routing; or Cloud Gateway's BGP IP Address (/32) (& route Metric)
                  }

                  # Enterprise Gateway's BGP Router and Cloud Peering details
                  BgpConfig = @{
                      LocalASN = "64521"
                      PeerIP   = "192.168.0.2"                # Cloud BGP Router's BGP IP Address
                      PeerASN  = "64510"                      # Cloud BGP Router's ASN
                  }

                  # Computer is an enterprise Gateway
                  Role = "Gateway"
                },
                @{ 
                  # Computer Name to be assigned to the Enterprise VM behind the IPSec S2S VPN Gateway
                  VMName = "ContosoIPSecVM1"
                  
                  # Enterprise client VM's Internal IP Address and network details
                  IPAddress   = "14.1.10.10"
                  Mask        = 24
                  Gateway     = "14.1.10.1"
                  vSwitchName = "ContosoA"             
                   
                  # Computer is an enterprise client VM
                  Role = "Client"
                }, 
                @{ 
                  # Computer Name to be assigned to the Enterprise GW used for GRE S2S VPN
                  VMName = "ContosoGreGW"
                  PortProfileID = "00000000-0000-0000-0000-000000000000"
                  
                  # Enterprise Gateway's Internet /DMZ IP Address and network details
                  IPAddress   = "10.127.134.120"
                  Mask        = 25
                  Gateway     = "10.127.134.1"
                  DNSServers  = @()
                  vSwitchName = "SDNSwitch"
                  VLANID      = 1001
                  
                  # Enterprise network details behind the Enterprise Gateway                  
                  EntNetwork = @{
                      SwitchName     = "ContosoB"
                      IPAddressSpace = "14.1.20.0"
                      IPAddress      = "14.1.20.1"
                      Mask           = 24
                  }
                  
                  # Enterprise Gateway's GRE S2S VPN connection details
                  VpnConnection = @{
                      TunnelName  = "ToCloud"
                      TunnelType  = "Gre"
                      Destination = "10.127.134.195"             # This must be the IP Address acquired by the "External" Network Adapter of the Cloud Gateway where GRE Tunnel has been provisioned
                      GreKey      = "1234"                   # A unique GRE Key differentiating the tunnel
                      IPv4Subnets = @("192.168.0.2/32:10")   # This can be all of the HNV Subnets (& route Metric) for static routing; or Cloud Gateway's BGP IP Address (/32) (& route Metric)
                  }
                  
                  # Enterprise Gateway's BGP Router and Cloud Peering details
                  BgpConfig = @{
                      LocalASN = "64522"
                      PeerIP   = "192.168.0.2"                # Cloud BGP Router's BGP IP Address
                      PeerASN  = "64510"                      # Cloud BGP Router's ASN
                  }
                  
                  # Computer is an enterprise Gateway
                  Role = "Gateway"
                },
                @{ 
                  # Computer Name to be assigned to the Enterprise GW used for L3 Forwarding
                  VMName = "ContosoL3GW"
                  PortProfileID = "00000000-0000-0000-0000-000000000000"
                  
                  # Enterprise Gateway's DMZ IP Address and network details
                  IPAddress   = "10.127.134.60"              # This must be same as the Peer IP Address specified in L3 Tunnel's configuration (see SDNExpressTunnel)
                  Mask        = 25
                  Gateway     = "10.127.134.1"
                  DNSServers  = @()
                  vSwitchName = "SDNSwitch"
                  VLANID      = 1001
                  
                  # Enterprise Gateway's L3 Forwarding connectiondetails
                  VpnConnection = @{
                      TunnelType  = "L3"
                      Destination = "10.127.134.50"           # This must be same as the IP Address specified in L3 Tunnel's configuration (see SDNExpressTunnel)
                      IPv4Subnets = @("192.168.0.2/32")       # This can be all of the HNV Subnets for static routing; or Cloud Gateway's BGP IP Address (/32)
                  }

                  # Enterprise network details behind the Enterprise Gateway                  
                  EntNetwork = @{
                      SwitchName     = "ContosoC"
                      IPAddressSpace = "14.1.30.0"
                      IPAddress      = "14.1.30.1"
                      Mask           = 24
                  }
                  
                  # Enterprise Gateway's BGP Router and Cloud Peering details
                  BgpConfig = @{
                      LocalASN = "64523"
                      PeerIP   = "192.168.0.2"                # Cloud BGP Router's BGP IP Address
                      PeerASN  = "64510"                      # Cloud BGP Router's ASN
                  }

                  # Computer is an enterprise Gateway
                  Role = "Gateway"
                }
             )
         }
     )
}


Configuration CreateEnterpriseVMs  
{
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
                        $entSwitchName = $using:VMInfo.EntNetwork.SwitchName

                        New-VMSwitch -Name $entSwitchName -SwitchType Internal -ErrorAction Stop
                    }                    
                }
                TestScript = {
                    if ($using:VMInfo.Role -eq "Gateway")
                    {
                        $testVMSwitch = (Get-VMSwitch -Name $using:VMInfo.EntNetwork.SwitchName -ErrorAction Ignore)
                        if ($testVMSwitch -eq $null -or $testVMSwitch.Name -ne $using:VMInfo.EntNetwork.SwitchName)
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
                    New-VM -Generation 2 -Name $using:VMInfo.VMName -Path ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)) -MemoryStartupBytes 4GB -VHDPath ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)+"\"+$using:node.VHDName) -SwitchName $using:VMInfo.vSwitchName
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

Configuration ConfigureEntNetworkAdapter
{
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $GatewayVMList = ($node.VMs | ? {$_.Role -eq "Gateway"})

        foreach ($VMInfo in $GatewayVMList) {
            Script "AddNetworkAdapter_$($VMInfo.VMName)"
            {
                SetScript = {                    
                        $vm = Get-VM -VMName $using:VMInfo.VMName -ErrorAction stop
                        Stop-VM $vm -ErrorAction stop

                        Add-VMNetworkAdapter -VMName $using:VMInfo.VMName -SwitchName $using:VMInfo.EntNetwork.SwitchName -Name "Enterprise" 

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

if ($undo.IsPresent -eq $false) {
    $netinfo = $ConfigData.AllNodes[0].Network

    write-verbose "STAGE 0: Cleaning up previous MOFs"

    Remove-Item .\CreateEnterpriseVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureEntNetworkAdapter -Force -Recurse 2>$null
    Remove-Item .\ConfigureEntGateway -Force -Recurse 2>$null

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
    $store = $($ConfigData.AllNodes[0].VMLocation)
    $allHosts = $($ConfigData.AllNodes | ? {$_.Role -eq "HyperVHost"})

    foreach ($HostNode in $allHosts)
    {
        # Get or create PS Session to the HyperVHost and remove all the VMs
        $HostPSSession = GetOrCreate-PSSession -ComputerName $HostNode.NodeName

        if ($HostPSSession -ne $null)
        {
            $VMList = @()

            # Get all the VMs associated with the host
            foreach ($VMNode in $HostNode.VMs)
            {
                $VMList += $VMNode.VMName
            }

            if ($VMList -ne $null -and $VMList.count -gt 0)
            {
                invoke-command -session $HostPSSession -scriptblock {
                    param ([string[]]$VMList, [bool]$Remove)
                    
                    # Stop VMs
                    foreach ($VMName in $VMList)
                    { Stop-VM -Name $VMName -Force -Confirm:$false }
                    
                    Start-Sleep 5
                    
                    # Remove VMs from Hyper V Manager
                    foreach ($VMName in $VMList)
                    { Remove-VM -Name $VMName -Force -Confirm:$false }
                    
                    Start-Sleep 5

                    # Delete VM files
                    foreach ($VMName in $VMList)
                    { Remove-Item -Path "$($using:store)\$VMName" -Recurse -Force }
                } -ArgumentList @($VMList, [bool]$true)
            }
        }
    }
}
