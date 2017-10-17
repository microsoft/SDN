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
<#
.SYNOPSIS 
    Deploys and configures the Microsoft SDN infrastructure, 
    including creation of the network controller, Software Load Balancer MUX 
    and gateway VMs.  Then the VMs and Hyper-V hosts are configured to be 
    used by the Network Controller.  When this script completes the SDN 
    infrastructure is ready to be fully used for workload deployments.
.EXAMPLE
    .\SDNExpress -ConfigurationDataFile .\MyConfig.psd1
    Reads in the configuration from a PSD1 file that contains a hash table 
    of settings data.
.EXAMPLE
    .\SDNExpress -ConfigurationData $MyConfigurationData
    Uses the hash table that is passed in as the configuration data.  This 
    parameter set is useful when programatically generating the 
    configuration data.
.NOTES
    Prerequisites:
    * All Hyper-V hosts must have Hyper-V enabled and the Virtual Switch 
    already created.
    * All Hyper-V hosts must be joined to Active Directory.
    * The physical network must be preconfigured for the necessary subnets and 
    VLANs as defined in the configuration data.
    * The deployment computer must have the deployment directory shared with 
    Read/Write permissions for Everyone.
#>

[CmdletBinding(DefaultParameterSetName="NoParameters")]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null
)    

# Script version, should be matched with the config files
$ScriptVersion = "1.1"

Configuration SetHyperVWinRMEnvelope
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        Script SetWinRmEnvelope
        {                                      
            SetScript = {
                write-verbose "Settign WinRM Envelope size."
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000
            }
            TestScript = {
                return ((Get-Item WSMan:\localhost\MaxEnvelopeSizekb).Value -ge 7000)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        Script AddNetworkVirtualizationRole
        {                                      
            SetScript = {
                add-windowsfeature NetworkVirtualization -IncludeAllSubFeature -IncludeManagementTools -Restart
            }
            TestScript = {
                $status = get-windowsfeature NetworkVirtualization
                return ($status -eq $null -or $status.Installed)
            }
            GetScript = {
                return @{ result = $true }
            }
        } 

    }
}

Configuration DeployVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        foreach ($VMInfo in $node.VMs) {
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

            File "CheckTempDirectory_$($VMInfo.VMName)"
            {
                Type = "Directory"
                Ensure = "Present"
                Force = $True
                DestinationPath = ($node.MountDir+$($VMInfo.VMName))
            }

            Script "MountImage_$($VMInfo.VMName)"
            {                                      
                SetScript = {
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
                    $unattendfile = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
{0}
            </Interfaces>
        </component>
         <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
{1}
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Identification>
                <Credentials>
                    <Domain>{3}</Domain>
                    <Password>{5}</Password>
                    <Username>{4}</Username>
                </Credentials>
                <JoinDomain>{3}</JoinDomain>
            </Identification>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>{2}</ComputerName>
            {7}
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>{6}</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
                <DomainAccounts>
                    <DomainAccountList wcm:action="add">
                        <DomainAccount wcm:action="add">
                            <Name>{4}</Name>
                            <Group>Administrators</Group>
                        </DomainAccount>
                        <Domain>{3}</Domain>
                    </DomainAccountList>
                </DomainAccounts>
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

                    $interfacetemplate = @"
                 <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <Identifier>{3}</Identifier>
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
"@
                $dnsinterfacetemplate = @"
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                       {1}
                    </DNSServerSearchOrder>
                    <Identifier>{0}</Identifier>
                    <EnableAdapterDomainNameRegistration>{2}</EnableAdapterDomainNameRegistration>
                </Interface>
"@

                    $dstfile = $using:node.MountDir+$($Using:VMInfo.VMName)+"\unattend.xml"

                    $count = 1
                    $allnics = ""
                    $dnsinterfaces = ""

                    foreach ($nic in $using:vminfo.Nics) {
                        $alldns = ""
                        if (![string]::IsNullOrEmpty($nic.LogicalNetwork)) {
                            foreach ($ln in $using:node.LogicalNetworks) {
                                if ($ln.Name -eq $nic.LogicalNetwork) {
                                    break
                                }
                            }

                            #TODO: Right now assumes there is one subnet.  Add code to find correct subnet given IP.
                        
                            $sp = $ln.subnets[0].AddressPrefix.Split("/")
                            $mask = $sp[1]

                            #TODO: Add in custom routes since multi-homed VMs will need them.
                            $mac = $nic.MacAddress
                            $gateway = $ln.subnets[0].gateways[0]
                            $allnics += $interfacetemplate -f $nic.IPAddress, $mask, $gateway, $mac.ToUpper()

                            foreach ($dns in $ln.subnets[0].DNS) {
                                $alldns += '<IpAddress wcm:action="add" wcm:keyValue="{1}">{0}</IpAddress>' -f $dns, $count++
                            }

                            if ($ln.subnets[0].DNS -eq $null -or $ln.subnets[0].DNS.count -eq 0) {
                                $dnsregistration = "false"
                            } else {
                                $dnsregistration = "true"
                            }

                            $dnsinterfaces += $dnsinterfacetemplate -f $mac, $alldns, $dnsregistration
                        }
                    }
                    
                    $key = ""
                    if ($($Using:node.productkey) -ne "" ) {
                        $key = "<ProductKey>$($Using:node.productkey)</ProductKey>"
                    }
                    $finalUnattend = ($unattendfile -f $allnics, $dnsinterfaces, $($Using:vminfo.vmname), $($Using:node.fqdn), $($Using:node.DomainJoinUsername), $($Using:node.DomainJoinPassword), $($Using:node.LocalAdminPassword), $key )
                    write-verbose $finalunattend
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
                    $mountpath = $using:node.MountDir+$($using:VMInfo.VMName)

                    Write-verbose "Dis-Mounting image [$mountpath]"
                    DisMount-WindowsImage -Save -path $mountpath
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
            
            Script "NewVM_$($VMInfo.VMName)"
            {                                      
                SetScript = {
                    $vminfo = $using:VMInfo

                    write-verbose "Creating new VM"
                    New-VM -Generation 2 -Name $VMInfo.VMName -Path ($using:node.VMLocation+"\"+$($VMInfo.VMName)) -MemoryStartupBytes $VMInfo.VMMemory -VHDPath ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)+"\"+$using:node.VHDName) -SwitchName $using:node.vSwitchName

                    write-verbose "Setting processor count"
                    set-vm -Name $VMInfo.VMName -processorcount 8

                    write-verbose "renaming default network adapter"
                    get-vmnetworkadapter -VMName $VMInfo.VMName | rename-vmnetworkadapter -newname $using:VMInfo.Nics[0].Name

                    $mac = $VMInfo.Nics[0].MACAddress -replace '-',''
                    set-vmnetworkadapter -VMName $VMInfo.VMName -VMNetworkAdapterName $using:VMInfo.Nics[0].Name -StaticMacAddress $mac

                    write-verbose "Adding $($VMInfo.Nics.Count-1) additional adapters"
                    
                    for ($i = 1; $i -lt $VMInfo.Nics.Count; $i++) {
                        write-verbose "Adding adapter $($VMInfo.Nics[$i].Name)"
                        $mac = $VMInfo.Nics[$i].MACAddress -replace '-',''
                        Add-VMNetworkAdapter -VMName $VMInfo.VMName -SwitchName $using:node.vSwitchName -Name $VMInfo.Nics[$i].Name -StaticMacAddress $mac
                    }

                    write-verbose "Finished creating VM"
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

            foreach ($nic in $vminfo.Nics) {
                Script "SetVlan_$($VMInfo.VMName)_$($nic.IPAddress)"
                {                                      
                    SetScript = {
                        $nic = $using:nic
                        $lns = $using:node.logicalnetworks
                        $vminfo = $using:vminfo

                        write-verbose "finding logical network"

                        foreach ($lntest in $lns) {
                            if ($lntest.Name -eq $nic.LogicalNetwork) {
                                write-verbose "found logical network"
                                $ln = $lntest 
                            }
                        }

                        write-verbose "Setting VLAN [$($vminfo.VMname)] [$($nic.Name)] [$($ln.subnets[0].vlanid)]"

                        #todo: assumes one subnet.
                        Set-VMNetworkAdapterIsolation -vmname $vminfo.VMname -vmnetworkadaptername $nic.Name -AllowUntaggedTraffic $true -IsolationMode VLAN -defaultisolationid $ln.subnets[0].vlanid
                    }
                    TestScript = {
                        $vlans = Get-VMNetworkAdapterIsolation -VMName $using:vminfo.VMName -vmnetworkadaptername $nic.Name
                        if($vlans -eq $null) {
                            return $false
                        } 
                        else {
                            foreach ($ln in $using:node.LogicalNetworks) {

                                if ($ln.Name -ieq $using:nic.LogicalNetwork) {
                                    break
                                }
                            }
                            
                            if(($vlans[0] -eq $null) -or ($vlans[0].defaultisolationid -eq $null) -or ($vlans[0].defaultisolationid -ne $ln.subnets[0].vlanid)) {
                                return $false
                            } 
                            return $true
                        }
                    }
                    GetScript = {
                        return @{ result = (Get-VMNetworkAdapterIsolation -VMName $using:vminfo.VMName)[0] }
                    }
                }

                Script "SetPortProfile_$($VMInfo.VMName)_$($nic.IPAddress)"
                {                                      
                    SetScript = {
                        $nic = $using:nic
                        $vminfo = $using:vminfo

                        write-verbose "Setting Port Profile [$($vminfo.VMname)] [$($nic.Name)] to [$([System.Guid]::Empty.guid)],[$($nic.PortProfileData)]"

                        $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"

                        $vmNic = Get-VMNetworkAdapter -VMName $vminfo.VMname -Name $nic.Name

                        Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic | remove-vmswitchExtensionPortFeature

                        $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
                        
                        $portProfileDefaultSetting.SettingData.ProfileId = "{$([System.Guid]::Empty.guid)}"
                        $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
                        $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
                        $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
                        $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
                        $portProfileDefaultSetting.SettingData.VendorId = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"
                        $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
                        $portProfileDefaultSetting.SettingData.ProfileData = $nic.PortProfileData
                        
                        Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vmNic | out-null
                        write-verbose "Adding port feature complete"
                    }
                    TestScript = {
                        return $false
                    }
                    GetScript = {
                        return @{ result = $true }
                    }
                }
            }

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

Configuration ConfigureNetworkControllerVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.Role -eq "NetworkController"}.NodeName
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        Script DisableIPv6
        {
            setscript = {
                reg add hklm\system\currentcontrolset\services\tcpip6\parameters /v DisabledComponents /t REG_DWORD /d 255 /f
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script SetWinRmEnvelope
        {                                      
            SetScript = {
                Set-Item WSMan:\localhost\Shell\MaxConcurrentUsers -Value 100
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000
            }
            TestScript = {
                return ((Get-Item WSMan:\localhost\MaxEnvelopeSizekb).Value -ge 7000)
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script SetAllHostsTrusted
        {                                      
            SetScript = {
                set-item wsman:\localhost\Client\TrustedHosts -value * -Force
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script Firewall-SMB
        {                                      
            SetScript = {
                Enable-netfirewallrule "FPS-SMB-In-TCP"
                Enable-netfirewallrule "FPS-SMB-Out-TCP"
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }  

        Script Firewall-REST
        {                                      
            SetScript = {
                new-netfirewallrule -Name "Firewall-REST" -DisplayName "Network Controller Host Agent REST" -Group "NcHostAgent" -Enabled True -direction Inbound -LocalPort 80 -action Allow -protocol "TCP"
            }
            TestScript = {
                return (get-netfirewallrule | where {$_.Name -eq "Firewall-REST"}) -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }        
        Script Firewall-OVSDB
        {                                      
            SetScript = {
                new-netfirewallrule -Name "Firewall-OVSDB" -DisplayName "Network Controller Host Agent OVSDB" -Group "NcHostAgent" -Enabled True -direction Inbound -LocalPort 6640 -action Allow -protocol "TCP"
            }
            TestScript = {
                return (get-netfirewallrule | where {$_.Name -eq "Firewall-OVSDB"}) -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }        

        Script AddNetworkControllerRole
        {                                      
            SetScript = {
                add-windowsfeature NetworkController -IncludeAllSubFeature -IncludeManagementTools -Restart
            }
            TestScript = {
                $status = get-windowsfeature NetworkController
                return ($status.Installed)
            }
            GetScript = {
                return @{ result = $true }
            }
        } 
    }
}

Configuration ConfigureMuxVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.Role -eq "SLBMUX"}.NodeName
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        Script DisableIPv6
        {
            setscript = {
                reg add hklm\system\currentcontrolset\services\tcpip6\parameters /v DisabledComponents /t REG_DWORD /d 255 /f
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        script SetEncapOverheadPropertyOnNic
        {
            setscript = {
                Write-Verbose "Setting EncapOverhead property of the HNVPA NIC on the SLB MUX machine"

                $nics = Get-NetAdapter -ErrorAction Ignore
                if(($nics -eq $null) -or ($nics.count -eq 0))
                {
                    throw "Failed to get available network adapters on the SLB MUX machine"
                }

                Write-Verbose "Found $($nics.count) Network Adapters: $($nics.Name)"

                $propValue = 160
                $foundNic = $false

                foreach($nic in $nics)
                {
                    Write-Verbose "Checking if adapter $($nic.Name) has the HNVPA MAC: $($using:node.HnvPaMac)"

                    if($nic.MacAddress -ieq $using:node.HnvPaMac)
                    {
                        Write-Verbose "Adapter $($nic.Name) has the HNVPA MAC. Checking if EncapOverhead property is correctly set"
    
                        $nicProperty = Get-NetAdapterAdvancedProperty -Name $nic.Name -AllProperties -RegistryKeyword *EncapOverhead -ErrorAction Ignore
                        if($nicProperty -eq $null)
                        {
                            Write-Verbose "The *EncapOverhead property has not been added to the NIC $($nic.Name) yet. Adding the property and setting it to $($propValue)"
                            New-NetAdapterAdvancedProperty -Name $nic.Name -RegistryKeyword *EncapOverhead -RegistryValue $propValue
                            Write-Verbose "Added the *EncapOverhead property to the NIC $($nic.Name)."
                        }
                        else
                        {
                            Write-Verbose "The *EncapOverhead property has been added to the NIC $($nic.Name) but the value is not the expected $($propValue), so setting it to $($propValue)."
                            Set-NetAdapterAdvancedProperty -Name $nic.Name -AllProperties -RegistryKeyword *EncapOverhead -RegistryValue $propValue
                            Write-Verbose "Changed the *EncapOverhead property value to $($propValue)."
                        }
                
                        Start-Sleep -Seconds 60  # Give NLA some time to detect network profile and let tracing gather enough info.

                        $foundNic = $true
                        break
                    }
                }

                if (!$foundNic)
                {
                    throw "No adapter with the HNVPA MAC $($using:node.HnvPaMac) was found"
                }
            }
            TestScript = {
                Write-Verbose "Checking EncapOverhead property of the HNVPA NIC on the SLB MUX machine"
                $nics = Get-NetAdapter -ErrorAction Ignore
                if(($nics -eq $null) -or ($nics.count -eq 0))
                {
                    Write-verbose "Failed to get available network adapters on the SLB MUX machine"
                    return $false
                }

                Write-Verbose "Found $($nics.count) Network Adapters: $($nics.Name)"

                foreach($nic in $nics)
                {
                    Write-Verbose "Checking if adapter $($nic.Name) has the HNVPA MAC: $($using:node.HnvPaMac)"

                    if($nic.MacAddress -ieq $using:node.HnvPaMac)
                    {
                        Write-Verbose "Adapter $($nic.Name) has the HNVPA MAC. Checking if EncapOverhead property is correctly set"
    
                        $nicProperty = Get-NetAdapterAdvancedProperty -Name $nic.Name -AllProperties -RegistryKeyword *EncapOverhead -ErrorAction Ignore
                        if($nicProperty -eq $null)
                        {
                            Write-Verbose "The *EncapOverhead property has not been added to the NIC $($nic.Name)"
                            return $false
                        }

                        $propValue = 160
                        if(($nicProperty.RegistryValue -eq $null) -or ($nicProperty.RegistryValue[0] -ne $propValue))
                        {
                            Write-Verbose "The value for the *EncapOverhead property on the NIC is not set to $($propValue)"
                            return $false
                        }

                        Write-Verbose "Adapter $($nic.Name) has the EncapOverhead property correctly set to $($propValue)"
                        return $true
                    }
                }

                Write-Verbose "No adapter with the HNVPA MAC $($using:node.HnvPaMac) was found"
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script AddMuxRole
        {                                      
            SetScript = {
                add-windowsfeature SoftwareLoadBalancer -Restart
            }
            TestScript = {
                $status = get-windowsfeature SoftwareLoadBalancer
                return ($status.Installed)
            }
            GetScript = {
                return @{ result = $true }
            }
        } 

        Script ForceRestart
        {                                      
            SetScript = {                
                Restart-computer -Force -Confirm:$false -AsJob
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

Configuration CreateControllerCert
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        Script CreateRESTCert
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $nccertSubject = "$($using:node.NetworkControllerRestName)"
                $nccertname = $nccertSubject

                write-verbose "Generating self signed cert for $($using:node.NetworkControllerRestName)."
                GenerateSelfSignedCertificate $nccertSubject

                $cn = "$($nccertSubject)".ToUpper()
                $cert = GetCertificate $cn
                GivePermissionToNetworkService $Cert[0]
                write-verbose "Exporting certificate to: [c:\$nccertname]"
                [System.io.file]::WriteAllBytes("c:\$nccertname.pfx", $cert.Export("PFX", "secret"))
                Export-Certificate -Type CERT -FilePath "c:\$nccertname" -cert $cert
                write-verbose "Adding to local machine store."
                AddCertToLocalMachineStore "c:\$nccertname" "Root"
            } 
            TestScript = {
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                
                write-verbose ("Checking network controller cert configuration.")
                $cert = get-childitem "Cert:\localmachine\my" -ErrorAction Ignore | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\my cert not found.")
                    return $false
                }
                
                $nccertname = "$($using:node.NetworkControllerRestName).pfx"
                write-verbose ("cert:\localmachine\my cert found.  Checking for c:\$nccertname.")
                $certfile = get-childitem "c:\$nccertname"  -ErrorAction Ignore
                if ($certfile -eq $null) {
                    write-verbose ("$nccertname not found.")
                    return $false
                }
                
                write-verbose ("$nccertname found.  Checking for cert in cert:\localmachine\root.")
                $cert = get-childitem "Cert:\localmachine\root\$($cert.thumbprint)" -ErrorAction Ignore
                if ($cert -eq $null) {
                    write-verbose ("Cert in cert:\localmachine\root not found.")
                    return $false
                }
                write-verbose ("Cert found in cert:\localmachine\root.  Cert creation not needed.")
                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        Script CreateNCVmCerts
        {
            SetScript = {
                write-verbose ("CreateNCVmCerts")
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $allnodes = $using:AllNodes
                $hyperVHosts = $allnodes.Where{$_.Role -eq "NetworkController"}

                foreach ($host in $hyperVHosts) {
                    write-verbose ("Creating Certs on host $($host.nodename)")
                    $cn = "$($host.nodename).$($host.FQDN)".ToUpper()
                    $nccertname = "$($using:host.NetworkControllerRestName)"
                    $certName = "$($host.NodeName).$($nccertname)"                    
                    write-verbose ("Creating Cert $($cn)")
                    $cert = GetCertificate $cn $true

                    $certPwd = $host.HostPassword
                    write-verbose "Exporting PFX certificate to: [c:\$nccertname]"
                    [System.io.file]::WriteAllBytes("c:\$($certName).pfx", $cert.Export("PFX", $certPwd))
                    write-verbose ("Export CER")
                    Export-Certificate -Type CERT -FilePath "c:\$($certName)" -cert $cert
                    del cert:\localmachine\my\$($cert.Thumbprint)
                }
            } 
            TestScript = {
                write-verbose ("CreateNCVmCerts test.")
                
                $allnodes = $using:AllNodes
                $hyperVHosts = $allnodes.Where{$_.Role -eq "NetworkController"}
                
                foreach ($host in $hyperVHosts) {
                    $nccertname = "$($using:host.NetworkControllerRestName)"
                    $certName = "$($host.NodeName).$($nccertname)"
                    
                    write-verbose ("Checking for c:\$($certName).pfx")
                    $certfile = get-childitem "c:\$($certName).pfx"  -ErrorAction Ignore
                    if ($certfile -eq $null) {
                        write-verbose ("c:\$($certName).pfx not found.")
                        return $false
                    }
                    
                    write-verbose ("Checking for c:\$($certName)")
                    $certfile = get-childitem "c:\$($certName)"  -ErrorAction Ignore
                    if ($certfile -eq $null) {
                        write-verbose ("c:\$($certName) not found.")
                        return $false
                    }
                    write-verbose ("Cert files found.  Cert creation not needed.")
                }

                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script CreateHostCerts
        {
            SetScript = {
                write-verbose ("CreateHostCerts")
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $allnodes = $using:AllNodes
                $hyperVHosts = $allnodes.Where{$_.Role -eq "HyperVHost"}

                foreach ($host in $hyperVHosts) {
                    write-verbose ("Creating Certs on host $($host.nodename)")
                    $cn = "$($host.nodename).$($host.FQDN)".ToUpper()
                    write-verbose ("Creating Cert $($cn)")
                    $cert = GetCertificate $cn $true

                    $certPwd = $host.HostPassword
                    $certPwdSec = ConvertTo-SecureString -String $certPwd -Force -AsPlainText
                    write-verbose ("Export PFX")
                    Export-PfxCertificate -FilePath "c:\$($cn).pfx" -Force -Cert $cert -Password $certPwdSec
                    write-verbose ("Export CER")
                    Export-Certificate -Type CERT -FilePath "c:\$($cn).cer" -cert $cert
                    del cert:\localmachine\my\$($cert.Thumbprint)
                }
            } 
            TestScript = {
                write-verbose ("CreateHostCerts test.")
                
                $allnodes = $using:AllNodes
                $hyperVHosts = $allnodes.Where{$_.Role -eq "HyperVHost"}
                
                foreach ($host in $hyperVHosts) {
                    $certName = "$($host.nodename).$($host.FQDN)".ToUpper()
                    
                    write-verbose ("Checking for c:\$($certName).pfx")
                    $certfile = get-childitem "c:\$($certName).pfx"  -ErrorAction Ignore
                    if ($certfile -eq $null) {
                        write-verbose ("c:\$($certName).pfx not found.")
                        return $false
                    }
                    
                    write-verbose ("Checking for c:\$($certName).cer")
                    $certfile = get-childitem "c:\$($certName).cer"  -ErrorAction Ignore
                    if ($certfile -eq $null) {
                        write-verbose ("c:\$($certName).cer not found.")
                        return $false
                    }
                    write-verbose ("Cert files found.  Cert creation not needed.")
                }

                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration InstallControllerCerts
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.Role -eq "NetworkController"}.NodeName
    {
        Script InstallMyCerts
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $certpath = "$($using:node.installsrcdir)\$($using:node.certfolder)"
                $nccertname = "$($using:node.NetworkControllerRestName)"

                write-verbose "Adding $($nccertname) to local machine store from $($certpath)"
                AddCertToLocalMachineStore "$certpath\$nccertname.pfx" "My" "secret"
                AddCertToLocalMachineStore "$certpath\$nccertname.pfx" "Root" "secret"
                
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                write-verbose "Getting Cert $($cn)"
                $cert = get-childitem "Cert:\localmachine\My" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}    
                if ($cert -eq $null) {
                    write-error ("Cert $cn in cert:\localmachine\My not found.")
                }
                write-verbose "Giving Permission to Network Service $($cert.Thumbprint)"
                GivePermissionToNetworkService $cert
                
                write-verbose "Getting Cert $($cn)"
                $cert = get-childitem "Cert:\localmachine\Root" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}    
                if ($cert -eq $null) {
                    write-error ("Cert $cn in cert:\localmachine\Root not found.")
                }
                write-verbose "Giving Permission to Network Service $($cert.Thumbprint)"
                GivePermissionToNetworkService $cert

                $ncVmCertname = "$($using:node.NodeName).$($nccertname)"
                $certPwd = "$($using:node.HostPassword)"
                write-verbose "Adding $($ncVmCertname) to local machine store."
                AddCertToLocalMachineStore "$certpath\$ncVmCertname.pfx" "My" $certPwd
            } 
            TestScript = {
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()

                write-verbose ("Checking for cert $($cn) in cert:\localmachine\my")
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                if ($cert -eq $null) {
                    write-verbose ("Cert in cert:\localmachine\my not found.")
                    return $false
                }
                
                $cn = "$($using:node.nodename).$($using:node.fqdn)".ToUpper()

                write-verbose ("Checking for cert $($cn) in cert:\localmachine\my")
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                if ($cert -eq $null) {
                    write-verbose ("Cert in cert:\localmachine\my not found.")
                    return $false
                }
                
                write-verbose ("Certs found in cert:\localmachine\my.  Cert creation not needed.")
                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script InstallRootCerts
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $certpath = "$($using:node.installsrcdir)\$($using:node.certfolder)"
                $nccertname = "$($using:node.NetworkControllerRestName)"

                foreach ($othernode in $using:allnodes) {
                    if ($othernode.Role -eq "NetworkController") {
                       # if ($othernode.NodeName -ne $using:node.nodename) {
                            $cn = "$($othernode.nodename).$($using:node.fqdn)".ToUpper()

                            write-verbose ("Checking $cn in cert:\localmachine\root")
                            $cert = get-childitem "Cert:\localmachine\root" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}

                            if ($cert -eq $null) {
                                $certfullpath = "$certpath\$($othernode.nodename).$($nccertname).pfx"
                                write-verbose "Adding $($cn) cert to root store from $certfullpath"
                                $certPwd = $using:node.HostPassword
                                AddCertToLocalMachineStore $certfullpath "Root" $certPwd
                            }
                       # } 
                    }
                }
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

Configuration EnableNCTracing
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.Role -eq "NetworkController"}.NodeName
    {
        Script StartNCTracing
        {
            SetScript = {
                $date = Get-Date
                $tracefile = "c:\networktrace-$($date.Year)-$($date.Month)-$($date.Day)-$($date.Hour)-$($date.Minute)-$($date.Second)-$($date.Millisecond).etl"

                New-NetEventSession -Name NCTrace -CaptureMode SaveToFile -LocalFilePath $tracefile
                Add-NetEventProvider "{80355850-c8ed-4336-ade2-6595f9ca821d}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{22f5dddb-329e-4f87-a876-56471886ba81}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{d2a364bd-0c3f-428a-a752-db983861673f}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{d304a717-2718-4580-a155-458f8ac12091}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{90399F0C-AE84-49AF-B46A-19079B77B6B8}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{6c2350f8-f827-4b74-ad0c-714a92e22576}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{ea2e4e95-2b14-462d-bb78-dee94170804f}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{d79293d5-78ba-4687-8cef-4492f1e3abf9}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{77494040-1F07-499D-8553-03DB545C031C}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{5C8E3932-E6DF-403D-A3A3-EC6BF6D7977D}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{A1EA8728-5700-499E-8FDD-64954D8D3578}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{8B0C6DD7-B6D8-48C2-B83E-AFCBBA5B57E8}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{C755849B-CF02-4F21-B82B-D92D26A91069}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{f1107188-2054-4758-8a89-8fe5c661590f}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{93e14ac2-289b-45b7-b654-db51e293bf52}" -Level 5 -SessionName NCTrace 
                Add-NetEventProvider "{eefaa5fb-5f0b-46a5-a3f7-0e06bc972c30}" -Level 5 -SessionName NCTrace
                Start-NetEventSession NCTrace
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

Configuration DisableNCTracing
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.Role -eq "NetworkController"}.NodeName
    {
        Script StopNCTracing
        {
            SetScript = {
                stop-neteventsession NCTrace
                remove-neteventsession NCTrace
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

Configuration CopyToolsAndCerts
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    
    Node $AllNodes.Where{$_.Role -in @("HyperVHost", "NetworkController")}.NodeName
    {
        if (![String]::IsNullOrEmpty($node.ToolsSrcLocation)) {
            File ToolsDirectory
            {
                Type = "Directory"
                Ensure = "Present"
                Force = $True
                Recurse = $True
                MatchSource = $True
                SourcePath = $node.InstallSrcDir+"\"+$node.ToolsSrcLocation
                DestinationPath = $node.ToolsLocation
            }  

            File CertHelpersScript
            {
                Type = "File"
                Ensure = "Present"
                Force = $True
                MatchSource = $True
                SourcePath = $node.InstallSrcDir+"\Scripts\CertHelpers.ps1"
                DestinationPath = $node.ToolsLocation+"\CertHelpers.ps1"
            }

            File RestWrappersScript
            {
                Type = "File"
                Ensure = "Present"
                Force = $True
                MatchSource = $True
                SourcePath = $node.InstallSrcDir+"\Scripts\NetworkControllerRESTWrappers.ps1"
                DestinationPath = $node.ToolsLocation+"\NetworkControllerRESTWrappers.ps1"
            }            
        }

        if (![String]::IsNullOrEmpty($node.CertFolder)) {
            File CertsDirectory
            {
                Type = "Directory"
                Ensure = "Present"
                Force = $True
                Recurse = $True
                MatchSource = $True
                SourcePath = $node.InstallSrcDir+"\"+$node.CertFolder
                DestinationPath = $env:systemdrive+"\"+$node.CertFolder
            }        
        }
    }
}

Configuration ConfigureNetworkControllerCluster
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        Script CreateControllerCluster
        {                                      
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"
                
                write-verbose ("Set CreateControllerCluster")
                $pwd = ConvertTo-SecureString $using:node.NCClusterPassword -AsPlainText -Force; 
                $cred = New-Object System.Management.Automation.PSCredential $using:node.NCClusterUsername, $pwd;
                
                $nc = try { get-networkcontroller -Credential $cred } catch { }
                if ($nc -ne $null) {
                    write-verbose ("Attempting cleanup of network controller.")
                    $start = Get-Date
                    uninstall-networkcontroller -Credential $cred -Force
                    write-verbose "Cleanup of network controller took $(((Get-Date)-$start).totalminutes) minutes."
                }
                $ncc = try { get-networkcontrollercluster -Credential $cred } catch { }
                if ($ncc -ne $null) {
                    write-verbose ("Attempting cleanup of network controller cluster.")
                    $start = Get-Date
                    uninstall-networkcontrollercluster -Credential $cred -Force

                    write-verbose "Cleanup of network controller cluster took $(((Get-Date)-$start).totalminutes) minutes."
                }
               
                $nodes = @()
                foreach ($server in $using:node.ServiceFabricRingMembers) {
                    write-verbose ("Clearing existing node content.")
                    try { Invoke-CommandVerify -ScriptBlock { clear-networkcontrollernodecontent -Force } -ComputerName $server -Credential $cred } catch { }

                    $cn = "$server.$($using:node.FQDN)".ToUpper()
                    $cert = get-childitem "Cert:\localmachine\root" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                    if ($cert -eq $null) {
                        write-error "Certificate not found for $cn in Root store" 
                    }
                    
                    $nic = get-netadapter 
                    if ($nic.count -gt 1) {
                        write-verbose ("WARNING: Invalid number of network adapters found in network Controller node.")    
                        write-verbose ("WARNING: Using first adapter returned: $($nic[0].name)")
                        $nic = $nic[0]    
                    } elseif ($nic.count -eq 0) {
                        write-verbose ("ERROR: No network adapters found in network Controller node.")
                        throw "Network controller node requires at least one network adapter."
                    }

                    write-verbose ("Adding node: {0}.{1}" -f $server, $using:node.FQDN)
                    $nodes += New-NetworkControllerNodeObject -Name $server -Server ($server+"."+$using:node.FQDN) -FaultDomain ("fd:/"+$server) -RestInterface $nic.Name -NodeCertificate $cert -verbose                    
                }

                $mgmtSecurityGroupName = $using:node.mgmtsecuritygroupname
                $clientSecurityGroupName = $using:node.clientsecuritygroupname
                
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                $cert = get-childitem "Cert:\localmachine\root" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")} | Select-Object -First 1 
                
                write-verbose "Using cert with Subject $($cert.Subject) $($cert.thumbprint)"
                
                write-verbose "nodes $($nodes) "
                write-verbose "mgmtSecurityGroupName $($mgmtSecurityGroupName) "
                $start = Get-Date
                if ([string]::isnullorempty($mgmtSecurityGroupName)) {
                    write-verbose "Install-NetworkControllerCluster X509 "
                    Install-NetworkControllerCluster -Node $nodes -ClusterAuthentication X509 -credentialencryptioncertificate $cert -Credential $cred -force -verbose
                } else {
                    write-verbose "Install-NetworkControllerCluster Kerberos "
                    Install-NetworkControllerCluster -Node $nodes -ClusterAuthentication Kerberos -ManagementSecurityGroup $mgmtSecurityGroupName -credentialencryptioncertificate $cert -Credential $cred -Force -Verbose
                }

                write-verbose "Installation of network controller cluster took $(((Get-Date)-$start).totalminutes) minutes."

                write-verbose ("Install-networkcontroller")
                write-verbose ("REST IP is: $($using:node.NetworkControllerRestIP)/$($using:node.NetworkControllerRestIPMask)")
                $start = Get-Date
                if ([string]::isnullorempty($clientSecurityGroupName)) {
                    Install-NetworkController -Node $nodes -ClientAuthentication None -ServerCertificate $cert  -Credential $cred -Force -Verbose -restipaddress "$($using:node.NetworkControllerRestIP)/$($using:node.NetworkControllerRestIPMask)"
                } else {
                    Install-NetworkController -Node $nodes -ClientAuthentication Kerberos -ClientSecurityGroup $clientSecurityGroupName -ServerCertificate $cert -Credential $cred -Force -Verbose -restipaddress "$($using:node.NetworkControllerRestIP)/$($using:node.NetworkControllerRestIPMask)"
                }

                write-verbose "Installation of network controller took $(((Get-Date)-$start).totalminutes) minutes."             
                write-verbose ("Network controller setup is complete.")

                Start-Sleep -Seconds 30
            }
            TestScript = {
                write-verbose ("Checking network controller configuration.")
                $pwd = ConvertTo-SecureString $using:node.NCClusterPassword -AsPlainText -Force; 
                $cred = New-Object System.Management.Automation.PSCredential $using:node.NCClusterUsername, $pwd; 

                $nc = try { get-networkcontroller -credential $cred } catch { }

                if ($nc -ne $null)
                {
                    write-verbose ("Network controller found, checking for REST response.")
                    $credential = $null
                    $response = $null
                    try {
                        if ([String]::isnullorempty($using:node.NCClusterUserName) -eq $false) {
                            $password =  convertto-securestring $using:node.NCClusterPassword -asplaintext -force
                            $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $using:node.NCClusterUserName,$password
                            $response = invoke-webrequest "https://$($using:node.NetworkControllerRestName)/Networking/v1/LogicalNetworks" -UseBasicParsing -credential $credential -ErrorAction SilentlyContinue
                        } else {
                           $response = invoke-webrequest "https://$($using:node.NetworkControllerRestName)/Networking/v1/LogicalNetworks" -UseBasicParsing -ErrorAction SilentlyContinue
                        }
                    }
                    catch {}
                    if ($response -eq $null) {
                        return $false;
                    }
                    return ($response.StatusCode -eq 200)
                }
                write-verbose ("Network controller not configured yet.")
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script CreateNCHostCredentials
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
               
                $hostcred = New-NCCredential -ResourceId $using:node.HostCredentialResourceId -Username $using:node.HostUsername -Password $using:node.HostPassword
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                ipconfig /flushdns

                $nic = get-netadapter 
                if ($nic.count -gt 1) {
                    write-verbose ("WARNING: Invalid number of network adapters found in network Controller node.")    
                    write-verbose ("WARNING: Using first adapter returned: $($nic[0].name)")
                    $nic = $nic[0]    
                } elseif ($nic.count -eq 0) {
                    write-verbose ("ERROR: No network adapters found in network Controller node.")
                    throw "Network controller node requires at least one network adapter."
                }
            
                #ensure we have DNS connectivity via the VIP
                [String[]]$dnsServers = (Get-DnsClientServerAddress -AddressFamily ipv4 -InterfaceAlias ($nic.Name)).ServerAddresses
                $dnsWorking = $false
                $dnsClientTracing = $false
                $dnsServerTracing = $false

                $securepass =  convertto-securestring $using:node.NCClusterPassword -asplaintext -force
                $adminUsername = $($using:node.NCClusterUserName).Split("\")[0]+"\admin1"
                $adminCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist $adminUsername,$securepass

                $attempts = 10
                while (($dnsWorking -eq $false) -and ($attempts -gt 0)) {
                    try
                    {
                        foreach ($dns in $dnsServers)
                        {
                            write-verbose ("Attempting to resolve NC $($using:node.NetworkControllerRestName) in $($dns) server")
                            $nameToResolve =  $($using:node.NetworkControllerRestName)
                            $dnsResponse = Resolve-DnsName -name $nameToResolve -Server $dns -ErrorAction Stop
                            write-verbose $dnsResponse
                        }
                        $dnsWorking = $true
                    } catch 
                    {
                        write-verbose ("Exception while trying to resolve $($nameToResolve)... Iteration $(10-$attempts)")
                        write-verbose "Exception caught: $_"

                        if ($dnsClientTracing -eq $true)
                        {
                            write-verbose "Stopping DNSClient tracing on the client..."
                            Stop-NetEventSession DNSClient
                            Remove-NetEventSession DNSClient
                            $dnsClientTracing = $false
                        }

                        if ($dnsServerTracing -eq $true)
                        {
                            $index = 0
                            foreach ($dns in $dnsServers)
                            {
                                $sessionName = "DnsServer$index"
                                $cim = New-CimSession -ComputerName $dns -Authentication Negotiate -Credential $adminCredential
                                write-verbose "Stopping DNSServer tracing on the server $($dns)..."
                                Stop-NetEventSession $sessionName -CimSession $cim
                                Remove-NetEventSession $sessionName -CimSession $cim

                                Remove-CimSession -CimSession $cim
                                $index++ 
                            }

                            $dnsServerTracing = $false
                        }
                        # lets start tracing locally (DNS client)
                        $date = Get-Date
                        $traceName = "c:\DnsClient-$(10-$attempts)-$($date.Year)-$($date.Month)-$($date.Day)-$($date.Hour)-$($date.Minute)-$($date.Second).etl"
                        write-verbose "Starting DNSClient tracing on the client..."
                        New-NetEventSession -name DNSClient -MaxFileSize 500 -LocalFilePath $traceName
                        Add-NetEventProvider -SessionName DNSClient -Name Microsoft-Windows-DNS-Client 
                        Add-NetEventPacketCaptureProvider -SessionName DNSClient -CaptureType Physical
                        Start-NetEventSession DNSClient
                        $dnsClientTracing = $true

                        # start remote tracing on the DNS servers
                        $index = 0
                        foreach ($dns in $dnsServers)
                        {
                            $sessionName = "DnsServer$index"
                            $date = Get-Date
                            write-verbose "Starting DNSServer tracing on the server $($dns)..."

                            $traceName = "c:\DnsServer-$(10-$attempts)-$($index)-$($date.Year)-$($date.Month)-$($date.Day)-$($date.Hour)-$($date.Minute)-$($date.Second).etl"
                            $cim = New-CimSession -ComputerName $dns -Authentication Negotiate -Credential $adminCredential
                            New-NetEventSession -name $sessionName -MaxFileSize 500 -LocalFilePath $traceName -CimSession $cim
                            Add-NetEventProvider -SessionName $sessionName -Name "{EB79061A-A566-4698-9119-3ED2807060E7}" -CimSession $cim
                            Add-NetEventPacketCaptureProvider -SessionName $sessionName -CaptureType Physical -CimSession $cim
                            Start-NetEventSession $sessionName -CimSession $cim

                            Remove-CimSession -CimSession $cim
                            $index++ 
                        }
                        $dnsServerTracing = $true
                    }
                    $attempts--
                }

                # stop any tracing that might had been running
                if ($dnsClientTracing -eq $true)
                {
                    write-verbose "Stopping DNSClient tracing on the client..."
                    Stop-NetEventSession DNSClient
                    Remove-NetEventSession DNSClient
                    $dnsClientTracing = $false
                }

                if ($dnsServerTracing -eq $true)
                {
                    $index = 0
                    foreach ($dns in $dnsServers)
                    {
                        $sessionName = "DnsServer$index"
                        $cim = New-CimSession -ComputerName $dns -Authentication Negotiate -Credential $adminCredential
                        write-verbose "Stopping DNSServer tracing on the server $($dns)..."
                        Stop-NetEventSession $sessionName -CimSession $cim
                        Remove-NetEventSession $sessionName -CimSession $cim

                        Remove-CimSession -CimSession $cim
                        $index++ 
                    }

                    $dnsServerTracing = $false
                }
                # throw if Dns is not working
                if ($dnsWorking -eq $false)
                {
                    throw "DNS not working"
                }
                
                $ncnotactive = $true
                $attempts = 10
                while ($ncnotactive) {
                    write-verbose "Checking that the controller is up and whether or not it has credentials yet."
                    sleep 10
                    $response = $null
                    try { 
                        if (![String]::isnullorempty($using:node.NCClusterUserName)) {
                            $securepass =  convertto-securestring $using:node.NCClusterPassword -asplaintext -force
                            $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $using:node.NCClusterUserName,$securepass
                            $response = invoke-webrequest https://$($using:node.NetworkControllerRestName)/Networking/v1/Credentials -usebasicparsing  -ErrorAction SilentlyContinue -credential $credential 
                        } else {
                            $response = invoke-webrequest https://$($using:node.NetworkControllerRestName)/Networking/v1/Credentials -usebasicparsing  -ErrorAction SilentlyContinue
                        }
                    } catch { }
                    $ncnotactive = ($response -eq $null)
                    $attempts -= 1;
                    if($attempts -eq 0) { write-verbose "Giving up after 10 tries."; return $false }
                }
                write-verbose "Controller is UP."

                $obj = Get-NCCredential -ResourceId $using:node.HostCredentialResourceId
                return $obj -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script CreateNCCredentials
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                write-verbose "got cert with cn=$cn"
                $hostcred = New-NCCredential -ResourceId $using:node.NCCredentialResourceId -Thumbprint $cert.Thumbprint
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $obj = Get-NCCredential -ResourceId $using:node.NCCredentialResourceId
                return $obj -ne $null  
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        foreach ($ln in $node.LogicalNetworks) {
            Script "CreateLogicalNetwork_$($ln.Name)"
            {
                SetScript = {
                    . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                    $subnets = @()
                    foreach ($subnet in $using:ln.Subnets) {
                        if ($subnet.IsPublic) {
                            $subnets += New-NCLogicalNetworkSubnet -AddressPrefix $subnet.AddressPrefix -VLANId $subnet.vlanid -DNSServers $subnet.DNS -defaultGateway $subnet.Gateways -IsPublic
                        } else {
                            $subnets += New-NCLogicalNetworkSubnet -AddressPrefix $subnet.AddressPrefix -VLANId $subnet.vlanid -DNSServers $subnet.DNS -defaultGateway $subnet.Gateways
                        }
                    }

                    #
                    for($attempt = 3; $attempt -ne 0; $attempt--)
                    {
                        if ($ln.NetworkVirtualization) {
                            $newln = New-NCLogicalNetwork -resourceId $using:ln.ResourceId -LogicalNetworkSubnets $subnets -EnableNetworkVirtualization 
                        } 
                        else
                        {
                            $newln = New-NCLogicalNetwork -resourceId $using:ln.ResourceId -LogicalNetworkSubnets $subnets
                        }
                        
                        if($newln -eq $null)
                        {
                            Write-Verbose "Logical network $($ln.Name) is not created on network controller. Will retry in 30 seconds."
                            Start-Sleep -Seconds 30
                        }
                        else
                        {
                            Write-Verbose "Logical network $($ln.Name) is created on network controller."
                            break;
                        }
                    }
                    if($newln -eq $null)
                    {
                        Write-Verbose "Logical network $($ln.Name) is not created on network controller."
                        throw "Logical Network $($ln.Name) wasn't created."
                    }

                    $i = 0
                    foreach ($subnet in $using:ln.Subnets) {
                        $ippool = New-NCIPPool -LogicalNetworkSubnet $newln.properties.subnets[$i++]  -StartIPAddress $subnet.PoolStart -EndIPAddress $subnet.PoolEnd
                    }
                } 
                TestScript = {
                    . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                    $obj = Get-NCLogicalNetwork -ResourceId $using:ln.ResourceId
                    return $obj -ne $null
                }
                GetScript = {
                    return @{ result = $true }
                }
            }
        }
        
        Script ConfigureSLBManager
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $LogicalNetworks = Get-NCLogicalNetwork
                $vipippools = @()
                $slbmip = ""

                Write-Verbose "Getting the subnets that have VIP pools from config data."
                $vipSubnets = @()
                foreach ($logicalNet in $using:node.LogicalNetworks) {
                    Write-Verbose "Checking logical network $($logicalNet.Name)."
                    foreach ($sn in $logicalNet.Subnets) {
                        if ($sn.IsVipPool -eq $true) {
                            Write-Verbose "Found VIP subnet in logical network $($logicalNet.Name)."
                            $vipSubnets += $sn
                        }
                    }
                }
                
                if ($vipSubnets.Count -eq 0) {
                    throw "No VIP Pool is defined in the configuration. At least one VIP pool should be defined."
                }
                
                write-verbose "Finding VIP subnets information from NC."
                foreach ($vipSn in $vipSubnets) {
                    $matchFound = $false
                    Write-Verbose "Searching subnets from NC to find the matching subnet ($($vipSn.AddressPrefix))."
                    foreach ($ln in $logicalNetworks) {
                        write-verbose "Checking logical network $($ln.resourceid)."
                        foreach ($subnet in $ln.properties.subnets) {
                            write-verbose "checking subnet $($subnet.properties.addressprefix)."
                            if($vipsn.AddressPrefix -eq $subnet.properties.addressprefix) {
                                $matchFound = $true
                                Write-Verbose "Found matching subnet."
                                $targetSubnet = $subnet
                                break;
                            }
                        }
                        if($matchFound) {
                            break;
                        }
                    }
                    
                    if(-not $matchFound) {
                        throw "Can't find subnet $($vipSn.AddressPrefix) on NC. Something was wrong."
                    }
                    
                    # SLBM vip should come from the internal VIP pool, not public one.
                    # However, if there is really no internal VIP pool in the setup, we will use the public one
                    if (-not $vipSn.IsPublic -and $slbmip -eq "") {
                        $slbmip = $targetSubnet.properties.ippools[0].properties.startIpAddress
                        Write-Verbose "SLBMVIP is $slbmip."
                    }
                    elseif ($vipSn.IsPublic -and -not $candidateSlbmIp) {
                        $candidateSlbmIp = $targetSubnet.properties.ippools[0].properties.startIpAddress
                        Write-Verbose "Candidate SLBMVIP is $candidateSlbmIp (if no internal SLBMVIP is available)"
                    }
                    
                    $vipippools += $targetSubnet.properties.ippools
                }
                
                if($slbmip -eq "") {
                    Write-Warning "SLBM VIP is not set to an IP from internalVip pool because internalVip network is not found."
                    Write-Verbose "So set SLBM VIP to an IP from External network: $candidateSlbmIp."
                    $slbmip = $candidateSlbmIp    
                }
                
                $lbconfig = set-ncloadbalancermanager -IPAddress $slbmip -VIPIPPools $vipippools -OutboundNatIPExemptions @("$slbmip/32")                
                
                $pwd = ConvertTo-SecureString $using:node.NCClusterPassword -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential $using:node.NCClusterUsername, $pwd                
                write-verbose "Finished configuring SLB Manager"
            } 
            TestScript = {
                #no need to test, just always set it to the correct value
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        Script CreatePublicIPAddress
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $ipAddress = New-NCPublicIPAddress -ResourceID $using:node.PublicIPResourceId -PublicIPAddress $using:node.GatewayPublicIPAddress
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $obj = Get-NCPublicIPAddress -ResourceId $using:node.PublicIPResourceId
                return ($obj -ne $null)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script ConfigureMACAddressPool
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $macpool = New-NCMacPool -ResourceId $using:node.MACAddressPoolResourceId -StartMACAddress $using:node.MACAddressPoolStart -EndMACAddress $using:node.MACAddressPoolEnd
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $obj = Get-NCMacPool -ResourceId $using:node.MACAddressPoolResourceId
                return $obj -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureGatewayPoolsandPublicIPAddress
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {

        Script CreatePublicIPAddress
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $ipAddress = New-NCPublicIPAddress -ResourceID $using:node.PublicIPResourceId -PublicIPAddress $using:node.GatewayPublicIPAddress
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $obj = Get-NCPublicIPAddress -ResourceId $using:node.PublicIPResourceId
                return ($obj -ne $null)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script ConfigureGatewayPools
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                # Get the Gre VIP Subnet Resource Ref
                foreach ($ln in $node.LogicalNetworks)
                {
                    if ($ln.Name -eq "GreVIP")
                    {
                        $greVipLogicalNetworkResourceId = $ln.ResourceId
                    }
                }

                if (![String]::IsNullOrEmpty($greVipLogicalNetworkResourceId))
                {
                    $greVipNetworkObj = Get-NCLogicalNetwork -ResourceID $greVipLogicalNetworkResourceId
                    $greVipSubnetResourceRef = $greVipNetworkObj.properties.subnets[0].resourceRef
                }

                foreach ($gatewayPool in $node.GatewayPools) {
                    switch ($gatewayPool.Type)
                    {
                        "All"        { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -GreVipSubnetResourceRef $greVipSubnetResourceRef `
                                                -PublicIPAddressId $using:node.PublicIPResourceId -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }

                        "S2sIpSec"   { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -PublicIPAddressId $using:node.PublicIPResourceId `
                                                -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }

                        "S2sGre"     { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -GreVipSubnetResourceRef $greVipSubnetResourceRef `
                                                -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }

                        "Forwarding" { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }
                    }
                }                
            }
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                # retrieve the GW Pools to check if exist
                foreach ($gwPool in $using:node.GatewayPools)
                {
                    $obj = Get-NCGatewayPool -ResourceId $gwPool.ResourceId
                    if ($obj -eq $null)
                    { return $false }
                }
                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureSLBMUX
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node $AllNodes.Where{$_.Role -eq "SLBMUX"}.NodeName
    {
        Script StartMUXTracing
        {
            SetScript = {
                $date = Get-Date
                $tracefile = "c:\muxtrace-$($date.Year)-$($date.Month)-$($date.Day)-$($date.Hour)-$($date.Minute)-$($date.Second)-$($date.Millisecond).etl"
                New-NetEventSession -Name MuxTrace -CaptureMode SaveToFile -LocalFilePath $tracefile
                Add-NetEventProvider "{6c2350f8-f827-4b74-ad0c-714a92e22576}" -Level 5 -SessionName MuxTrace 
                Start-NetEventSession MuxTrace                
            } 
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script DoAllCerts
        {                                      
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $nccertname = "$($using:node.NetworkControllerRestName)"
                $ControllerCertificate="$($using:node.installsrcdir)\$($using:node.certfolder)\$($nccertname).pfx"
                $cn = (GetSubjectName($true)).ToUpper()
                
                write-verbose "Creating self signed certificate...";
                $existingCertList = get-childitem "Cert:\localmachine\my" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                foreach($existingCert in $existingCertList)
                {
                    del "Cert:\localmachine\my\$($existingCert.Thumbprint)"
                }
                
                GenerateSelfSignedCertificate $cn;

                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}

                Write-Verbose "Giving permission to network service for the mux certificate";
                GivePermissionToNetworkService $cert

                Write-Verbose "Adding Network Controller Certificates to trusted Root Store"
                AddCertToLocalMachineStore $ControllerCertificate "Root" "secret"

                Write-Verbose "Updating registry values for Mux"

                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name SlbmThumb -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name SlbmThumb -PropertyType String -Value $nccertname

                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name MuxCert -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name MuxCert -PropertyType String -Value $cn

                Get-ChildItem -Path WSMan:\localhost\Listener | Where {$_.Keys.Contains("Transport=HTTPS") } | Remove-Item -Recurse -Force
                New-Item -Path WSMan:\localhost\Listener -Address * -HostName $cn -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force

                Write-Verbose "Enabling firewall rule for software load balancer mux"
                Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule
            }
            TestScript = {
                write-verbose ("Checking network controller cert configuration.")
                $cert = get-childitem "Cert:\localmachine\my" -ErrorAction Ignore 
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\my cert not found.")
                    return $false
                }
                $nccertname = "$($using:node.NetworkControllerRestName)".ToUpper()
                
                $cert = get-childitem "Cert:\localmachine\root\" -ErrorAction Ignore | where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")}
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\root rest cert not found.")
                    return $false
                }

                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script AddVirtualServerToNC
        {
            SetScript = {
                Write-Verbose "Set AddVirtualServerToNC";
                
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $hostname = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).physicalhostname

                $MUXFQDN = "$($using:node.nodename).$($using:node.fqdn)"

                $nccred = get-nccredential -ResourceId $using:node.NCCredentialResourceId
                
                $connections = @()
                $connections += New-NCServerConnection -ComputerNames @($MUXFQDN) -Credential $nccred

                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$MUXFQDN"}
                $certPath = "C:\$MUXFQDN.cer"

                Write-Verbose "Exporting certificate to the file system and converting to Base64 string...";
                Export-Certificate -Type CERT -FilePath $certPath -Cert $cert
                $file = Get-Content $certPath -Encoding Byte
                $base64 = [System.Convert]::ToBase64String($file)
                Remove-Item -Path $certPath
                
                $vmguid = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid
                $vsrv = new-ncvirtualserver -ResourceId $using:node.MuxVirtualServerResourceId -Connections $connections -Certificate $base64 -vmGuid $vmguid                
            } 
            TestScript = {
                Write-Verbose "Test AddVirtualServerToNC";
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                $obj = Get-NCVirtualServer -ResourceId $using:node.MuxVirtualServerResourceId
                return $obj -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script AddMUXToNC
        {
            SetScript = {
                Write-Verbose "Set AddMUXToNC";
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                Write-Verbose "Obtaining local peering IP from the HNVPA adapter"

                $nics = Get-NetAdapter -ErrorAction Ignore
                if(($nics -eq $null) -or ($nics.count -eq 0))
                {
                    throw "Failed to get available network adapters on the SLB MUX machine"
                }

                $localPeeringIp = ""

                foreach($nic in $nics)
                {
                    if($nic.MacAddress -ieq $using:node.HnvPaMac)
                    {
                        Write-Verbose "Adapter $($nic.Name) has the HNVPA MAC. Obtaining IP address from adapter."
    
                        $localPeeringIp = $nic | Get-NetIPAddress | Select-Object -ExpandProperty IPAddress
                        break
                    }
                }

                Write-Verbose "MuxVirtualServerResourceId $($using:node.MuxVirtualServerResourceId)";
                $vsrv = get-ncvirtualserver -ResourceId $using:node.MuxVirtualServerResourceId

                Write-Verbose "MuxPeerRouterName $($using:node.MuxPeerRouterName) MuxPeerRouterIP $($using:node.MuxPeerRouterIP) MuxPeerRouterASN $($using:node.MuxPeerRouterASN) LocalIPAddress $($localPeeringIp)";
                $peers = @()
                $peers += New-NCLoadBalancerMuxPeerRouterConfiguration -RouterName $using:node.MuxPeerRouterName -RouterIPAddress $using:node.MuxPeerRouterIP -peerASN $using:node.MuxPeerRouterASN -LocalIPAddress $localPeeringIp
                $mux = New-ncloadbalancerMux -ResourceId $using:node.MuxResourceId -LocalASN $using:node.MuxASN -peerRouterConfigurations $peers -VirtualServer $vsrv
            } 
            TestScript = {
                Write-Verbose "Test AddMUXToNC";
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                Write-Verbose "MuxResourceId is $($using:node.MuxResourceId)";
                if ($using:node.MuxResourceId)
                {
                    $obj = Get-ncloadbalancerMux -ResourceId $using:node.MuxResourceId
                    return $obj -ne $null
                }
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }     
        
        Script StopMUXTracing
        {
            SetScript = {
                stop-NetEventSession MuxTrace
                remove-neteventsession MuxTrace        
            } 
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script ForceRestart
        {                                      
            SetScript = {                
                Restart-computer -Force -Confirm:$false -AsJob
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

Configuration AddGatewayNetworkAdapters
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $GatewayVMList = ($node.VMs | ? {$_.VMRole -eq "Gateway"})
                
        foreach ($VMInfo in $GatewayVMList) {
            Script "AddGatewayNetworkAdapter_$($VMInfo.VMName)"
            {
                SetScript = {                    
                    $vm = Get-VM -VMName $using:VMInfo.VMName -ErrorAction stop
                    Stop-VM $vm -Force -ErrorAction stop

                    $internalMac = $using:VMInfo.InternalNicMac -replace '-',''
                    $externalMac = $using:VMInfo.ExternalNicMac -replace '-',''

                    Add-VMNetworkAdapter -VMName $using:VMInfo.VMName -SwitchName $using:node.vSwitchName -Name "Internal" -StaticMacAddress $internalMac
                    Add-VMNetworkAdapter -VMName $using:VMInfo.VMName -SwitchName $using:node.vSwitchName -Name "External" -StaticMacAddress $externalMac

                    Start-VM -VMName $using:VMInfo.VMName -ErrorAction stop
                }
                TestScript = {                        
                    $adapters = @(Get-VMNetworkAdapter –VMName $using:VMInfo.VMName)
                    if ($adapters.count -lt 3)
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

Configuration ConfigureGatewayNetworkAdapterPortProfiles
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        foreach ($hostNode in $AllNodes.Where{$_.Role -eq "HyperVHost"})
        {
            $GatewayVMList = ($hostNode.VMs | ? {$_.VMRole -eq "Gateway"})
        
            foreach ($VMInfo in $GatewayVMList) {
                $gatewayNode = $AllNodes.Where{$_.NodeName -eq $VMInfo.VMName}
                
                # The next block executes locally on the deployment machine as the NC VM does not have VMSwitch cmdlets present
                $internalNicName = "Internal"
                if (![String]::IsNullOrEmpty($gatewayNode.InternalNicName)) {
                    $internalNicName = $gatewayNode.InternalNicName
                }
                $externalNicName = "External"
                if (![String]::IsNullOrEmpty($gatewayNode.ExternalNicName)) {
                    $externalNicName = $gatewayNode.ExternalNicName
                }
                
                $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
                $IntNicProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -ComputerName $hostNode.NodeName -VMName $VMInfo.VMName -VMNetworkAdapterName $internalNicName -ErrorAction Ignore
                $ExtNicProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -ComputerName $hostNode.NodeName -VMName $VMInfo.VMName -VMNetworkAdapterName $externalNicName -ErrorAction Ignore
                 
                # Executes remotely on the NC VM so that REST calls can be made successfully
                
                Script "SetPort_$($VMInfo.VMName)"
                {
                    SetScript = {
                        . "$($using:hostNode.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:hostNode.NetworkControllerRestName -UserName $using:hostNode.NCClusterUserName -Password $using:hostNode.NCClusterPassword

                        $InternalNicInstanceid =  Get-NCNetworkInterfaceInstanceId -resourceid $using:VMInfo.InternalNicPortProfileId
                        $ExternalNicInstanceid =  Get-NCNetworkInterfaceInstanceId -resourceid $using:VMInfo.ExternalNicPortProfileId

                        write-verbose "Gateway instance ids [$InternalNicInstanceid] [$ExternalNicInstanceid]"

                        write-verbose ("VM - $($using:VMInfo.VMName), Adapter - $using:internalNicName")
                        set-portprofileid -ResourceID $InternalNicInstanceid -vmname $using:VMInfo.VMName -VMNetworkAdapterName $using:internalNicName -computername $using:hostNode.NodeName -ProfileData "1" -Force
                        write-verbose ("VM - $($using:VMInfo.VMName), Adapter - $using:externalNicName")
                        set-portprofileid -ResourceID $ExternalNicInstanceid -vmname $using:VMInfo.VMName -VMNetworkAdapterName $using:externalNicName -computername $using:hostNode.NodeName -ProfileData "1" -Force
                    }
                    TestScript = {
                        . "$($using:hostNode.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:hostNode.NetworkControllerRestName -UserName $using:hostNode.NCClusterUserName -Password $using:hostNode.NCClusterPassword
                        write-verbose "Gateway Node is [$($using:gatewaynode.NodeName)]"
                        write-verbose "Gateway port profiles [$($using:VMInfo.InternalNicPortProfileId)] [$($using:VMInfo.ExternalNicPortProfileId)]"
                        $InternalNicInstanceid =  Get-NCNetworkInterfaceInstanceId -resourceid $using:VMInfo.InternalNicPortProfileId
                        $ExternalNicInstanceid =  Get-NCNetworkInterfaceInstanceId -resourceid $using:VMInfo.ExternalNicPortProfileId
                        
                        return ($using:IntNicProfile.SettingData.ProfileData -eq "1" -and $using:IntNicProfile.SettingData.ProfileId -eq $InternalNicInstanceid -and
                                $using:ExtNicProfile.SettingData.ProfileData -eq "1" -and $using:ExtNicProfile.SettingData.ProfileId -eq $ExternalNicInstanceid )
                    }
                    GetScript = {
                        return @{ result = @(Get-VMNetworkAdapter –VMName $using:VMInfo.VMName) }
                    }
                }
            }
        }
    }
}

Configuration ConfigureGatewayVMs
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "Gateway"}.NodeName
    {
        Script SetWinRmEnvelope
        {                                      
            SetScript = {
                write-verbose "Setting WinRM Envelope size."
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000
            }
            TestScript = {
                return ((Get-Item WSMan:\localhost\MaxEnvelopeSizekb).Value -ge 7000)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        WindowsFeature RemoteAccess
        {
            Ensure = "Present"
            Name = "RemoteAccess"
            IncludeAllSubFeature = $true
        }
        
    }
}

Configuration ConfigureGateway
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "Gateway"}.NodeName
    {
        Script RenameGatewayNetworkAdapters
        {
            SetScript = {
                $adapters = @(Get-NetAdapter)
                Write-Verbose "Found $($adapters.count) Network Adapters: $($adapters.Name)"

                foreach($adapter in $adapters)
                {
                    try {
                        if($adapter.MacAddress -eq $using:node.InternalNicMac)
                        {
                            Write-Verbose "[Internal]Renaming adapter '$($adapter.Name)'"
                            Rename-NetAdapter -Name $adapter.Name -NewName "Internal" -Confirm:$false -ErrorAction Stop
                            Write-Verbose "[Internal]Renaming successful"
                        }
                    }
                    catch { Write-Verbose "[$($using:node.NodeName)]Failed to rename Internal Network Adapter" }

                    try {
                        if($adapter.MacAddress -eq $using:node.ExternalNicMac)
                        { 
                            Write-Verbose "[External]Renaming adapter '$($adapter.Name)'"
                            Rename-NetAdapter -Name $adapter.Name -NewName "External" -Confirm:$false -ErrorAction Stop
                            Write-Verbose "[External]Renaming successful"
                        }
                    }
                    catch{  Write-Verbose "[$($using:node.NodeName)]Failed to rename External Network Adapter" }
                }
            }
            TestScript = {
                try { 
                    $adapters = @(Get-NetAdapter)
                    
                    if ($adapters.Name -Contains "Internal" -and $adapters.Name -Contains "External") 
                    { 
                        Write-Verbose "[$($using:node.NodeName)]Found 'Internal' & 'External' network adapters, skipping SET"
                        return $true 
                    }
                    else 
                    { 
                        Write-Verbose "[$($using:node.NodeName)]'Internal' & 'External' network adapters not found, executing SET"
                        return $false 
                    }
                }
                catch{ return $false }                
            }
            GetScript = {
                return @{ result = @(Get-NetAdapter) }
            }
        } 

        Script ConfigureRemoteAccess
        {
            SetScript = {              
                Add-WindowsFeature -Name RemoteAccess -IncludeAllSubFeature -IncludeManagementTools
                try { $RemoteAccess = Get-RemoteAccess } catch{$RemoteAccess = $null}
                    
                $hostname = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).physicalhostname

                if($RemoteAccess -eq $null -or $RemoteAccess.VpnMultiTenancyStatus -ne "Installed")
                {
                    Write-Verbose "Installing RemoteAccess Multitenancy on $hostname"
                    Install-RemoteAccess -MultiTenancy
                }
            }
            TestScript = {
                try { $RemoteAccess = Get-RemoteAccess } catch{$RemoteAccess = $null}
                if($RemoteAccess -eq $null -or $RemoteAccess.VpnMultiTenancyStatus -ne "Installed")
                { return $false } 
                else 
                { return $true }
            }
            GetScript = {
                return @{ result = $RemoteAccess.VpnMultiTenancyStatus }
            }
        }

        Script InstallNCCert
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $nccertname = "$($using:node.NetworkControllerRestName)"
                $ControllerCertificate="$($using:node.installsrcdir)\$($using:node.certfolder)\$($nccertname).pfx"
                
                Write-Verbose "Adding Network Controller Certificates to trusted Root Store"
                AddCertToLocalMachineStore $ControllerCertificate "Root" "secret"

                Write-Verbose "Enabling firewall rule"
                Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule
            }
            TestScript = {
                write-verbose ("Checking network controller cert configuration.")
                $nccertname = "$($using:node.NetworkControllerRestName)".ToUpper()
                
                $cert = get-childitem "Cert:\localmachine\root\" -ErrorAction Ignore | where {$_.Subject.ToUpper().StartsWith("CN=$($nccertname)")}
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\root rest cert not found.")
                    return $false
                }                
                                
                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script AddVirtualServerToNC
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                              
                $hostname = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).physicalhostname

                $GatewayFQDN = "$($using:node.nodename).$($using:node.fqdn)"

                $hostcred = get-nccredential -ResourceId $using:node.HostCredentialResourceId

                $connections = @()
                $connections += New-NCServerConnection -ComputerNames @($GatewayFQDN) -Credential $hostcred

                $vmguid = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid                
                $vsrv = new-ncvirtualserver -ResourceId $using:node.NodeName -Connections $connections -vmGuid $vmguid

            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                $obj = Get-NCVirtualServer -ResourceId $using:node.NodeName
                return $obj -ne $null  #TODO: validate it has correct values before returning $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script AddGatewayToNC
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                
                
                if ([String]::IsNullOrEmpty($using:node.ExternalLogicalNetwork)) {
                    $lnName = "Transit"
                } else {
                    $lnName = $using:node.ExternalLogicalNetwork
                }

                # Get Transit Subnet ResourceId
                foreach ($ln in $using:node.LogicalNetworks)
                {
                    if ($ln.Name -eq $lnName)
                    {
                        $transitLogicalNetworkResourceId = $ln.ResourceId
                    }
                }
                
                $transitNetwork = Get-NCLogicalNetwork -ResourceID $transitLogicalNetworkResourceId

                # Add new Interfaces for the GW VM     
                $internalMac = $using:node.InternalNicMac
                $externalMac = $using:node.ExternalNicMac

                Write-verbose "New network interface [$($using:node.ExternalNicPortProfileId)] [$($externalMac)] [$($using:node.ExternalIPAddress)]"
                write-verbose $($transitNetwork.properties.Subnets[0] | Convertto-json -depth 10) 

                $InternalInterface = New-NCNetworkInterface -ResourceId $using:node.InternalNicPortProfileId -MacAddress $internalMac
                $ExternalInterface = New-NCNetworkInterface -ResourceId $using:node.ExternalNicPortProfileId -MacAddress $externalMac -IPAddress $using:node.ExternalIPAddress -Subnet $transitNetwork.properties.Subnets[0]

                # Get the Gateway Pool reference
                $GatewayPoolObj = Get-NCGatewayPool -ResourceId $using:Node.GatewayPoolResourceId

                # Get the virtual Server reference
                $VirtualServerObj = Get-NCVirtualServer -ResourceId $using:node.NodeName 
        
                $GreBgpConfig = 
                @{
                    extAsNumber = "0.$($using:node.GreBgpRouterASN)"
                    bgpPeer = 
                    @(
                        @{
                            peerIP = $using:node.GreBgpPeerRouterIP
                            peerExtAsNumber = "0.$($using:node.GreBgpPeerRouterASN)"
                        }
                    )
                }

                # PUT new Gateway
                switch ($gatewayPoolObj.properties.type)
                {
                    { @("All", "S2sGre") -contains $_ }   {     
                                    $gateway = New-NCGateway -ResourceID $using:node.NodeName -GatewayPoolRef $GatewayPoolObj.resourceRef -Type $GatewayPoolObj.properties.type -BgpConfig $GreBgpConfig `
                                                            -VirtualServerRef $VirtualServerObj.resourceRef -ExternalInterfaceRef $ExternalInterface.resourceRef -InternalInterfaceRef $InternalInterface.resourceRef
                                }
                    { @("S2sIpSec", "Forwarding") -contains $_ }     {
                                    $gateway = New-NCGateway -ResourceID $using:node.NodeName -GatewayPoolRef $GatewayPoolObj.resourceRef -Type $GatewayPoolObj.properties.type `
                                                            -VirtualServerRef $VirtualServerObj.resourceRef -ExternalInterfaceRef $ExternalInterface.resourceRef -InternalInterfaceRef $InternalInterface.resourceRef 
                                }
                }
                
            }
            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword

                $obj = Get-NCGateway -ResourceId $using:node.NodeName
                return $obj -ne $null  #TODO: validate it has correct values before returning $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureHostNetworkingPreNCSetup
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $NCIP = $node.networkControllerRestIP
        
        $connections = "ssl:$($NCIP):6640","pssl:6640"
        $peerCertCName = "$($node.NetworkControllerRestName)".ToUpper()
        $hostAgentCertCName = "$($node.nodename).$($node.fqdn)".ToUpper()
        
        $psPwd = ConvertTo-SecureString $node.HostPassword -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential $node.HostUserName, $psPwd
        
        Script DisableWFP
        {
            SetScript = {
                $switch = $using:node.vSwitchName
                Disable-VmSwitchExtension -VMSwitchName $switch -Name "Microsoft Windows Filtering Platform"

                if((get-vmswitchextension -VMSwitchName $switch -Name "Microsoft Windows Filtering Platform").Enabled -eq $true)
                {
                    throw "DisableWFP Failed on $($using:node.NodeName)"
                }
            }
            TestScript = {
                return (get-vmswitchextension -VMSwitchName $using:node.vSwitchName -Name "Microsoft Windows Filtering Platform").Enabled -eq $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Registry SetNCHostAgent_Connections
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters"
            ValueName = "Connections"
            ValueData = $connections
            ValueType = "MultiString"
        }

        Registry SetNCHostAgent_PeerCertificateCName
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters"
            ValueName = "PeerCertificateCName"
            ValueData = $peerCertCName
            ValueType = "String"
        }
       
        Registry SetNCHostAgent_HostAgentCertificateCName
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters"
            ValueName = "HostAgentCertificateCName"
            ValueData = $hostAgentCertCName
            ValueType = "String"
        }     

        Script ConfigureWindowsFirewall
        {
            SetScript = {
                # Firewall-REST    
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-REST" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for NCHostAgent Rest";
                    New-NetFirewallRule -Name "Firewall-REST" -DisplayName "Network Controller Host Agent REST" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-REST" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-REST Rule Failed on $($using:node.NodeName)"
                }
            
                # Firewall-OVSDB
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for NCHostAgent OVSDB";
                    New-NetFirewallRule -Name "Firewall-OVSDB" -DisplayName "Network Controller Host Agent OVSDB" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 6640 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-OVSDB Rule Failed on $($using:node.NodeName)"
                }
                
                # Firewall-HostAgent-TCP-IN
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for Firewall-HostAgent-TCP-IN";
                    New-NetFirewallRule -Name "Firewall-HostAgent-TCP-IN" -DisplayName "Network Controller Host Agent (TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort Any -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-HostAgent-TCP-IN Rule Failed on $($using:node.NodeName)"
                }
                
                # Firewall-HostAgent-WCF-TCP-IN  
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for Firewall-HostAgent-WCF-TCP-IN";
                    New-NetFirewallRule -Name "Firewall-HostAgent-WCF-TCP-IN" -DisplayName "Network Controller Host Agent WCF(TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-HostAgent-WCF-TCP-IN Rule Failed on $($using:node.NodeName)"
                }
                
                # Firewall-HostAgent-TLS-TCP-IN
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for Firewall-HostAgent-TLS-TCP-IN";
                    New-NetFirewallRule -Name "Firewall-HostAgent-TLS-TCP-IN" -DisplayName "Network Controller Host Agent WCF over TLS (TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort 443 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-HostAgent-TLS-TCP-IN Rule Failed on $($using:node.NodeName)"
                }            
            }
            TestScript = {
                if(((get-netfirewallrule -Name "Firewall-REST" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue) -eq $null))
                {
                    return $false
                }

                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script CleanupCerts
        {
            SetScript = {
                # Host Cert in My
                $store = new-object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
                $store.open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $fqdn = "$($using:node.fqdn)".ToUpper()
                $certs = $store.Certificates | Where {$_.Subject.ToUpper().Contains($fqdn)}
                foreach($cert in $certs) {
                    $store.Remove($cert)
                }
                $store.Dispose()
                
                # NC Cert in Root
                $store = new-object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
                $store.open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $fqdn = "$($using:node.fqdn)".ToUpper()
                $certs = $store.Certificates | Where {$_.Subject.ToUpper().Contains($fqdn)}
                foreach($cert in $certs) {
                    $store.Remove($cert)
                }
                $store.Dispose()
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script InstallHostCert
        {
            SetScript = {
                Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
                . "$($using:node.HostInstallSrcDir)\Scripts\CertHelpers.ps1"
                
                write-verbose "Querying self signed certificate ...";
                $cn = "$($using:node.NodeName).$($node.fqdn)".ToUpper()
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")} | Select -First 1
                if ($cert -eq $null) {
                    $certName = "$($using:node.nodename).$($using:node.FQDN)".ToUpper()
                    $certPath = "c:\$($using:node.certfolder)"
                    $certPwd = $using:node.HostPassword
                    write-verbose "Adding Host Certificate to trusted My Store from [$certpath\$certName]"
                    AddCertToLocalMachineStore "$($certPath)\$($certName).pfx" "My" "$($certPwd)"

                    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")} | Select -First 1
                }
                    
                write-verbose "Giving permission to network service for the host certificate $($cert.Subject)"
                GivePermissionToNetworkService $cert
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
            PSDSCRunAsCredential = $psCred
        }  

        Script InstallNCCert
        {
            SetScript = {
                write-verbose "Adding Network Controller Certificates to trusted Root Store"
                . "$($using:node.HostInstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $certPath = "c:\$($using:node.CertFolder)\$($using:node.NetworkControllerRestName).pfx"
                $certPwd = "secret"
                
                write-verbose "Adding $($certPath) to Root Store"
                AddCertToLocalMachineStore "$($certPath)" "Root" "$($certPwd)"
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script RestartHostAgent
        {
            SetScript = {
                $service = Get-Service -Name NCHostAgent
                Stop-Service -InputObject $service -Force
                Set-Service -InputObject $service -StartupType Automatic
                Start-Service -InputObject $service
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        } 
 
        Script EnableVFP
        {
            SetScript = {
                $switch = $using:node.vSwitchName
                Enable-VmSwitchExtension -VMSwitchName $switch -Name "Microsoft Azure VFP Switch Extension"

                Write-Verbose "Wait 40 seconds for the VFP extention to be enabled"
                sleep 40
            
                if((get-vmswitchextension -VMSwitchName $switch -Name "Microsoft Azure VFP Switch Extension").Enabled -ne $true)
                {
                    throw "EnableVFP Failed on $($using:node.NodeName)"
                }
            }
            TestScript = {
                return (get-vmswitchextension -VMSwitchName $using:node.vSwitchName -Name "Microsoft Azure VFP Switch Extension").Enabled                 
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureSLBHostAgent
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        . "$($node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword
        $slbmVip = (Get-NCLoadbalancerManager).properties.loadbalancermanageripaddress

        Script CreateSLBConfigFile
        {
            SetScript = {
                $slbhpconfigtemplate = @'
<?xml version="1.0" encoding="utf-8"?>
<SlbHostPluginConfiguration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SlbManager>
        <HomeSlbmVipEndpoints>
            <HomeSlbmVipEndpoint>{0}:8570</HomeSlbmVipEndpoint>
        </HomeSlbmVipEndpoints>
        <SlbmVipEndpoints>
            <SlbmVipEndpoint>{1}:8570</SlbmVipEndpoint>
        </SlbmVipEndpoints>
        <SlbManagerCertSubjectName>{2}</SlbManagerCertSubjectName>
    </SlbManager>
    <SlbHostPlugin>
        <SlbHostPluginCertSubjectName>{3}</SlbHostPluginCertSubjectName>
    </SlbHostPlugin>
    <NetworkConfig>
        <MtuSize>0</MtuSize>
        <JumboFrameSize>4088</JumboFrameSize>
        <VfpFlowStatesLimit>500000</VfpFlowStatesLimit>
    </NetworkConfig>
</SlbHostPluginConfiguration>
'@

                $hostFQDN = "$($using:node.NodeName).$($using:node.fqdn)".ToLower()
                $ncFQDN = "$($using:node.NetworkControllerRestName)".ToLower()
                
                $slbhpconfig = $slbhpconfigtemplate -f $using:slbmVip, $using:slbmVip, $ncFQDN, $hostFQDN
                write-verbose $slbhpconfig
                set-content -value $slbhpconfig -path 'c:\windows\system32\slbhpconfig.xml' -encoding UTF8
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script RestartSLBHostAgent
        {
            SetScript = {
                #this should be temporary fix
                $tracingpath = "C:\Windows\tracing"
                if((test-path $tracingpath) -ne $true) {
                    mkdir $tracingpath
                }

                $service = Get-Service -Name SlbHostAgent
                Stop-Service -InputObject $service -Force
                Set-Service -InputObject $service -StartupType Automatic
                Start-Service -InputObject $service
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

Configuration ConfigureServers
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    # This executes from the NC as the 
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        foreach ($hostNode in $AllNodes.Where{$_.Role -eq "HyperVHost"})
        {
            Script "AddHostToNC_$($hostNode.NodeName)"
            {
                SetScript = {
                    $verbosepreference = "Continue"
                  
                    . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
            
                    $serverResourceId = Get-ServerResourceId -ComputerName $using:hostNode.NodeName
                    write-verbose "Server ResourceId (VMswitch[0]): $serverResourceId"

                    $hostcred = Get-NCCredential -ResourceId $using:hostNode.HostCredentialResourceId
                    write-verbose "NC Host Credential: $($hostcred)"

                    $nccred = get-nccredential -ResourceId $using:hostNode.NCCredentialResourceId
                    write-verbose "NC NC Credential: $($nccred)";
            
                    $hostFQDN = "$($using:hostNode.NodeName).$($using:hostNode.fqdn)".ToLower()
                    $ipaddress = [System.Net.Dns]::GetHostByName($hostFQDN).AddressList[0].ToString()
        
                    $connections = @()
                    $connections += New-NCServerConnection -ComputerNames @($ipaddress, $hostFQDN) -Credential $hostcred -Verbose
                    $connections += New-NCServerConnection -ComputerNames @($ipaddress, $hostFQDN) -Credential $nccred -Verbose
        
                    $ln = Get-NCLogicalNetwork -ResourceId $using:hostNode.PALogicalNetworkResourceId -Verbose
            
                    $pNICs = @()
                    $pNICs += New-NCServerNetworkInterface -LogicalNetworksubnets ($ln.properties.subnets) -Verbose

                    $certPath = "$($using:hostNode.InstallSrcDir)\$($using:hostNode.CertFolder)\$($hostFQDN).cer"
                    write-verbose "Getting cert file content: $($certPath)"
                    $file = Get-Content $certPath -Encoding Byte
                    write-verbose "Doing conversion to base64"
                    $base64 = [System.Convert]::ToBase64String($file)
            
                    $server = New-NCServer -ResourceId $serverResourceId -Connections $connections -PhysicalNetworkInterfaces $pNICs -Certificate $base64 -Verbose
            
                    $serverObj = Get-NCServer -ResourceId $serverResourceId
                    if(!$serverObj)
                    {
                        throw "Adding Host to NC Failed on $($using:hostNode.NodeName)"
                    }
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

Configuration ConfigureHostAgent
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        # This block executes locally on the deployment machine as some hosts are not able to make REST calls (e.g. Nano)

        . "$($node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword

        $serverResourceId = Get-ServerResourceId -ComputerName $node.NodeName
        $serverObj = Get-NCServer -ResourceId $serverResourceId
        $serverInstanceId = $serverObj.instanceId

        # The following Registry/script configurations execute on the actual hosts

        Registry SetHostId
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters"
            ValueName = "HostId"
            ValueData = $serverInstanceId
            ValueType = "String"
        }

        Script RestartHostAgents
        {
            SetScript = {
                $dnsproxy = get-service DNSProxy -ErrorAction Ignore
                if ($dnsproxy -ne $null) {
                    Write-Verbose "Stopping DnsProxy service."
                    Stop-Service DnsProxy -Force
                }

                Write-Verbose "Stopping SlbHostAgent service."
                Stop-Service SlbHostAgent -Force                
                Write-Verbose "Stopping NcHostAgent service."
                Stop-Service NcHostAgent -Force

                Write-Verbose "Starting NcHostAgent service."
                Start-Service NcHostAgent
                Write-Verbose "Starting SlbHostAgent service."
                Start-Service SlbHostAgent

                if ($dnsproxy -ne $null) {                
                    $i = 0
                    while ($i -lt 10) {
                        try {
                            Start-Sleep -Seconds 10
                            Write-Verbose "Starting DnsProxy service (Attempt: $i)."
                            Start-Service DnsProxy -ErrorAction Stop
                            break
                        }
                        catch {
                            Write-Verbose "DnsProxy service can't be started. Will retry."
                            $i++
                            if($i -ge 10) {
                                Write-Verbose "DnsProxy serivce can't be started after $i attempts. Exception: $_"
                                throw $_
                            }
                        }
                    }   
                }           
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

Configuration ConfigureIDns
{    
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        Script CreateiDnsCredentials
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword                 
                $hostcred = New-NCCredential -ResourceId $node.iDNSCredentialResourceId -UserName $using:node.iDNSAdminUsername -Password $using:node.iDNSAdminPassword
            }

            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $obj = Get-NCCredential -ResourceId $using:node.iDNSCredentialResourceId
                if ($obj -ne $null)	{
                    Write-verbose "Get NC creds: object already exists. returning true."
                    return $true
                }
                else {
                    Write-verbose "Get NC creds: object does not exist. returning false."
                    return $false
                }
            }

            GetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $obj = Get-NCCredential -ResourceId $using:node.iDNSCredentialResourceId
                return @{ result = $obj }
            }
        }
             
        Script PutiDnsConfiguration
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $cred = Get-NCCredential -ResourceId $using:node.iDNSCredentialResourceId
                write-verbose "Adding IP address: $($using:node.iDNSAddress) to the DNSConfig"
                $connections = @()
                $connections += New-NCServerConnection -ComputerNames @($using:node.iDNSAddress) -Credential $cred -Verbose
                write-verbose "Adding zone $($using:node.iDNSZoneName) to the DNSConfig"
                $iDnsConfig = Add-iDnsConfiguration -Connections $connections -ZoneName $using:node.iDNSZoneName
            }

            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                try { $iDnsObj = Get-iDnsConfiguration } catch { $iDnsObj = $null }
                if ($iDnsObj -ne $null) {
                    Write-verbose "Get iDNS: object already exists. Returning true."
                    return $true
                }
                else {
                    Write-verbose "Get iDNS: object does not exist. Returning false."
                    return $false
                }
            }

            GetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $iDnsObj = Get-iDnsConfiguration
                return @{ result = $iDnsObj }
            }
        }
    }
}

Configuration ConfigureIDnsProxy
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        #iDNS Proxy Registry Hives
        $iDnsVfpPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService"                                                                                          
        $iDnsProxyPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNSProxy\Parameters"

        Registry SetDnsPort
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "Port"
            ValueData = 53
            ValueType = "Dword"
        }

        Registry SetDnsProxyPort
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "ProxyPort"
            ValueData = 53
            ValueType = "Dword"
        }

        Registry SetDnsIPAddress
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "IP"
            ValueData = "169.254.169.254"
            ValueType = "String"
        }

        Registry SetDnsMacAddress
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "MAC"
            ValueData = $node.iDNSMacAddress
            ValueType = "String"
        }

        Registry SetDnsForwarder
        {
            Ensure = "Present"
            Key = $iDnsProxyPath
            ValueName = "Forwarders"
            ValueData = $node.iDNSAddress
            ValueType = "String"
        }

        Script SetupDNSProxy
        {
            SetScript = {

                # Enable firewall rules for DNS proxy service
                Write-verbose "Enable DNS Proxy Service firewall rule group"
                Enable-NetFirewallRule -DisplayGroup 'DNS Proxy Service'

                <#
                # restart the NC host agent service
                Write-verbose "Restarting NC host agent service"
                Restart-Service nchostagent -Force

                # Enable firewall rules for DNS proxy service
                Write-verbose "Start DnsProxy service and make it automatic"
                Enable-NetFirewallRule -DisplayGroup 'DNS Proxy Service'

                # Start DnsProxy service and make it automatic
                Write-verbose "Start DnsProxy service and make it automatic"
                $dnsProxyService = Get-Service -Name "DnsProxy" 
                Set-Service -Name "DnsProxy" -StartupType Automatic
                Restart-Service -Name "DnsProxy" -force
                #>
                
                # Workaround for DnsProxy
                
                Write-Verbose "Stopping DnsProxy service."
                Stop-Service DnsProxy -Force
                
                Write-Verbose "Stopping NcHostAgent service."
                Stop-Service NcHostAgent -Force

                Write-Verbose "Starting NcHostAgent service."
                Start-Service NcHostAgent

                Write-verbose "Set DnsProxy service startup type to Automatic"
                Set-Service -Name "DnsProxy" -StartupType Automatic

                $i = 0
                while ($i -lt 10) {
                    try {
                        Start-Sleep -Seconds 10
                        Write-Verbose "Starting DnsProxy service (Attempt: $i)."
                        Start-Service DnsProxy -ErrorAction Stop
                        break
                    }
                    catch {
                        Write-Verbose "DnsProxy service can't be started. Will retry."
                        $i++
                        if($i -ge 10) {
                            Write-Verbose "DnsProxy serivce can't be started after $i attempts. Exception: $_"
                            throw $_
                        }
                    }
                }
            }

            TestScript = {
                $dnsProxyServiceState = $false;
                Write-verbose "Get DnsProxy service running state"
                $dnsProxyService = Get-Service -Name "DnsProxy"
                $dnsProxyServiceState = ($dnsProxyService.status -eq "Running")
                return $dnsProxyServiceState            
            }

            GetScript = {
                Write-verbose "Get DnsProxy service "
                $dnsProxyService = Get-Service -Name "DnsProxy"
                return @{ result = $true }
            }
        }
    }
}

Configuration CleanUp
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.NodeName
    {
        script "RemoveCertsDirectory"
        {
            SetScript = {
                write-verbose "Removing contents of Certs directory"
                rm -recurse -force "$($env:systemdrive)\$($Using:node.CertFolder)\*"
            }
            TestScript = {
                return ((Test-Path "$($env:systemdrive)\$($Using:node.CertFolder)") -ne $True)
            }
            GetScript = {
                return @{ result = $true }
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
    { return (New-PSSession -ComputerName $ComputerName -ErrorAction Ignore) }
    else
    { return (New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Ignore) }
}

function WaitForComputerToBeReady
{
    param(
        [string[]] $ComputerName,
        [Switch]$CheckPendingReboot
    )


    foreach ($computer in $computername) {        
        write-verbose "Waiting for $Computer to become active."
        
        $continue = $true
        while ($continue) {
            try {
                $ps = $null
                $result = ""
                
                klist purge | out-null  #clear kerberos ticket cache 
                Clear-DnsClientCache    #clear DNS cache in case IP address is stale
                
                write-verbose "Attempting to contact $Computer."
                $ps = GetOrCreate-pssession -computername $Computer -erroraction ignore
                if ($ps -ne $null) {
                    if ($CheckPendingReboot) {                        
                        $result = Invoke-Command -Session $ps -ScriptBlock { 
                            if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                                "Reboot pending"
                            } 
                            else {
                                hostname 
                            }
                        }
                    }
                    else {
                        try {
                            $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
                        } catch { }
                    }
                }
                if ($result -eq $Computer) {
                    $continue = $false
                    break
                }
                if ($result -eq "Reboot pending") {
                    write-verbose "Reboot pending on $Computer.  Waiting for restart."
                }
            }
            catch 
            {
            }
            write-verbose "$Computer is not active, sleeping for 10 seconds."
            sleep 10
        }
    write-verbose "$Computer IS ACTIVE.  Continuing with deployment."
    }
}

function GetRoleMembers
{
    param(
        [Object] $ConfigData,
        [String[]] $RoleNames
    )
    $results = @()

    foreach ($node in $configdata.AllNodes) {
        if ($node.Role -in $RoleNames) {
            $results += $node.NodeName
        }
    }
    if ($results.count -eq 0) {
        throw "No node with NetworkController role found in configuration data"
    }
    return $results
}

function RestartRoleMembers
{
    param(
        [Object] $ConfigData,
        [String[]] $RoleNames,
        [Switch] $Wait,
        [Switch] $Force
    )
    $results = @()

    foreach ($node in $configdata.AllNodes) {
        if ($node.Role -in $RoleNames) {
                write-verbose "Restarting $($node.NodeName)"
                $ps = GetOrCreate-pssession -ComputerName $($node.NodeName)
                Invoke-Command -Session $ps -ScriptBlock { 
                    if ($using:Force -or (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")) {
                        Restart-computer -Force -Confirm:$false
                    }
                }
        }
    }
    
    sleep 10

    if ($wait.IsPresent) {
        WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController")) -CheckPendingReboot
    }
}

function GatherCerts
{
    param(
        [Object] $ConfigData
    )
    $nccertname = $ConfigData.allnodes[0].NetworkControllerRestName

    write-verbose "Finding NC VM with REST cert."
    foreach ($n in $configdata.allnodes) {
        if (($n.role -eq "NetworkController") -and ($n.ServiceFabricRingMembers -ne $null)) {
            write-verbose "NC REST host is $($n.nodename)."
            $ncresthost = $n.nodename

            Write-Verbose "Copying all certs to the installation sources cert directory."
            $NCCertSource = "\\$($ncresthost)\c$\$($nccertname)"
            $NCCertDestination = "$($configData.AllNodes[0].installsrcdir)\$($configData.AllNodes[0].certfolder)"

            write-verbose ("Copying REST cert from [{0}] to [{1}]" -f $NCCertSource, $NCCertDestination)
            copy-item -path $NCCertSource -Destination $NCCertDestination

            if(Test-Path "$NCCertSource.pfx") {
                write-verbose ("Copying REST cert pfx from [{0}] to [{1}]" -f "$NCCertSource.pfx", $NCCertDestination)
                copy-item -path "$NCCertSource.pfx" -Destination $NCCertDestination
            }

            foreach ($n2 in $configdata.allnodes) {
                if ($n2.role -eq "NetworkController") {
                    $NCCertSource = '\\{0}\c$\{1}.{2}.pfx' -f $ncresthost, $n2.NodeName, $nccertname
                    $fulldest = "$($NCCertDestination)\$($n2.NodeName).$($nccertname).pfx"

                    write-verbose ("Copying NC Node cert pfx from [{0}] to [{1}]" -f $NCCertSource, $fulldest)
                    copy-item -path $NCCertSource -Destination $fulldest
                }
                elseif ($n2.role -eq "HyperVHost") {
                    $CertName = "$($n2.nodename).$($n2.FQDN)".ToUpper()
                    $HostCertSource = '\\{0}\c$\{1}' -f $ncresthost, $CertName
                    $fulldest = "$($NCCertDestination)\$($CertName)"

                    write-verbose ("Copying Host Node cert from [{0}] to [{1}]" -f "$HostCertSource.cer", "$fulldest.cer")
                    copy-item -path "$HostCertSource.cer" -Destination "$fulldest.cer"

                    write-verbose ("Copying Host Node cert pfx from [{0}] to [{1}]" -f "$HostCertSource.pfx", "$fulldest.pfx")
                    copy-item -path "$HostCertSource.pfx" -Destination "$fulldest.pfx"
                }
            }

            break
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
        $error = "The Fabric configuration file which was provided is not compatible with this version of the script. "
        $error += "To avoid compatibility issues, please use only the version of FabricConfig.psd1 which came with this version of the SDNExpress.ps1 script"

        throw $error
    }
}


function PopulateDefaults
{
    param(
        [Object] $AllNodes
    )

    write-verbose "Populating defaults into parameters that were not set in config file."

    #Set Logical Network resourceids based on name
    foreach ($ln in $AllNodes[0].LogicalNetworks)
    {
        if ([string]::IsNullOrEmpty($ln.ResourceId)) {
            $ln.ResourceId = $ln.Name
        }

        foreach ($subnet in $ln.subnets) {
            if ($subnet.DNS -eq $null) {
                $subnet.DNS = @()
            }
        }
    }

    #Set NetworkInterface ResourceIds if not specified
    foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
        foreach ($VMInfo in $node.VMs) {
            foreach ($nic in $VMInfo.NICs) {
                if ([String]::IsNullOrEmpty($nic.Name)) {
                    $nic.Name = $nic.LogicalNetwork
                }
            }
        }
    }

    #Populate mac addresses if not specified for each VM

    if (![string]::IsNullOrEmpty($AllNodes[0].VMMACAddressPoolStart)) 
    {
        $nextmac = ($AllNodes[0].VMMACAddressPoolStart -replace '[\W]', '')
        write-verbose "Starting MAC is $nextmac"

        foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
            foreach ($VMInfo in $node.VMs) {
                foreach ($nic in $VMInfo.NICs) {

                    if ([String]::IsNullOrEmpty($nic.MacAddress)) {
                        $nic.MacAddress = $nextmac
                        $intmac = [long]::Parse($nextmac, [System.Globalization.NumberStyles]::HexNumber)
                        $nextmac = "{0:x12}" -f ($intmac + 1) 
                        write-verbose "Assigned MAC $($nic.MacAddress) to [$($vminfo.VMname)] [$($nic.Name)]"
                    } else {
                        $nic.MacAddress = $nic.MacAddress -replace '[\W]', ''
                    }

                    # Normalize the Mac Addresses
                    $nic.MacAddress = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
                }
            }
        }
    }

    #Set NetworkInterface ResourceIds if not specified
    foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
        foreach ($VMInfo in $node.VMs) {
            foreach ($nic in $VMInfo.NICs) {
                if ([String]::IsNullOrEmpty($nic.PortProfileId)) {
                    $vmnode = $AllNodes.Where{$_.NodeName -eq $vminfo.VMName}
                    
                    switch ($vmnode.Role)
                    { 
                        "NetworkController" {
                            write-verbose "VM $($vminfo.vmname) is a Network Controller"
                            $nic.PortProfileId = [System.Guid]::Empty.Guid
                            $nic.PortProfileData = 1
                        }
                        "SLBMUX" {
                            write-verbose "VM $($vminfo.VMname) is a MUX"
                            $nic.PortProfileId = [System.Guid]::Empty.Guid
                            $nic.PortProfileData = 2
                        }
                        default {
                            write-verbose "VM $($vminfo.VMname) is a Gateway or Other"
                            $nic.PortProfileId = "$($VMInfo.VMName)_$($nic.Name)"
                            $nic.PortProfileData = 1
                        }
                    }

                }
            }
        }
    }

    $IsFirst = $true
    $RingMembers = @()
    foreach ($node in $AllNodes.Where{$_.Role -eq "NetworkController"}) {
        if ($IsFirst) {
            $firstnode = $node
            $IsFirst = $false
        }
        $RingMembers += $node.NodeName
    }

    if ($firstnode.ServiceFabricRingMembers -eq $null) {
        write-verbose "Service Fabric ring members: $RingMembers"
        $firstnode.ServiceFabricRingMembers = $RingMembers
    }

    foreach ($node in $AllNodes.Where{$_.Role -eq "SLBMUX"}) {
        If ([String]::IsNullOrEmpty($node.MuxVirtualServerResourceId)) 
        {
            write-verbose "Setting a MuxVirtualServerResourceId to $($node.NodeName)"
            $node.MuxVirtualServerResourceId = $node.NodeName
        }
        If ([String]::IsNullOrEmpty($node.MuxResourceId)) 
        {
            write-verbose "Setting a MuxResourceId to $($node.NodeName)"
            $node.MuxResourceId = $node.NodeName
        }
        If ([String]::IsNullOrEmpty($node.HnvPaMac)) 
        {
            foreach ($hvnode in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
                foreach ($VMInfo in $hvnode.VMs) {
                    if ($VMInfo.VMName -eq $node.NodeName) {
                        foreach ($nic in $VMInfo.NICs) {
                            if ($nic.Name -eq $node.InternalNicName) {
                                write-verbose "Setting Mux HnvPaMac to $($nic.MAcAddress)"
                                $node.HnvPaMac = $nic.MacAddress
                            }
                        }
                    }
                }
            }
        }

        # Normalize the Mac Addresses
        $node.HnvPaMac = [regex]::matches($node.HnvPaMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
    }

    foreach ($node in $AllNodes.Where{$_.Role -eq "Gateway"}) {
        
        foreach ($hvnode in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
            foreach ($VMInfo in $hvnode.VMs) {
                if ($VMInfo.VMName -eq $node.NodeName) {
                    $VMInfo.VMRole = "Gateway"
                    
                    foreach ($nic in $VMInfo.NICs) {
                        if ($nic.Name -eq $node.InternalNicName)
                        {
                            If ([String]::IsNullOrEmpty($node.InternalNicMAC)) 
                            {
                                write-verbose "Setting a InternalNicMAC to $($nic.MAcAddress)"
                                $node.InternalNicMac = $nic.MacAddress
                            }
                        }
                        elseif ($nic.Name -eq $node.ExternalNicName)
                        {
                            If ([String]::IsNullOrEmpty($node.ExternalNicMAC)) 
                            {
                                write-verbose "Setting a ExternalNicMAC to $($nic.MacAddress)"
                                $node.ExternalNicMac = $nic.MacAddress
                            } 

                            If ([String]::IsNullOrEmpty($node.ExternalIPAddress)) 
                            {
                                write-verbose "Setting a ExternalIPAddress to $($nic.IPAddress)"
                                $node.ExternalIPAddress = $nic.IPAddress
                            }

                            write-verbose "Setting a ExternalLogicalNetwork to $($nic.LogicalNetwork)"
                            $node.ExternalLogicalNetwork = $nic.LogicalNetwork
                        }

                    }
                    if ([string]::IsNullOrEmpty($VMInfo.InternalNicPortProfileId)) {
                        write-verbose "Setting gateway VM InternalNicPortProfileId to $($node.NodeName)_Internal"
                        $VMInfo.InternalNicPortProfileId = $node.NodeName+"_Internal"
                    }
                    if ([string]::IsNullOrEmpty($VMInfo.ExternalNicPortProfileId)) {
                        write-verbose "Setting gateway VM ExternalNicPortProfileId to $($node.NodeName)_external"
                        $VMInfo.ExternalNicPortProfileId = $node.NodeName+"_External"
                    }
                }
            }
        }

        write-verbose "Gateway Internal MAC is $($node.InternalNicMac) before normalization."
        write-verbose "Gateway External MAC is $($node.ExternalNicMac) before normalization."

        # Normalize the Mac Addresses
        $node.InternalNicMac = [regex]::matches($node.InternalNicMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
        $node.ExternalNicMac = [regex]::matches($node.ExternalNicMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
        
        If ([String]::IsNullOrEmpty($node.InternalNicPortProfileId)) 
        {
            write-verbose "Setting gateway node InternalNicPortProfileId to $($node.NodeName)_Internal"
            $node.InternalNicPortProfileId = $node.NodeName+"_Internal"
        }
        If ([String]::IsNullOrEmpty($node.ExternalNicPortProfileId)) 
        {
            write-verbose "Setting gateway node ExternalNicPortProfileId to $($node.NodeName)_External"
            $node.ExternalNicPortProfileId = $node.NodeName+"_External"
        }
    }

    write-verbose "Finished populating defaults."
}



function CleanupMOFS
{  
    Remove-Item .\SetHyperVWinRMEnvelope -Force -Recurse 2>$null
    Remove-Item .\DeployVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureNetworkControllerVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureMuxVMs -Force -Recurse 2>$null
    Remove-Item .\CreateControllerCert -Force -Recurse 2>$null
    Remove-Item .\InstallControllerCerts -Force -Recurse 2>$null
    Remove-Item .\EnableNCTracing -Force -Recurse 2>$null
    Remove-Item .\DisableNCTracing -Force -Recurse 2>$null    
    Remove-Item .\ConfigureNetworkControllerCluster -Force -Recurse 2>$null
    Remove-Item .\ConfigureGatewayPoolsandPublicIPAddress -Force -Recurse 2>$null
    Remove-Item .\ConfigureSLBMUX -Force -Recurse 2>$null
    Remove-Item .\ConfigureGatewayVMs -Force -Recurse 2>$null
    Remove-Item .\AddGatewayNetworkAdapters -Force -Recurse 2>$null
    Remove-Item .\ConfigureGatewayNetworkAdapterPortProfiles -Force -Recurse 2>$null
    Remove-Item .\ConfigureGateway -Force -Recurse 2>$null
    Remove-Item .\CopyToolsAndCerts -Force -Recurse 2>$null
    Remove-Item .\CleanUp -Force -Recurse 2>$null
    Remove-Item .\ConfigureSLBHostAgent -Force -Recurse 2>$null
    Remove-Item .\ConfigureServers -Force -Recurse 2>$null
    Remove-Item .\ConfigureHostAgent -Force -Recurse 2>$null
    Remove-ITem .\ConfigureHostNetworkingPreNCSetup -Force -Recurse 2>$null 
    Remove-ITem .\ConfigureIDns -Force -Recurse 2>$null
    Remove-ITem .\ConfigureIDnsProxy -Force -Recurse 2>$null 
}

function CompileDSCResources
{
    SetHyperVWinRMEnvelope -ConfigurationData $ConfigData -verbose
    DeployVMs -ConfigurationData $ConfigData -verbose
    ConfigureNetworkControllerVMs -ConfigurationData $ConfigData -verbose
    ConfigureMuxVMs -ConfigurationData $ConfigData -verbose
    CreateControllerCert -ConfigurationData $ConfigData -verbose
    InstallControllerCerts -ConfigurationData $ConfigData -verbose
    EnableNCTracing -ConfigurationData $ConfigData -verbose
    DisableNCTracing -ConfigurationData $Configdata -verbose
    ConfigureNetworkControllerCluster -ConfigurationData $ConfigData -verbose
    ConfigureGatewayPoolsandPublicIPAddress -ConfigurationData $ConfigData -verbose
    ConfigureSLBMUX -ConfigurationData $ConfigData -verbose 
    ConfigureGatewayVMs -ConfigurationData $ConfigData -verbose
    AddGatewayNetworkAdapters -ConfigurationData $ConfigData -verbose 
    ConfigureGatewayNetworkAdapterPortProfiles  -ConfigurationData $ConfigData -verbose 
    ConfigureGateway -ConfigurationData $ConfigData -verbose
    CopyToolsAndCerts -ConfigurationData $ConfigData -verbose
    CleanUp -ConfigurationData $ConfigData -verbose
    ConfigureServers -ConfigurationData $ConfigData -verbose
    ConfigureHostNetworkingPreNCSetup -ConfigurationData $ConfigData -verbose   
    ConfigureIDns -ConfigurationData $ConfigData -verbose 
    ConfigureIDnsProxy -ConfigurationData $ConfigData -verbose
}



if ($psCmdlet.ParameterSetName -ne "NoParameters") {

    $global:stopwatch = [Diagnostics.Stopwatch]::StartNew()

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

    $originalExecutionPolicy = Get-ExecutionPolicy

    try
    {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
        Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000

        write-verbose "STAGE 1: Housekeeping"

        CheckCompatibility -ScriptVer $ScriptVersion -ConfigVer $configData.AllNodes[0].ConfigFileVersion
        CleanupMOFS
        PopulateDefaults $ConfigData.AllNodes

        write-verbose "STAGE 2.1: Compile DSC resources"

        CompileDSCResources
    
        write-verbose "STAGE 2.2: Set WinRM envelope size on hosts"

        Start-DscConfiguration -Path .\SetHyperVWinRMEnvelope -Wait -Force -Verbose -Erroraction Stop
        WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("HyperVHost")) -checkpendingreboot

        write-verbose "STAGE 3: Deploy VMs"

        Start-DscConfiguration -Path .\DeployVMs -Wait -Force -Verbose -Erroraction Stop
        WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController", "SLBMUX", "Gateway"))

        write-verbose "STAGE 4: Install Network Controller nodes"

        Start-DscConfiguration -Path .\ConfigureNetworkControllerVMs -Wait -Force -Verbose -Erroraction Stop
        Start-DscConfiguration -Path .\ConfigureMuxVMs -Wait -Force -Verbose -Erroraction Stop
        
        WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController", "SLBMUX")) -CheckPendingReboot 

        write-verbose "STAGE 5.1: Generate controller certificates"
        
        Start-DscConfiguration -Path .\CreateControllerCert -Wait -Force -Verbose -Erroraction Stop

        write-verbose "STAGE 5.2: Gather controller certificates"
        
        GatherCerts -ConfigData $ConfigData

        write-verbose "STAGE 6: Distribute Tools and Certs to all nodes"

        Start-DscConfiguration -Path .\CopyToolsAndCerts -Wait -Force -Verbose -Erroraction Stop

        write-verbose "STAGE 7: Install controller certificates"

        Start-DscConfiguration -Path .\InstallControllerCerts -Wait -Force -Verbose -Erroraction Stop

        write-verbose "STAGE 8: Configure Hyper-V host networking (Pre-NC)"

        Start-DscConfiguration -Path .\ConfigureHostNetworkingPreNCSetup -Wait -Force -Verbose -Erroraction Stop
     
        try
        {

            write-verbose "STAGE 9.1: Configure NetworkController cluster"
            
            Start-DscConfiguration -Path .\EnableNCTracing -Wait -Force  -Verbose -Erroraction Ignore
            Start-DscConfiguration -Path .\ConfigureNetworkControllerCluster -Wait -Force -Verbose -Erroraction Stop

            write-verbose "STAGE 9.2: ConfigureGatewayPools and PublicIPAddress"        
            Start-DscConfiguration -Path .\ConfigureGatewayPoolsandPublicIPAddress -Wait -Force -Verbose -Erroraction Stop
            
            write-verbose ("Importing NC Cert to trusted root store of deployment machine" )
            $scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
            . "$($scriptPath)\certhelpers.ps1"
            AddCertToLocalMachineStore "$($configData.AllNodes[0].installsrcdir)\$($configData.AllNodes[0].certfolder)\$($configData.AllNodes[0].NetworkControllerRestName)" "Root"

            if (![string]::IsNullOrEmpty($configData.AllNodes[0].iDNSCredentialResourceId)) {
                write-verbose "STAGE 10.1: Configure IDNS on NC"
                ConfigureIDns -ConfigurationData $ConfigData -verbose
                Start-DscConfiguration -Path .\ConfigureIDns -Wait -Force -Verbose -ErrorAction Stop

                write-verbose "STAGE 10.2: Configure Host for IDNS"
                ConfigureIDnsProxy -ConfigurationData $ConfigData -verbose
                Start-DscConfiguration -Path .\ConfigureIDnsProxy -Wait -Force -Verbose -ErrorAction Stop
            }

            write-verbose "STAGE 11: Configure Hyper-V host networking (Post-NC)"
            write-verbose "STAGE 11: Configure Servers and HostAgents"

            ConfigureSLBHostAgent -ConfigurationData $ConfigData -verbose
            Start-DscConfiguration -Path .\ConfigureSLBHostAgent -Wait -Force -Verbose -Erroraction Stop

            Start-DscConfiguration -Path .\ConfigureServers -Wait -Force -Verbose -Erroraction Stop

            ConfigureHostAgent -ConfigurationData $ConfigData -verbose
            Start-DscConfiguration -Path .\ConfigureHostAgent -Wait -Force -Verbose -Erroraction Stop
        
            write-verbose "STAGE 12: Configure SLBMUXes"
            
            if ((Get-ChildItem .\ConfigureSLBMUX\).count -gt 0) {
                Start-DscConfiguration -Path .\ConfigureSLBMUX -wait -Force -Verbose -Erroraction Stop
            } else {
                write-verbose "No muxes defined in configuration."
            }
        
            write-verbose "STAGE 13: Configure Gateways"
            if ((Get-ChildItem .\ConfigureGateway\).count -gt 0) {

                write-verbose "STAGE 13.1: Configure Gateway VMs"

                Start-DscConfiguration -Path .\ConfigureGatewayVMs -Wait -Force -Verbose -Erroraction Stop

                write-verbose "STAGE 13.2: Add additional Gateway Network Adapters"
        
                Start-DscConfiguration -Path .\AddGatewayNetworkAdapters -Wait -Force -Verbose -Erroraction Stop
                WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("Gateway"))

                # This is a quick fix to make sure we get stable PS Sessions for GW VMs
                RestartRoleMembers -ConfigData $ConfigData -RoleNames @("Gateway") -Wait -Force
                WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("Gateway"))

                Write-verbose "Sleeping for 60 sec before starting Gateway configuration"
                Sleep 60
                
                write-verbose "STAGE 13.3: Configure Gateways"

                Start-DscConfiguration -Path .\ConfigureGateway -wait -Force -Verbose -Erroraction Stop
                
                Write-verbose "Sleeping for 30 sec before plumbing the port profiles for Gateways"
                Sleep 30
                
                write-verbose "STAGE 13.4: Configure Gateway Network Adapter Port profiles"

                Start-DscConfiguration -Path .\ConfigureGatewayNetworkAdapterPortProfiles -wait -Force -Verbose -Erroraction Stop
            } else {
                write-verbose "No gateways defined in configuration."
            }
        }
        catch {
            Write-Verbose "Exception: $_"
            throw
        }
        finally
        {
            Write-Verbose "Disabling tracing for NC."
            Start-DscConfiguration -Path .\DisableNCTracing -Wait -Force -Verbose -Erroraction Ignore
        }

        Write-Verbose "Cleaning up."
        Start-DscConfiguration -Path .\CleanUp -Wait -Force -Verbose -Erroraction Ignore

        CleanupMOFS
        
        $global:stopwatch.stop()
        write-verbose "TOTAL RUNNING TIME: $($global:stopwatch.Elapsed.ToString())"
    }
    finally {
        Set-ExecutionPolicy -ExecutionPolicy $originalExecutionPolicy -Scope Process
    }
}
