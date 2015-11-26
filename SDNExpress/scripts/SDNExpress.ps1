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



Configuration SetHyperVWinRMEnvelope
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        Script SetWinRmEnvelope
        {                                      
            SetScript = {
                write-verbose "Settign WinRM Envelope size."
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 5000
            }
            TestScript = {
                return ((Get-Item WSMan:\localhost\MaxEnvelopeSizekb).Value -ge 5000)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration DeployVMs
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’

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
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
{1}
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
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
"@

                    $dstfile = $using:node.MountDir+$($Using:VMInfo.VMName)+"\unattend.xml"

                    $alldns = ""
                    $count = 1
                    $allnics = ""

                    foreach ($nic in $using:vminfo.Nics) {
                        foreach ($ln in $using:node.LogicalNetworks) {
                            if ($ln.Name -eq $nic.LogicalNetwork) {
                                break
                            }
                        }

                        if (![String]::IsNullorEmpty($nic.IPAddress))
                        {
                            #TODO: Right now assumes there is one subnet.  Add code to find correct subnet given IP.
                        
                            $sp = $ln.subnets[0].AddressPrefix.Split("/")
                            $mask = $sp[1]

                            #TODO: Add in custom routes since multi-homed VMs will need them.
                        
                            $gateway = $ln.subnets[0].gateways[0]
                            $allnics += $interfacetemplate -f $nic.IPAddress, $mask, $gateway

                            foreach ($dns in $ln.subnets[0].DNS) {
                                $alldns += '<IpAddress wcm:action="add" wcm:keyValue="{1}">{0}</IpAddress>' -f $dns, $count++
                            }
                        }
                    }
                    
                    $key = ""
                    if ($($Using:node.productkey) -ne "" ) {
                        $key = "<ProductKey>$($Using:node.productkey)</ProductKey>"
                    }
                    $finalUnattend = ($unattendfile -f $allnics, $alldns, $($Using:vminfo.vmname), $($Using:node.fqdn), $($Using:node.DomainJoinUsername), $($Using:node.DomainJoinPassword), $($Using:node.LocalAdminPassword), $key )
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
                    New-VM -Generation 2 -Name $VMInfo.VMName -Path ($using:node.VMLocation+"\"+$($VMInfo.VMName)) -MemoryStartupBytes 8GB -VHDPath ($using:node.VMLocation+"\"+$($using:VMInfo.VMName)+"\"+$using:node.VHDName) -SwitchName $using:node.vSwitchName 
                    write-verbose "Setting processor count"
                    set-vm -Name $VMInfo.VMName -processorcount 8
                    write-verbose "renaming default network adapter"
                    get-vmnetworkadapter -VMName $VMInfo.VMName | rename-vmnetworkadapter -newname $using:VMInfo.Nics[0].Name
                    write-verbose "Adding $($VMInfo.Nics.Count-1) additional adapters"
                    
                    for ($i = 1; $i -lt $VMInfo.Nics.Count; i++) {
                        write-verbose "Adding adapter $($VMInfo.Nics[$i].Name)"
                        Add-VMNetworkAdapter -VMName $VMInfo.VMName -SwitchName $using:node.vSwitchName -Name $VMInfo.Nics[$i].Name -StaticMacAddress $VMInfo.Nics[$i].MACAddress
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
                Script "SetPortAndProfile_$($VMInfo.VMName)_$($nic.Name)"
                {                                      
                    SetScript = {
                        . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"

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
                        Set-VMNetworkAdapterIsolation -vmname $vminfo.VMname –vmnetworkadaptername $nic.Name -AllowUntaggedTraffic $true -IsolationMode VLAN -defaultisolationid $ln.subnets[0].vlanid
                        write-verbose "Setting port profile"
                        Set-PortProfileId -ResourceID $nic.portprofileid -vmname $using:vminfo.vmName -computername localhost -ProfileData $nic.portprofiledata -Force
                        write-verbose "completed setport"
                    }
                    TestScript = {
                        $vlans = Get-VMNetworkAdapterIsolation –VMName $using:vminfo.VMName –vmnetworkadaptername $nic.Name
                        if($vlans -eq $null) {
                            return $false
                        } 
                        else {
                            foreach ($ln in $using:node.LogicalNetworks) {

                                if ($ln.Name -eq $using:nic.LogicalNetwork) {
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
                        return @{ result = (Get-VMNetworkAdapterVlan –VMName $using:vminfo.VMName)[0] }
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
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’
    Node $AllNodes.Where{$_.Role -eq "NetworkController"}.NodeName
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        File ToolsDirectory
        {
            Type = "Directory"
            Ensure = "Present"
            Force = $True
            Recurse = $True
            SourcePath = $node.InstallSrcDir+"\"+$node.ToolsSrcLocation
            DestinationPath = $node.ToolsLocation
                    
        }        

        Script SetWinRmEnvelope
        {                                      
            SetScript = {
                write-verbose "Settign WinRM Envelope size."
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 5000
            }
            TestScript = {
                return ((Get-Item WSMan:\localhost\MaxEnvelopeSizekb).Value -ge 5000)
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script SetAllHostsTrusted
        {                                      
            SetScript = {
                write-verbose "Trusting all hosts."
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
        Script CreateNodeCert
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $nccertname = "$($using:node.nccertname)"

                $cn = "$($using:node.nodename).$($using:node.fqdn)".ToUpper()

                GenerateSelfSignedCertificate $cn

                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject -eq "CN=$cn"}
                GivePermissionToNetworkService $Cert[0]
                write-verbose "Exporting certificate to: [c\$nccertname]"
                Export-Certificate -Type CERT -FilePath "c:\$nccertname" -cert $cert
                write-verbose "Adding to local machine store."
                AddCertToLocalMachineStore "c:\$nccertname" "Root"
            } 
            TestScript = {
                $cn = "$($using:node.nodename).$($using:node.fqdn)".ToUpper()
                
                $cert = get-childitem "Cert:\localmachine\my" -ErrorAction Ignore | where {$_.Subject -eq "CN=$cn"}
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\my cert not found.")
                    return $false
                }
                
                $nccertname = "$($using:node.nccertname)"
                write-verbose ("cert:\localmachine\my cert found.  Checking for c:\$nccertname.")
                $certfile = get-childitem "c:\$nccertname"  -ErrorAction Ignore
                if ($certfile -eq $null) {
                    write-verbose ("$nccertname not found.")
                    return $false
                }
                
                return $true
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
        Script ForceRestart
        {                                      
            SetScript = {
                Restart-computer -Force -Confirm:$false -AsJob
            }
            TestScript = {
                $nc = try { get-networkcontroller } catch { }
                return ($nc -ne $null)
            }
            GetScript = {
                return @{ result = $true }
            }
        } 

    }
}

Configuration CreateControllerCert
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        Script CreateRESTCert
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $nccertname = "rest.$($using:node.nccertname)"

                GenerateSelfSignedCertificate "$($using:node.NetworkControllerRestName)"

                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject -eq "CN=$cn"}
                GivePermissionToNetworkService $Cert[0]
                write-verbose "Exporting certificate to: [c\$nccertname]"
                [System.io.file]::WriteAllBytes("c:\$nccertname.pfx", $cert.Export("PFX", "secret"))
                Export-Certificate -Type CERT -FilePath "c:\$nccertname" -cert $cert
                write-verbose "Adding to local machine store."
                AddCertToLocalMachineStore "c:\$nccertname" "Root"
            } 
            TestScript = {
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                
                write-verbose ("Checking network controller cert configuration.")
                $cert = get-childitem "Cert:\localmachine\my" -ErrorAction Ignore | where {$_.Subject -eq "CN=$cn"}
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\my cert not found.")
                    return $false
                }
                
                $nccertname = "$($using:node.nccertname)"
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
    }
}
Configuration DistributeControllerCerts
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’
    Node $AllNodes.Where{$_.Role -eq "NetworkController"}.NodeName
    {
        Script InstallRESTCert
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $certpath = "$($using:node.installsrcdir)\$($using:node.certfolder)"
                $nccertname = "rest.$($using:node.nccertname)"

                write-verbose "Adding to local machine store from $certpath\$nccertname."

                AddCertToLocalMachineStore "$certpath\$nccertname.pfx" "My" "secret"
                
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.subject.ToUpper().StartsWith("CN=$cn")}    
                if ($cert -eq $null) {
                    write-error ("Cert $cn in cert:\localmachine\my not found.")
                }             
                GivePermissionToNetworkService $cert

                AddCertToLocalMachineStore "$certpath\$nccertname" "Root"

            } 
            TestScript = {
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()

                write-verbose ("$cn found.  Checking for cert in cert:\localmachine\my")
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.subject.ToUpper().StartsWith("CN=$cn")}
                if ($cert -eq $null) {
                    write-verbose ("Cert in cert:\localmachine\my not found.")
                    return $false
                }
                write-verbose ("Cert found in cert:\localmachine\my.  Cert creation not needed.")
                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script InstallNodeCerts
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"

                $certpath = "$($using:node.installsrcdir)\$($using:node.certfolder)"
                $nccertname = "$($using:node.nccertname)"

                foreach ($othernode in $using:allnodes) {
                    if ($othernode.Role -eq "NetworkController") {
                       # if ($othernode.NodeName -ne $using:node.nodename) {
                            $cn = "$($othernode.nodename).$($using:node.fqdn)".ToUpper()

                            write-verbose ("Checking $cn in cert:\localmachine\root")
                            $cert = get-childitem "Cert:\localmachine\root" | where {$_.subject.ToUpper().StartsWith("CN=$cn")}

                            if ($cert -eq $null) {
                                $certfullpath = "$certpath\$($othernode.nodename).$nccertname"
                                write-verbose "Adding $($othernode.nodename) cert to root store from $certfullpath"
                                AddCertToLocalMachineStore $certfullpath "root"
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
Configuration ConfigureNetworkControllerCluster
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        Script StartNCTracing
        {
            SetScript = {
                cmd /c "netsh trace start globallevel=5 provider={28F7FB0F-EAB3-4960-9693-9289CA768DEA} provider={A6527853-5B2B-46E5-9D77-A4486E012E73} provider={41DC7652-AAF6-4428-BBBB-CFBDA322F9F3} provider={F2605199-8A9B-4EBD-B593-72F32DEEC058} provider={dbc217a8-018f-4d8e-a849-acea31bc93f9} report=di tracefile=c:\networktrace.etl"
            } 
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }            
      
        Script CreateControllerCluster
        {                                      
            SetScript = {
                $nc = try { get-networkcontroller } catch { }
                if ($nc -ne $null) {
                    write-verbose ("Attempting cleanup of network controller.")
                    uninstall-networkcontroller -Force
                }
                $ncc = try { get-networkcontrollercluster } catch { }
                if ($ncc -ne $null) {
                    write-verbose ("Attempting cleanup of network controller cluster.")
                    uninstall-networkcontrollercluster -Force
                }

                $nodes = @()
                foreach ($server in $using:node.ServiceFabricRingMembers) {
                    write-verbose ("Clearing existing node content.")
                    try { clear-networkcontrollernodecontent -Force } catch { }

                    $cn = "$server.$($using:node.FQDN)".ToUpper()
                    $cert = get-childitem "Cert:\localmachine\root" | where {$_.Subject.ToUpper() -eq "CN=$cn"}
                    if ($cert -eq $null) {
                        write-error "Certificate not found for $cn in Root store" 
                    }
                    write-verbose ("Adding node: {0}.{1}" -f $server, $using:node.FQDN)
                    $nodes += New-NetworkControllerNodeObject -Name $server -Server ($server+"."+$using:node.FQDN) -FaultDomain ("fd:/"+$server) -RestInterface "Ethernet" -NodeCertificate $cert -verbose
                }

                $mgmtSecurityGroupName = $using:node.mgmtsecuritygroupname
                $clientSecurityGroupName = $using:node.clientsecuritygroupname
                
                $cn = "$($using:node.NetworkControllerRestName)".ToUpper()
                $cert = get-childitem "Cert:\localmachine\root" | where {$_.Subject -eq "CN=$cn"}
                
                write-verbose "Using cert with subject $($cert.subject)"
                
                $pwd = ConvertTo-SecureString $using:node.NCClusterPassword -AsPlainText -Force; 
                $cred = New-Object System.Management.Automation.PSCredential $using:node.NCClusterUsername, $pwd; 

                if ([string]::isnullorempty($mgmtSecurityGroupName)) {
                    Install-NetworkControllerCluster -Node $nodes -ClusterAuthentication X509 -credentialencryptioncertificate $cert -Credential $cred -force -verbose
                } else {
                    Install-NetworkControllerCluster -Node $nodes -ClusterAuthentication Kerberos -ManagementSecurityGroup $mgmtSecurityGroupName -credentialencryptioncertificate $cert -Force -Verbose
                }

                if ($using:node.UseHttp -eq $true) {
                    [Microsoft.Windows.Networking.NetworkController.PowerShell.InstallNetworkControllerCommand]::UseHttpForRest=$true
                }

                #TODO: RESTIP SUBnet needs to remove hardcoded /24
                write-verbose ("Install-networkcontroller")
                if ([string]::isnullorempty($clientSecurityGroupName)) {
                    try { Install-NetworkController -ErrorAction Ignore -Node $nodes -ClientAuthentication None -ServerCertificate $cert  -Credential $cred -Force -Verbose -restipaddress "$($using:node.NetworkControllerRestIP)/$($using:node.NetworkControllerRestIPMask)" } catch { }
                } else {
                    Install-NetworkController -Node $nodes -ClientAuthentication Kerberos -ClientSecurityGroup $clientSecurityGroupName -ServerCertificate $cert  -Force -Verbose -restipaddress "$($using:node.NetworkControllerRestIP)/$($using:node.NetworkControllerRestIPMask)"
                }                
                write-verbose ("Network controller setup is complete.")
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
                    if ([String]::isnullorempty($using:node.NCUsername) -eq $false) {
                        $password =  convertto-securestring $using:node.NCPassword -asplaintext -force
                        $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $using:node.NCUsername,$password
                        $result = invoke-webrequest "https://$($using:node.NetworkControllerRestName)/Networking/v1/LogicalNetworks" -UseBasicParsing -credential $credential 
                    } else {
                       $result = invoke-webrequest "https://$($using:node.NetworkControllerRestName)/Networking/v1/LogicalNetworks" -UseBasicParsing
                    }
                    if ($result -eq $null) {
                        return $false;
                    }
                    return ($result.StatusCode -eq 200)
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $hostcred = New-NCCredential -ResourceId $using:node.HostCredentialResourceId -Username $using:node.HostUsername -Password $using:node.HostPassword
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $ncnotactive = $true
                while ($ncnotactive) {
                    write-verbose "Checking that the controller is up and whether or not it has credentials yet."
                    sleep 5
                    $response = $null
                    try { 
                        if (![String]::isnullorempty($using:node.ncUsername)) {
                            $securepass =  convertto-securestring $using:node.ncPassword -asplaintext -force
                            $credentials = new-object -typename System.Management.Automation.PSCredential -argumentlist $using:node.ncUsername,$securepass
                            $response = invoke-webrequest https://$($using:node.NetworkControllerRestName)/Networking/v1/Credentials -usebasicparsing  -ErrorAction SilentlyContinue -credential $credential 
                        } else {
                            $response = invoke-webrequest https://$($using:node.NetworkControllerRestName)/Networking/v1/Credentials -usebasicparsing  -ErrorAction SilentlyContinue
                        }
                    } catch { }
                    $ncnotactive = ($response -eq $null)
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword

                $cn = "$($using:node.NetworkControllerRestName)"
                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject -eq "CN=$cn"}
                write-verbose "got cert with cn=$cn"
                $hostcred = New-NCCredential -ResourceId $using:node.NCCredentialResourceId -Thumbprint $cert.Thumbprint
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
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
                    . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                    $subnets = @()
                    foreach ($subnet in $using:ln.Subnets) {
                        if ($subnet.IsPublic) {
                            $subnets += New-NCLogicalNetworkSubnet -AddressPrefix $subnet.AddressPrefix -VLANId $subnet.vlanid -DNSServers $subnet.DNS -defaultGateway $subnet.Gateways -IsPublic
                        } else {
                            $subnets += New-NCLogicalNetworkSubnet -AddressPrefix $subnet.AddressPrefix -VLANId $subnet.vlanid -DNSServers $subnet.DNS -defaultGateway $subnet.Gateways
                        }
                    }

                    if ($ln.NetworkVirtualization) {
                        $newln = New-NCLogicalNetwork -resourceId $using:ln.ResourceId -LogicalNetworkSubnets $subnets -EnableNetworkVirtualization 
                    } 
                    else
                    {
                        $newln = New-NCLogicalNetwork -resourceId $using:ln.ResourceId -LogicalNetworkSubnets $subnets
                    }

                    $i = 0
                    foreach ($subnet in $using:ln.Subnets) {
                        $ippool = New-NCIPPool -LogicalNetworkSubnet $newln.properties.subnets[$i++]  -StartIPAddress $subnet.PoolStart -EndIPAddress $subnet.PoolEnd -DNSServers $subnet.DNS -DefaultGateways $subnet.Gateways
                    }
                } 
                TestScript = {
                    . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $LogicalNetworks = Get-NCLogicalNetwork #-resourceId $using:node.VIPLogicalNetworkResourceId

                $vipippools = @()
                $slbmip = ""

                write-verbose "Finding public subnets to use as VIPs."

                foreach ($ln in $logicalNetworks) {
                    write-verbose "Checking $($ln.resourceid)."
                    foreach ($subnet in $ln.properties.subnets) {
                        write-verbose "subnet $($subnet.properties.addressprefix)."
                        if ($subnet.properties.isPublic -eq "True") {
                            write-verbose "Found public subnet."
                            $vipippools += $subnet.properties.ippools
                            if ($slbmip -eq "") {
                                $slbmip = $subnet.properties.ippools[0].properties.startIpAddress
                                write-verbose "SLBMVIP is $slbmip."
                            }
                        }
                    }
                }

                $lbconfig = set-ncloadbalancermanager -IPAddress $slbmip -VIPIPPools $vipippools -OutboundNatIPExemptions @("$slbmip/32")

                $pwd = ConvertTo-SecureString $using:node.NCClusterPassword -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential $using:node.NCClusterUsername, $pwd

                #write-verbose "Resetting SLBM VIP [$slbmip] prefix to /32 on $($using:node.ServiceFabricRingMembers)"
                
                Invoke-Command -ComputerName $using:node.ServiceFabricRingMembers -credential $cred -Argumentlist $slbmip -ScriptBlock { 
                    param($slbmip2)

                    $ip = $null

                    while ($ip -eq $null) 
                    {
                        write-host "Waiting for SLBM VIP [$slbmip2] to be created"
                        sleep 1
                        $ip = get-netipaddress $slbmip2 -ErrorAction Ignore
                    }
                    write-host "Forcing SLBM VIP prefix length to 32"
                    set-netipaddress $slbmip2 -prefixlength 32
                }
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $ipAddress = New-NCPublicIPAddress -ResourceID $using:node.PublicIPResourceId -PublicIPAddress $using:node.GatewayPublicIPAddress
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $macpool = New-NCMacPool -ResourceId $using:node.MACAddressPoolResourceId -StartMACAddress $using:node.MACAddressPoolStart -EndMACAddress $using:node.MACAddressPoolEnd
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $obj = Get-NCMacPool -ResourceId $using:node.MACAddressPoolResourceId
                return $obj -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script ConfigureGatewayPools
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                # Get the Gre VIP Subnet Resource Ref
                foreach ($ln in $node.LogicalNetworks)
                {
                    if ($ln.Name -eq "GreVIP")
                    {
                        $greVipLogicalNetworkResourceId = $ln.ResourceId
                    }
                }

                $greVipNetworkObj = Get-NCLogicalNetwork -ResourceID $greVipLogicalNetworkResourceId
                $greVipSubnetResourceRef = $greVipNetworkObj.properties.subnets[0].resourceRef

                foreach ($gatewayPool in $node.GatewayPools) {
<#                    switch ($gatewayPool.Type)
                    {
                        "All"        { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -GreVipSubnetResourceRef $greVipSubnetResourceRef `
                                                -PublicIPAddressId $using:node.PublicIPResourceId -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }

                        "S2sIpSec"   { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -PublicIPAddressId $using:node.PublicIPResourceId `
                                                -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }

                        "Gre"        { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -GreVipSubnetResourceRef $greVipSubnetResourceRef `
                                                -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }

                        "Forwarding" { $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount }
                    }#>
                    $gwPool = New-NCGatewayPool -ResourceId $gatewayPool.ResourceId -Type $gatewayPool.Type -GreVipSubnetResourceRef $greVipSubnetResourceRef `
                                                -PublicIPAddressId $using:node.PublicIPResourceId -Capacity $gatewayPool.Capacity -RedundantGatewayCount $gatewayPool.RedundantGatewayCount
                }
                
            }
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                # retrieve the first GW Pool to check if exists
                $obj = Get-NCGatewayPool -ResourceId $using:node.GatewayPools[0].ResourceId
                return $obj -ne $null 
            }
            GetScript = {
                return @{ result = $true }
            }
        }        

        Script StopNCTracing
        {
            SetScript = {
                cmd /c "netsh trace stop"
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

Configuration ConfigureSLBMUX
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’
    Node $AllNodes.Where{$_.Role -eq "SLBMUX"}.NodeName
    {
        Script DoAllCerts
        {                                      
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
	            $ControllerCertificateFolder="$($using:node.installsrcdir)\$($using:node.certfolder)\rest.$($using:node.NCCertName)"	
                $certName = (GetSubjectName($true)).ToLower()
                $certPath = "c:\$certName.cer"

                write-verbose "Creating self signed certificate if not exists...";
                GenerateSelfSignedCertificate $certName;

                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject -eq "CN=$certName"}

                $muxCertSubjectFqdn = GetSubjectFqdnFromCertificate $cert 
  
                Write-Verbose "Giving permission to network service for the mux certificate";
                GivePermissionToNetworkService $cert

	            Write-Verbose "Adding Network Controller Certificates to trusted Root Store"
	            AddCertToLocalMachineStore $ControllerCertificateFolder "Root" 

                Write-Verbose "Extracting subject Name from Certificate "
                $controllerCertSubjectFqdn = GetSubjectFqdnFromCertificatePath $ControllerCertificateFolder

                Write-Verbose "Updating registry values for Mux"
                $muxService = "slbmux"
                Stop-Service -Name $muxService -ErrorAction Ignore

                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name SlbmThumb -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name SlbmThumb -PropertyType String -Value $controllerCertSubjectFqdn

                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name MuxCert -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name MuxCert -PropertyType String -Value $muxCertSubjectFqdn

                Write-Verbose "Setting slbmux service to autostart"
                Set-Service $muxService -StartupType Automatic

                Write-Verbose "Starting slbmux service"
                Start-Service -Name $muxService

                Get-ChildItem -Path WSMan:\localhost\Listener | Where {$_.Keys.Contains("Transport=HTTPS") } | Remove-Item -Recurse -Force
                New-Item -Path WSMan:\localhost\Listener -Address * -HostName $certName -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force

                Write-Verbose "Enabling firewall rule for software load balancer mux"
                Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule
            }
            TestScript = {
                $ControllerCertificateFolder="$($using:node.installsrcdir)\$($using:node.certfolder)\rest.$($using:node.NCCertName)"	
                
                write-verbose ("Checking network controller cert configuration.")
                $cert = get-childitem "Cert:\localmachine\my" -ErrorAction Ignore 
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\my cert not found.")
                    return $false
                }
                
                if ((get-Service "slbmux").Status -ne "Running") {
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword

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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $vsrv = get-ncvirtualserver -ResourceId $using:node.MuxVirtualServerResourceId

                $peers = @()
                $peers += New-NCLoadBalancerMuxPeerRouterConfiguration -RouterName $using:node.MuxPeerRouterName -RouterIPAddress $using:node.MuxPeerRouterIP -peerASN $using:node.MuxPeerRouterASN
                $mux = New-ncloadbalancerMux -ResourceId $using:node.MuxResourceId -LocalASN $using:node.MuxASN -peerRouterConfigurations $peers -VirtualServer $vsrv

            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                $obj = Get-ncloadbalancerMux -ResourceId $using:node.MuxResourceId
                return $obj -ne $null 
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}


Configuration AddNetworkAdapter
{
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $GatewayVMList = ($node.VMs | ? {$_.VMRole -eq "Gateway"})
                
        foreach ($VMInfo in $GatewayVMList) {
            Script "AddGatewayNetworkAdapter_$($VMInfo.VMName)"
            {
                SetScript = {                    
                    $vm = Get-VM -VMName $using:VMInfo.VMName -ErrorAction stop
                    Stop-VM $vm -ErrorAction stop

                    Add-VMNetworkAdapter -VMName $using:VMInfo.VMName -SwitchName $using:node.vSwitchName -Name "Internal" -StaticMacAddress $using:VMInfo.InternalNicMac
                    Add-VMNetworkAdapter -VMName $using:VMInfo.VMName -SwitchName $using:node.vSwitchName -Name "External" -StaticMacAddress $using:VMInfo.ExternalNicMac

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


Configuration ConfigureNetworkAdapterPortProfile
{
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        $GatewayVMList = ($node.VMs | ? {$_.VMRole -eq "Gateway"})
        
        foreach ($VMInfo in $GatewayVMList) {
            Script "SetPort_$($VMInfo.VMName)"
            {
                SetScript = {
                     . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"
                    
                    write-verbose ("VM - $($using:VMInfo.VMName), Adapter - Internal")
                    set-portprofileid -ResourceID $using:VMInfo.InternalNicPortProfileId -vmname $using:VMInfo.VMName -VMNetworkAdapterName "Internal" -computername localhost -ProfileData "1" -Force
                    write-verbose ("VM - $($using:VMInfo.VMName), Adapter - External")
                    set-portprofileid -ResourceID $using:VMInfo.ExternalNicPortProfileId -vmname $using:VMInfo.VMName -VMNetworkAdapterName "External" -computername localhost -ProfileData "1" -Force
                }
                TestScript = {
                    $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"

                    $adapters = Get-VMNetworkAdapter –VMName $using:VMInfo.VMName
                    $IntNic = $adapters | ? {$_.Name -eq "Internal"}
                    $ExtNic = $adapters | ? {$_.Name -eq "External"}
                    
                    $IntNicProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $IntNic
                    $ExtNicProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $ExtNic

                    if ($IntNicProfile -eq $null -and $ExtNicProfile -eq $null)
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

Configuration ConfigureGateway
{  
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’

    Node $AllNodes.Where{$_.Role -eq "Gateway"}.NodeName
    {
        WindowsFeature RemoteAccess
        {
            Ensure = "Present"
            Name = "RemoteAccess"
            IncludeAllSubFeature = $true
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

        Script InstallCerts
        {                                      
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                

	            $ControllerCertificateFolder="$($using:node.installsrcdir)\$($using:node.certfolder)\rest.$($using:node.NCCertName)"	
                $certName = (GetSubjectName($true)).ToLower()
                $certPath = "c:\$certName.cer"

                write-verbose "Creating self signed certificate if not exists...";
                GenerateSelfSignedCertificate $certName;

                $cert = get-childitem "Cert:\localmachine\my" | where {$_.Subject -eq "CN=$certName"}

                $muxCertSubjectFqdn = GetSubjectFqdnFromCertificate $cert 
  
                Write-Verbose "Giving permission to network service for the certificate";
                GivePermissionToNetworkService $cert

	            Write-Verbose "Adding Network Controller Certificates to trusted Root Store"
	            AddCertToLocalMachineStore $ControllerCertificateFolder "Root" 

                Write-Verbose "Extracting subject Name from Certificate "
                $controllerCertSubjectFqdn = GetSubjectFqdnFromCertificatePath $ControllerCertificateFolder

                Get-ChildItem -Path WSMan:\localhost\Listener | Where {$_.Keys.Contains("Transport=HTTPS") } | Remove-Item -Recurse -Force
                New-Item -Path WSMan:\localhost\Listener -Address * -HostName $certName -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force

                Write-Verbose "Enabling firewall rule"
                Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule
            }
            TestScript = {
                $ControllerCertificateFolder="$($using:node.installsrcdir)\$($using:node.certfolder)\$($using:node.NCCertName)"	
                
                write-verbose ("Checking network controller cert configuration.")
                $cert = get-childitem "Cert:\localmachine\my" -ErrorAction Ignore 
                if ($cert -eq $null) {
                    write-verbose ("cert:\localmachine\my cert not found.")
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                              
                $hostname = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).physicalhostname

                $GatewayFQDN = "$($using:node.nodename).$($using:node.fqdn)"

                $hostcred = get-nccredential -ResourceId $using:node.HostCredentialResourceId

                $connections = @()
                $connections += New-NCServerConnection -ComputerNames @($GatewayFQDN) -Credential $hostcred

                $vmguid = (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid                
                $vsrv = new-ncvirtualserver -ResourceId $using:node.NodeName -Connections $connections -vmGuid $vmguid

            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword

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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                
                # Get Transit Subnet ResourceId
                foreach ($ln in $node.LogicalNetworks)
                {
                    if ($ln.Name -eq "Transit")
                    {
                        $transitLogicalNetworkResourceId = $ln.ResourceId
                    }
                }
                
                $transitNetwork = Get-NCLogicalNetwork -ResourceID $transitLogicalNetworkResourceId

                # Get the VirtualServer JSON for this GW VM
                $virtualServerObj = Get-ncvirtualserver -ResourceID $using:node.NodeName

                # Add new Interfaces for the GW VM                
                $InternalInterface = New-NCNetworkInterface -ResourceId $using:node.InternalNicPortProfileId -MacAddress $using:node.InternalNicMac
                $ExternalInterface = New-NCNetworkInterface -ResourceId $using:node.ExternalNicPortProfileId -MacAddress $using:node.ExternalNicMac -IPAddress $using:node.ExternalIPAddress -Subnet $transitNetwork.properties.Subnets[0]

                # Get the Gateway Pool reference
                $GatewayPoolObj = Get-NCGatewayPool -ResourceId $using:Node.GatewayPoolResourceId

                # Get the virtual Server reference
                $VirtualServerObj = Get-NCVirtualServer -ResourceId $using:node.NodeName 
		
		        $GreBgpConfig = 
		        @{
			        extAsNumber = $using:node.GreBgpRouterASN
			        bgpPeer = 
			        @(
				        @{
					        peerIP = $using:node.GreBgpPeerRouterIP
					        peerExtAsNumber = $using:node.GreBgpPeerRouterASN
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

                    "Forwarding"   { 
                                    $gateway = New-NCGateway -ResourceID $using:node.NodeName -GatewayPoolRef $GatewayPoolObj.resourceRef -Type $GatewayPoolObj.properties.type `
                                                            -VirtualServerRef $VirtualServerObj.resourceRef -ExternalInterfaceRef $ExternalInterface.resourceRef -InternalInterfaceRef $InternalInterface.resourceRef 
                                }
                }
                
            }
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword

                $obj = Get-NCGateway -ResourceId $using:node.NodeName
                return $obj -ne $null  #TODO: validate it has correct values before returning $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}


Configuration ConfigureHostNetworking
{
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’
    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
            
        Script CertExchange
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                write-verbose "Running as $val";
                $certName = "$($using:node.nodename).$($using:node.fqdn)".ToLower()
                $certpath = "$($using:node.installsrcdir)\$($using:node.certfolder)"
                $nccertname = "rest.$($using:node.nccertname)"

                write-verbose "Querying self signed certificate ..."
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject -eq "CN=$certName"}
                if ($cert -eq $null) {
                    GenerateSelfSignedCertificate $certname
                    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject -eq "CN=$certName"}
                }
                if ($cert.count > 0)
                {
                    $cert = $cert[0]
                }

                write-verbose "Giving permission to network service for the host certificate"
                GivePermissionToNetworkService $cert

                write-verbose "Adding Network Controller Certificates to trusted Root Store"
                AddCertToLocalMachineStore "$certpath\$NCCertName" "Root" 

                Get-ChildItem -Path WSMan:\localhost\Listener | Where {$_.Keys.Contains("Transport=HTTPS") } | Remove-Item -Recurse -Force
                New-Item -Path WSMan:\localhost\Listener -Address * -HostName $certName -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force

                Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = "hello" }
            }
        } 

        Script DisableWfp
        {                                      
            SetScript = {
                Disable-VmSwitchExtension -VMSwitchName $using:node.vSwitchName -Name "Microsoft Windows Filtering Platform"
            }
            TestScript = {
                return (get-vmswitchextension -VMSwitchName $using:node.vSwitchName -Name "Microsoft Windows Filtering Platform").Enabled -eq $false
            }
            GetScript = {
                return @{ result = "hello" }
            }
        }

        #Start host agent before enabling VFP to ensure that VFP unblocks the necessary ports as quickly as possible
        
        Script SetNCConnection
        {                                      
            SetScript = {
                $NCIP = [System.Net.Dns]::GetHostByName($using:node.NetworkControllerRestName).AddressList[0].ToString()

                Remove-ItemProperty -Path  "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name Connections -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name Connections -PropertyType MultiString -Value @("ssl:$($NCIP):6640","pssl:6640:")

                Remove-ItemProperty -Path  "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name PeerCertificateCName -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name PeerCertificateCName -PropertyType String -Value $using:node.NetworkControllerRestName

                Remove-ItemProperty -Path  "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name HostAgentCertificateCName -ErrorAction Ignore
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name HostAgentCertificateCName -PropertyType String -Value "$($using:node.nodename).$($using:node.fqdn)".ToLower()
            }
            TestScript = {
                
                return $false
            }
            GetScript = {
                return @{ result = "hello" }
            }
        }

        Script HostAgent
        {                                      
            SetScript = {
                stop-service -name NCHostAgent 
                $service = (Get-WmiObject win32_service -filter "Name='NcHostAgent'")
                $service.Change($null,$null,16) # 16 = "Own Process"
                Set-Service -Name NcHostAgent -StartupType Automatic
                Start-Service -Name NcHostAgent
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = "hello" }
            }
        }
        Script EnableVFP
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"
                
                $vms = get-vm

                foreach ($vm in $vms) {
                    set-portprofileid -ResourceID "00000000-0000-0000-0000-000000000000" -vmname $vm.Name -computername localhost -ProfileData 2 -Force
                }

                Enable-VMSwitchExtension -VMSwitchName $using:node.vSwitchName -Name "Windows Azure VFP Switch Extension"
            }
            TestScript = {
                return (get-vmswitchextension -VMSwitchName $using:node.vSwitchName -Name "Windows Azure VFP Switch Extension").Enabled
            }
            GetScript = {
                return @{ result = "hello" }
            }
        }

        Script Firewall-HostAgent
        {                                      
            SetScript = {
                Enable-netfirewallrule "Microsoft-Windows-Hyper-V-HostAgent"
                Enable-netfirewallrule "Microsoft-Windows-Hyper-V-HostAgent-WCF"
                Enable-netfirewallrule "Microsoft-Windows-Hyper-V-HostAgent-WCF-TLS"
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

        File ToolsDirectory
        {
            Type = "Directory"
            Ensure = "Present"
            Force = $True
            Recurse = $True
            SourcePath = $node.InstallSrcDir+"\"+$node.ToolsSrcLocation
            DestinationPath = $node.ToolsLocation
                    
        }   

     
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
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $NCIP = [System.Net.Dns]::GetHostByName($using:node.NetworkControllerRestName).AddressList[0].ToString()
                $SLBMVIP = (Get-NCLoadbalancerManager).properties.loadbalancermanageripaddress

                $slbhpconfig = $slbhpconfigtemplate -f $ncip, $SLBMVIP, "$($using:node.NetworkControllerRestName)", "$($using:node.nodename).$($using:node.fqdn)"
                write-verbose $slbhpconfig
                set-content -value $slbhpconfig -path 'c:\windows\system32\slbhpconfig.xml' -encoding UTF8
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = "hello" }
            }
        }
        Script SLBHostAgent
        {
            SetScript = {
                stop-service -name SlbHostAgent 
                $service = (Get-WmiObject win32_service -filter "Name='SlbHostAgent'")
                $service.Change($null,$null,16) # 16 = "Own Process"
                Set-Service -Name SlbHostAgent -StartupType Automatic
                Start-Service -Name SlbHostAgent
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = "hello" }
            }
        }         

        Script AddHostToNC
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword
                . "$($using:node.InstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $HOSTFQDN = "$($using:node.nodename).$($using:node.fqdn)"

                $hostcred = get-nccredential -ResourceId $using:node.HostCredentialResourceId
                $nccred = get-nccredential -ResourceId $using:node.NCCredentialResourceId
 
                $ipaddress = [System.Net.Dns]::GetHostByName($HOSTFQDN).AddressList[0].ToString()

                $connections = @()
                $connections += New-NCServerConnection -ComputerNames @($HOSTFQDN) -Credential $hostcred
                $connections += New-NCServerConnection -ComputerNames @($HOSTFQDN) -Credential $nccred

                $lns = @()
                foreach ($lndef in $using:node.logicalnetworks) {
                    if ($lndef.NetworkVirtualization) {
                        $ln = get-nclogicalnetwork -ResourceId $lndef.ResourceId
                        $lns += $ln.properties.subnets
                    }
                }
                
                $pNICs = @()
                $pNICs = New-NCServerNetworkInterface -LogicalNetworksubnets $lns

                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$HOSTFQDN"}
                $certPath = "C:\$HOSTFQDN.cer"

                Write-Verbose "Exporting certificate to the file system and converting to Base64 string...";
                Export-Certificate -Type CERT -FilePath $certPath -Cert $cert
                $file = Get-Content $certPath -Encoding Byte
                $base64 = [System.Convert]::ToBase64String($file)
                Remove-Item -Path $certPath

                $ResourceId = (get-vmswitch $using:node.vSwitchName).id.ToString()
                $server = New-NCServer -ResourceId $ResourceId -Connections $connections -PhysicalNetworkInterfaces $pNICs -Certificate $base64
               
            } 
            TestScript = {
                . "$($using:node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.ncUsername -Password $using:node.ncpassword

                $ResourceId = (get-wmiobject win32_computersystemproduct).uuid 
                $obj = Get-NCServer -ResourceId $ResourceId
                return $obj -ne $null
            }
            GetScript = {
                return @{ result = $true }
            }
        }      
                     
    }
}


<#
Workflow ConfigureHostNetworking
{
     param(
      [Object]$ConfigData
     )

    $nodeList = $ConfigData.AllNodes.Where{$_.Role -eq "HyperVHost"}

    ForEach -Parallel -ThrottleLimit 10 ($hostNode in $nodeList) {

        # Variables used in several Inline Scripts
        $hostFQDN = "$($hostNode.NodeName).$($hostNode.fqdn)".ToLower()
        $localDir = "\\$($hostNode.NodeName)\c$\Deployment"
        $certPath = "$($localDir)\$($hostNode.CertFolder)"
        $certPwd = "P@ssw0rd"

        Write-Verbose "$($hostFQDN)"
        InlineScript 
        {
            # Create Host Certificate
            Write-Verbose "Create Host Certificate for [$($using:hostNode.NodeName)]";
            . "$($using:hostNode.InstallSrcDir)\Scripts\CertHelpers.ps1"
        
            # Copy Deployment Files
            $copyFrom = $using:hostNode.InstallSrcDir
            $localDir = $using:localDir
            New-Item -ItemType Directory -Force -Path $localDir
            Get-ChildItem -Path $copyFrom | % { 
                Copy-Item $_.fullname -Destination $localDir -Recurse -Force -Exclude @('Images')
            }

            Set-ExecutionPolicy bypass

            # Generate Cert on Mgmt Node
            Write-Verbose "GenerateSelfSignedCertificate for Host $($using:hostNode.NodeName)";

            $hostFQDN = $using:hostFQDN
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject -eq "CN=$hostFQDN"} | Select -First 1
            
            if ($cert -eq $null) {
                GenerateSelfSignedCertificate $hostFQDN
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject -eq "CN=$hostFQDN"} | Select -First 1
            }
            
            # Export Cert to hostNode
            $certFP = "$($using:certPath)\$($using:hostNode.NodeName)cert.pfx"
            $certPwdSec = ConvertTo-SecureString -String $using:certPwd -Force -AsPlainText
            Write-Verbose "ExportPfxCertificate fp: $($certFP) pass: $($certPwd)"
            Export-PfxCertificate -FilePath $certFP -Force -Cert $cert -Password $certPwdSec
        } # end Create Host Certificate

        # Credential is used to run InlineScripts on Remote Hosts
        $psPwd = ConvertTo-SecureString $hostNode.HostPassword -AsPlainText -Force;
        $psCred = New-Object System.Management.Automation.PSCredential $hostNode.HostUserName, $psPwd;

        InlineScript {
            # CertExchange
            Write-Verbose "CertExchange";
            . "$($using:localDir)\Scripts\CertHelpers.ps1"

            $hostFQDN = $using:hostFQDN

            write-verbose "Querying self signed certificate ..."
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject -eq "CN=$certName"}
            if ($cert -eq $null) {
                GenerateSelfSignedCertificate $certname
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject -eq "CN=$certName"}
            }
            if ($cert.count > 0)
            {
                $cert = $cert[0]
            }
        
            write-verbose "Giving permission to network service for the host certificate $($cert.Subject)"
            GivePermissionToNetworkService $cert

            write-verbose "Adding Network Controller Certificates to trusted Root Store"
            $fp = "$($using:localDir)\Tools\certmgr.exe"
            $certFP = "$($using:certpath)\$($using:hostNode.ncCertName)"
            $arguments = "-add $($certFP) -s -r localMachine Root -all"
            Write-Verbose "Import-Certificate fp: $($fp) arguments: $($arguments)";
            
            #temporarily use old method until we figure out if certmgr.exe is required and how to distribute it
            addcerttolocalmachinestore $certFP "Root"

        } -psComputerName $hostNode.NodeName -psCredential $psCred
        # end CertExchange

        InlineScript {
            # DisableWfp
            Write-Verbose "DisableWfp";
        
            $hostNode = $using:hostNode.NodeName
            $switch = $using:hostNode.vSwitchName
            Disable-VmSwitchExtension -VMSwitchName $switch -Name "Microsoft Windows Filtering Platform"
        
            #Test DisableWfp
            if((get-vmswitchextension -VMSwitchName $switch -Name "Microsoft Windows Filtering Platform").Enabled -eq $true)
            {
                Write-Error "DisableWfp Failed on $($hostNode)"
            }
        } -psComputerName $hostNode.NodeName -psCredential $psCred
        # end DisableWfp

        #Start host agent before enabling VFP to ensure that VFP unblocks the necessary ports as quickly as possible
    
        InlineScript {
            # SetNCConnection
            Write-Verbose "SetNCConnection";

            #$connection = "tcp:$($using:hostNode.NetworkControllerRestName):6640"
            $connection = @("ssl:$($using:hostNode.NetworkControllerRestName):6640", "pssl:6640:")
            Write-Verbose "Connection Value $($connection)";
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name Connections -ErrorAction Ignore
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name Connections -PropertyType MultiString -Value $connection
        } -psComputerName $hostNode.NodeName -psCredential $psCred
        # end SetNCConnection

        InlineScript {
            # NcHostAgent Restart
            Write-Verbose "NcHostAgent Restart";

            $service = Get-Service -Name NCHostAgent
            Stop-Service -InputObject $service
            Set-Service -InputObject $service -StartupType Automatic
            Start-Service -InputObject $service
        } -psComputerName $hostNode.NodeName -psCredential $psCred 
        # end NcHostAgent Restart

        InlineScript {
            # EnableVFP Set Vm Port Profile Ids
            Write-Verbose "EnableVFP - Set Vm Port Profile Ids";
            . "$($using:hostNode.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1"

            $vms = Get-VM -ComputerName $using:hostNode.NodeName
            foreach($vm in $vms) {
                set-portprofileid -ResourceID "00000000-0000-0000-0000-000000000000" -vmname $vm.Name -ComputerName $using:hostNode.NodeName -ProfileData 2
            }

            # EnableVFP - Enable-VMSwitchExtension
            Write-Verbose "EnableVFP - Enable-VMSwitchExtension";
            Enable-VMSwitchExtension -ComputerName $using:hostNode.NodeName -VMSwitchName $using:hostNode.vSwitchName -Name "Windows Azure VFP Switch Extension"
        
            #Test EnableVFP
            if((get-vmswitchextension -ComputerName $using:hostNode.NodeName -VMSwitchName $using:hostNode.vSwitchName -Name "Windows Azure VFP Switch Extension").Enabled -eq $false)
            {
                Write-Error "Enable-VMSwitchExtension Failed on $($using:hostNode.NodeName) Switch: $($using:hostNode.vSwitchName)"
            }
        } -psComputerName $env:Computername
        # end EnableVFP

        InlineScript {
            # Firewall Rules
            Write-Verbose "Firewall Rules";

            $fwrule = Get-NetFirewallRule -Name "Firewall-REST"
            if ($fwrule -eq $null) {
                Write-Verbose "Create Firewall rule for NCHostAgent Rest";
                New-NetFirewallRule -Name "Firewall-REST" -DisplayName "Network Controller Host Agent REST" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True
            }
            #Test Firewall-REST
            if((get-netfirewallrule | where {$_.Name -eq "Firewall-REST"}) -eq $null)
            {
                Write-Error "Create Firewall-REST Rule Failed on $($using:hostNode.NodeName)"
            }
        
            $fwrule = Get-NetFirewallRule -Name "Firewall-OVSDB"
            if ($fwrule -eq $null) {
                Write-Verbose "Create Firewall rule for NCHostAgent OVSDB";
                New-NetFirewallRule -Name "Firewall-OVSDB" -DisplayName "Network Controller Host Agent OVSDB" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 6640 -Direction Inbound -Enabled True
            }
            #Test Firewall-OVSDB
            if((get-netfirewallrule | where {$_.Name -eq "Firewall-OVSDB"}) -eq $null)
            {
                Write-Error "Create Firewall-REST Rule Failed on $($using:hostNode.NodeName)"
            }
        } -psComputerName $hostNode.NodeName -psCredential $psCred
        # end Firewall Rules

        InlineScript {
            # CreateSLBConfigFile
            Write-Verbose "CreateSLBConfigFile";

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
                . "$($using:localDir)\Scripts\NetworkControllerRESTWrappers.ps1" -computername $using:hostnode.NetworkControllerRestName -UserName $using:hostnode.ncUsername -Password $using:hostnode.ncpassword


                $ncfqdn = "$($using:hostNode.ncname).$($using:hostNode.fqdn)".ToLower()
                $ncrest = "$($using:hostNode.NetworkControllerRestName)".ToLower()
                $slbhpconfig = $slbhpconfigtemplate -f $ncrest, $((Get-NCLoadbalancerManager).properties.loadbalancermanageripaddress), $ncfqdn, $using:hostFQDN
                write-verbose $slbhpconfig
                set-content -value $slbhpconfig -path 'c:\windows\system32\slbhpconfig.xml' -encoding UTF8
        } -psComputerName $hostNode.NodeName -psCredential $psCred
        # end CreateSLBConfigFile

        InlineScript {
            # SLBHostAgent Restart
            Write-Verbose "SLBHostAgent Restart";

            $service = Get-Service -Name SlbHostAgent
            Stop-Service -InputObject $service
            Set-Service -InputObject $service -StartupType Automatic
            Start-Service -InputObject $service
        } -psComputerName $hostNode.NodeName -psCredential $psCred 
        # end SLBHostAgent Restart

        $ResourceId = (get-vmswitch -ComputerName $hostNode.NodeName -Name $hostNode.vSwitchName).id.ToString()
        InlineScript {
            # AddHostToNC
            Write-Verbose "AddHostToNC";
            
            . "$($using:hostNode.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:hostnode.NetworkControllerRestName -UserName $using:hostnode.ncUsername -Password $using:hostnode.ncpassword

            $p = ping $using:hostNode.NetworkControllerRestName | Out-String
            Write-Verbose $p

            set-ncconnection $using:hostNode.NetworkControllerRestName -Credential $credential
        
            $hostcred = get-nccredential -ResourceId $using:hostNode.HostCredentialResourceId
            $nccred = get-nccredential -ResourceId $using:hostNode.NCCredentialResourceId
            
            $connections = @()
            $connections += New-NCServerConnection -ComputerNames @($using:hostFQDN) -Credential $hostcred -Verbose
            $connections += New-NCServerConnection -ComputerNames @($using:hostFQDN) -Credential $nccred -Verbose
        
            $ln = get-nclogicalnetwork -ResourceId $using:hostNode.PALogicalNetworkResourceId -Verbose
            
            $pNICs = @()
            $pNICs += New-NCServerNetworkInterface -LogicalNetworksubnets ($ln.properties.subnets) -Verbose

            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$using:hostFQDN"} | Select -First 1;
            $base64 = [System.Convert]::ToBase64String($cert.GetRawCertData())
            
            $server = New-NCServer -ResourceId $using:ResourceId -Connections $connections -PhysicalNetworkInterfaces $pNICs -Certificate $base64 -Verbose
            
        } -psComputerName $env:Computername -psCredential $psCred
        # end AddHostToNC

    } # end ForEach -Parallel
}
#>

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

function RenameGatewayNetworkAdapters
{
    param([Object] $ConfigData)

    $GatewayNodes = @($configdata.AllNodes | ? {$_.Role -eq "Gateway"})

    foreach ($node in $GatewayNodes) {
        klist purge | out-null  #clear kerberos ticket cache 
    
        write-verbose "Attempting to contact $($node.NodeName)."
        $ps = GetOrCreate-PSSession -computername $node.NodeName 
        if ($ps -eq $null) { return }

        $result = Invoke-Command -Session $ps -ScriptBlock {
                param($InternalNicMac, $ExternalNicMac)
                 
                $Adapters = @(Get-NetAdapter)
                $InternalAdapter = $Adapters | ? {$_.MacAddress -eq $InternalNicMac}
                $ExternalAdapter = $Adapters | ? {$_.MacAddress -eq $ExternalNicMac}

                if ($InternalAdapter -ne $null)
                { Rename-NetAdapter -Name $InternalAdapter.Name -NewName "Internal" -Confirm:$false }
                if ($ExternalAdapter -ne $null)
                { Rename-NetAdapter -Name $ExternalAdapter.Name -NewName "External" -Confirm:$false }
            } -ArgumentList @($node.InternalNicMac, $node.ExternalNicMac)        
    }
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

function CleanupMOFS
{  
    Remove-Item .\SetHyperVWinRMEnvelope -Force -Recurse 2>$null
    Remove-Item .\DeployVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureNetworkControllerVMs -Force -Recurse 2>$null
    Remove-Item .\CreateControllerCerts -Force -Recurse 2>$null
    Remove-Item .\DistributeControllerCert -Force -Recurse 2>$null
    Remove-Item .\ConfigureNetworkControllerCluster -Force -Recurse 2>$null
    Remove-Item .\ConfigureSLBMUX -Force -Recurse 2>$null
    Remove-Item .\ConfigureHostNetworking -Force -Recurse 2>$null
    Remove-Item .\AddNetworkAdapter -Force -Recurse 2>$null
    Remove-Item .\ConfigureNetworkAdapterPortProfile -Force -Recurse 2>$null
    Remove-Item .\ConfigureGateway -Force -Recurse 2>$null
}

function CompileDSCResources
{
    SetHyperVWinRMEnvelope -ConfigurationData $ConfigData -verbose
    DeployVMs -ConfigurationData $ConfigData -verbose
    ConfigureNetworkControllerVMs -ConfigurationData $ConfigData -verbose
    CreateControllerCert -ConfigurationData $ConfigData -verbose
    DistributeControllerCerts -ConfigurationData $ConfigData -verbose
    ConfigureNetworkControllerCluster -ConfigurationData $ConfigData -verbose
    ConfigureHostNetworking -ConfigurationData $ConfigData -verbose 
    ConfigureSLBMUX -ConfigurationData $ConfigData -verbose 
    AddNetworkAdapter -ConfigurationData $ConfigData -verbose 
    ConfigureNetworkAdapterPortProfile  -ConfigurationData $ConfigData -verbose 
    ConfigureGateway -ConfigurationData $ConfigData -verbose
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

    write-verbose "STAGE 1: Cleaning up previous MOFs"

    CleanupMOFS

    write-verbose "STAGE 2: Compile DSC resources"

    CompileDSCResources

    write-verbose "STAGE 2.5: Set WinRM envelope size on hosts"

    Start-DscConfiguration -Path .\SetHyperVWinRMEnvelope -Wait -Force -Verbose -Erroraction Stop

    write-verbose "STAGE 3: Deploy VMs"

    Start-DscConfiguration -Path .\DeployVMs -Wait -Force -Verbose -Erroraction Stop
    WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController", "SLBMUX", "Gateway"))

    write-verbose "STAGE 3.1: Configure Gateway Network Adapters"
    Start-DscConfiguration -Path .\AddNetworkAdapter -Wait -Force -Verbose -Erroraction Stop
    WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("Gateway"))
    
    #TODO: add and rename nic as part of VM creation
    write-verbose "STAGE 3.2: Rename network adapters on Gateway VMs"
    RenameGatewayNetworkAdapters $ConfigData

    write-verbose "STAGE 4: Install Network Controller nodes"

    Start-DscConfiguration -Path .\ConfigureNetworkControllerVMs -Wait -Force -Verbose -Erroraction Stop
    WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController")) -CheckPendingReboot 
    
    write-verbose "STAGE 5: Configure NetworkController cluster"
    Start-DscConfiguration -Path .\CreateControllerCert -Wait -Force -Verbose -Erroraction Stop

    #Note: the following section assumes there is only one NC VM.
    foreach ($n in $configdata.allnodes) {
        if ($n.role -eq "NetworkController") {
            $NCCertDestination = "$($configData.AllNodes[0].installsrcdir)\$($configData.AllNodes[0].certfolder)"

            if ($n.ServiceFabricRingMembers -ne $null) {
                $NCCertSource = '\\{0}\c$\rest.{1}' -f $n.NodeName, $configData.AllNodes[0].NCCertName
                write-verbose ("Copying Rest Cert from [{0}] to [{1}]" -f $NCCertSource, $NCCertDestination)
                copy-item -path $NCCertSource -Destination $NCCertDestination
                copy-item -path "$NCCertSource.pfx" -Destination $NCCertDestination
            }
        
            $NCCertSource = '\\{0}\c$\{1}' -f $n.NodeName, $configData.AllNodes[0].NCCertName

            write-verbose ("Copying Node Cert from [{0}] to [{1}]" -f $NCCertSource, $NCCertDestination)
            copy-item -path $NCCertSource -Destination "$NCCertDestination\$($n.NodeName).$($configData.AllNodes[0].NCCertName)"
        }
    }

    Start-DscConfiguration -Path .\DistributeControllerCerts -Wait -Force -Verbose -Erroraction Stop

    Start-DscConfiguration -Path .\ConfigureNetworkControllerCluster -Wait -Force -Verbose -Erroraction Stop

    write-verbose ("Importing NC Cert to trusted root store of deployment machine" )
    . "$($configData.AllNodes[0].installsrcdir)\Scripts\certhelpers.ps1"
    AddCertToLocalMachineStore "$NCCertDestination\rest.$($configData.AllNodes[0].NCCertName)" "Root"
    
    #Hosts, Muxes and Gateways can all be configured in parallel
    
    write-verbose "STAGE 6: Configure Hyper-V hosts"
    
    if ((Get-ChildItem .\ConfigureHostNetworking\).count -gt 0) {
        Start-DscConfiguration -Path .\ConfigureHostNetworking -wait -Force -Verbose -Erroraction Stop
        #Start-DscConfiguration -Path .\ConfigureHostNetworking -JobName "HyperV" -Force -Verbose -Erroraction Stop
    } else {
        write-verbose "No hosts defined in configuration."
    }

    write-verbose "STAGE 7: Configure SLBMUXes"
    if ((Get-ChildItem .\ConfigureSLBMUX\).count -gt 0) {
        Start-DscConfiguration -Path .\ConfigureSLBMUX -wait -Force -Verbose -Erroraction Stop
        #Start-DscConfiguration -Path .\ConfigureSLBMUX -JobName "SLBMUX" -Force -Verbose -Erroraction Stop
    } else {
        write-verbose "No muxes defined in configuration."
    }

    write-verbose "STAGE 8: Configure Gateways"
    if ((Get-ChildItem .\ConfigureGateway\).count -gt 0) {
        Start-DscConfiguration -Path .\ConfigureGateway -wait -Force -Verbose -Erroraction Stop
        Start-DscConfiguration -Path .\ConfigureNetworkAdapterPortProfile -wait -Force -Verbose -Erroraction Stop
        #Start-DscConfiguration -Path .\ConfigureGateway -JobName "Gateway" -Force -Verbose -Erroraction Stop

    } else {
        write-verbose "No gateways defined in configuration."
    }

    #Wait-job -Name "HyperV","SLBMUX","Gateway"

    $global:stopwatch.stop()
    write-verbose "TOTAL RUNNING TIME: $($global:stopwatch.Elapsed.ToString())"
}