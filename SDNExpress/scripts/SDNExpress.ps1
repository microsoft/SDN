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
    .\SDNExpress.ps1 -ConfigurationDataFile .\MyConfig.psd1
    Reads in the configuration from a PSD1 file that contains a hash table 
    of settings data.
.EXAMPLE
    .\SDNExpress -ConfigurationData $MyConfigurationData
    Uses the hash table that is passed in as the configuration data.  This 
    parameter set is useful when programatically generating the 
    configuration data.
.EXAMPLE
    .\SDNExpress 
    Displays a user interface for interactively defining the configuraiton 
    data.  At the end you have the option to save as a configuration file
    before deploying.
.NOTES
    Prerequisites:
    * All Hyper-V hosts must have Hyper-V enabled and the Virtual Switch 
    already created.
    * All Hyper-V hosts must be joined to Active Directory.
    * The physical network must be preconfigured for the necessary subnets and 
    VLANs as defined in the configuration data.
    * The VHD specified in the configuration data must be reachable from the 
    computer where this script is run. 
#>

[CmdletBinding(DefaultParameterSetName="NoParameters")]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null,
    [Switch] $SkipValidation,
    [Switch] $SkipDeployment,
    [PSCredential] $DomainJoinCredential = $null,
    [PSCredential] $NCCredential = $null,
    [PSCredential] $LocalAdminCredential = $null
    )    


# Script version, should be matched with the config files
$ScriptVersion = "2.0"


if ((get-wmiobject win32_operatingsystem).caption.Contains("Windows 10")) {
    get-windowscapability -name rsat.NetworkController.Tools* -online | Add-WindowsCapability -online
} else {
    $feature = get-windowsfeature "RSAT-NetworkController"
    if ($null -eq $feature) {
        throw "SDN Express requires Windows Server 2016 or later."
    }
    if (!$feature.Installed) {
        add-windowsfeature "RSAT-NetworkController"
    }
}
import-module networkcontroller
import-module .\SDNExpressModule.psm1 -force

write-SDNExpressLog "*** Begin SDN Express Deployment ***"
write-SDNExpressLog "ParameterSet: $($psCmdlet.ParameterSetName)" 
write-SDNExpressLog "  -ConfigurationDataFile: $ConfigurationDataFile"
write-SDNExpressLog "  -ConfigurationData: $ConfigurationData"
write-SDNExpressLog "  -SkipValidation: $SkipValidation"
write-SDNExpressLog "  -SkipDeployment: $SkipValidation"
Write-SDNExpressLog "Version info follows: $($PSVersionTable | out-string)"

if ($psCmdlet.ParameterSetName -eq "NoParameters") {
    write-sdnexpresslog "Begin interactive mode."    

    import-module .\SDNExpressUI.psm1 -force
    $configData = SDNExpressUI  
    if ($null -eq $configData)
    {
        # user cancelled
        exit
    }

} elseif ($psCmdlet.ParameterSetName -eq "ConfigurationFile") {
    write-sdnexpresslog "Using configuration file passed in by parameter."    
    $configdata = [hashtable] (Invoke-Expression (Get-Content $ConfigurationDataFile | out-string))
} elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") {
    write-sdnexpresslog "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) {
    write-error "Configuration file version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express.  Please update your config file to match the version $scriptversion example."
    return
}

function GetPassword 
{
    param(
        [String] $SecurePasswordText,
        [PSCredential] $Credential,
        [String] $Message,
        [String] $UserName
    )
    if ([String]::IsNullOrEmpty($SecurePasswordText) -and ($null -eq $Credential)) {
        write-sdnexpresslog "No credentials found on command line or in config file.  Prompting."    
        $Credential = get-Credential -Message $Message -UserName $UserName
    }

    if ($null -ne $Credential) {
        write-sdnexpresslog "Using credentials from the command line."    
        return $Credential.GetNetworkCredential().Password
    }

    try {
        write-sdnexpresslog "Using credentials from config file."    
        $securepassword = $SecurePasswordText | convertto-securestring -erroraction Ignore
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    } catch {
        write-sdnexpresslog "Unable to decrpypt credentials in config file.  Could be from a different user or generated on different computer.  Prompting instead."    
        $Credential = get-Credential -Message $Message -UserName $UserName
        if ($null -eq $credential) {
            write-sdnexpresslog "User cancelled credential input.  Exiting."    
            exit
        }
        return $Credential.GetNetworkCredential().Password
    }

}
function GetNextMacAddress
{
    param(
        [String] $MacAddress
    )

    return ("{0:X12}" -f ([convert]::ToInt64($MacAddress.ToUpper().Replace(":", "").Replace("-", ""), 16) + 1)).Insert(2, "-").Insert(5, "-").Insert(8, "-").Insert(11, "-").Insert(14, "-")
}

try {
    $DomainJoinPassword = GetPassword $ConfigData.DomainJoinSecurePassword $DomainJoinCredential "Enter credentials for joining VMs to the AD domain." $configdata.DomainJoinUserName
    $NCPassword = GetPassword $ConfigData.NCSecurePassword $NCCredential "Enter credentials for the Network Controller to use." $configdata.NCUserName
    $LocalAdminPassword = GetPassword $ConfigData.LocalAdminSecurePassword $LocalAdminCredential "Enter the password for the local administrator of newly created VMs.  Username is ignored." "Administrator"

    $NCSecurePassword = $NCPassword | convertto-securestring -AsPlainText -Force

    $credential = New-Object System.Management.Automation.PsCredential($ConfigData.NCUsername, $NCSecurePassword)

    if (![string]::IsNullOrEmpty($ConfigData.ManagementSubnet)) {
        $ManagementSubnetBits = $ConfigData.ManagementSubnet.Split("/")[1]
    }

    if ([string]::IsNullOrEmpty($ConfigData.PASubnet)) {
        if ($ConfigData.Muxes.Count -gt 0) {
            throw "Load Balancer Mux configuration requires a PA Subnet."
        }
        if ($ConfigData.Gateways.Count -gt 0) {
            throw "Gateway configuration requires a PA Subnet."
        }
    }
    if (($ConfigData.Muxes.count -gt 0) -or ($ConfigData.Gateways.count -gt 0)) {
        $PASubnetBits = $ConfigData.PASubnet.Split("/")[1]
    }

    $DomainJoinUserNameDomain = $ConfigData.DomainJoinUserName.Split("\")[0]
    $DomainJoinUserNameName = $ConfigData.DomainJoinUserName.Split("\")[1]
    $LocalAdminDomainUserDomain = $ConfigData.LocalAdminDomainUser.Split("\")[0]
    $LocalAdminDomainUserName = $ConfigData.LocalAdminDomainUser.Split("\")[1]

    if ($null -eq $ConfigData.VMProcessorCount) {$ConfigData.VMProcessorCount = 8}
    if ($null -eq $ConfigData.VMMemory) {$ConfigData.VMMemory = 8GB}
    if ([string]::IsNullOrEmpty($ConfigData.PoolName)) {$ConfigData.PoolName = "DefaultAll"}

    write-SDNExpressLog "STAGE 1: Create VMs"

    $params = @{
        'ComputerName'='';
        'VMLocation'=$ConfigData.VMLocation;
        'VMName'='';
        'VHDSrcPath'=$ConfigData.VHDPath;
        'VHDName'=$ConfigData.VHDFile;
        'VMMemory'=$ConfigData.VMMemory;
        'VMProcessorCount'=$ConfigData.VMProcessorCount;
        'Nics'=@();
        'CredentialDomain'=$DomainJoinUserNameDomain;
        'CredentialUserName'=$DomainJoinUserNameName;
        'CredentialPassword'=$DomainJoinPassword;
        'JoinDomain'=$ConfigData.JoinDomain;
        'LocalAdminPassword'=$LocalAdminPassword;
        'DomainAdminDomain'=$LocalAdminDomainUserDomain;
        'DomainAdminUserName'=$LocalAdminDomainUserName;
        'SwitchName'=$ConfigData.SwitchName
    }

    if (![String]::IsNullOrEmpty($ConfigData.ProductKey)) {
        $params.ProductKey = $ConfigData.ProductKey
    }
    if (![String]::IsNullOrEmpty($ConfigData.Locale)) {
        $params.Locale = $ConfigData.Locale
    }
    if (![String]::IsNullOrEmpty($ConfigData.TimeZone)) {
        $params.TimeZone = $ConfigData.TimeZone
    }

    $HostNameIter = 0
    foreach ($NC in $ConfigData.NCs) {
        if ([string]::IsNullOrEmpty($nc.macaddress)) {
            $nc.macaddress = $ConfigData.SDNMacPoolStart
            $configdata.SDNMacPoolStart = GetNextMacAddress($ConfigData.SDNMacPoolStart)
        }

        if ([string]::IsNullOrEmpty($nc.HostName)) {
            $nc.HostName = $ConfigData.HyperVHosts[$HostNameIter]
            $HostNameIter = ($HostNameIter + 1) % $ConfigData.HyperVHosts.Count
        }
    }
    foreach ($Mux in $ConfigData.Muxes) {
        if ([string]::IsNullOrEmpty($Mux.macaddress)) {
            $mux.macaddress = $ConfigData.SDNMacPoolStart
            $configdata.SDNMacPoolStart = GetNextMacAddress($ConfigData.SDNMacPoolStart)
        }
        if ([string]::IsNullOrEmpty($Mux.pamacaddress)) {
            $mux.pamacaddress = $ConfigData.SDNMacPoolStart
            $configdata.SDNMacPoolStart = GetNextMacAddress($ConfigData.SDNMacPoolStart)
        }
        if ([string]::IsNullOrEmpty($Mux.HostName)) {
            $Mux.HostName = $ConfigData.HyperVHosts[$HostNameIter]
            $HostNameIter = ($HostNameIter + 1) % $ConfigData.HyperVHosts.Count
        }
        if ([string]::IsNullOrEmpty($Mux.PAIPAddress)) {
            $Mux.PAIPAddress = $ConfigData.PAPoolStart
            $ConfigData.PAPoolStart = Get-IPAddressInSubnet -Subnet $ConfigData.PAPoolStart -Offset 1
        }
    }
    #Allocate GW management MACs from outside of SDN pool
    foreach ($gateway in $ConfigData.Gateways) {
        if ([string]::IsNullOrEmpty($Gateway.macaddress)) {
            $gateway.macaddress = $ConfigData.SDNMacPoolStart
            $configdata.SDNMacPoolStart = GetNextMacAddress($ConfigData.SDNMacPoolStart)
        }
        if ([string]::IsNullOrEmpty($Gateway.HostName)) {
            $Gateway.HostName = $ConfigData.HyperVHosts[$HostNameIter]
            $HostNameIter = ($HostNameIter + 1) % $ConfigData.HyperVHosts.Count
        }        
    }
    #Allocate GW FE & BE macs, FE IP from within SDN mac and PA pools
    $nextmac = $configdata.SDNMacPoolStart
    $PAOffset = 0
    foreach ($gateway in $ConfigData.Gateways) {
        if ([string]::IsNullOrEmpty($Gateway.FrontEndMac)) {
            $gateway.FrontEndMac = $nextmac
            $nextmac = GetNextMacAddress($nextmac)
        }
        if ([string]::IsNullOrEmpty($Gateway.BackEndMac)) {
            $gateway.BackEndMac = $nextmac
            $nextmac = GetNextMacAddress($nextmac)
        }
        if ([string]::IsNullOrEmpty($Gateway.FrontEndIP)) {
            $Gateway.FrontEndIP = Get-IPAddressInSubnet -Subnet $ConfigData.PAPoolStart -Offset $PAOffset
            $PAOffset += 1
        }
    }

    write-SDNExpressLog "STAGE 1.1: Create NC VMs"
    foreach ($NC in $ConfigData.NCs) {
        $params.ComputerName=$NC.HostName;
        $params.VMName=$NC.ComputerName;
        if ([string]::IsNullOrEmpty($NC.ManagementIP)) {
            $params.Nics=@(
                @{Name="Management"; MacAddress=$NC.MacAddress; VLANID=$ConfigData.ManagementVLANID}
            )
        } else {
            $params.Nics=@(
                @{Name="Management"; MacAddress=$NC.MacAddress; IPAddress="$($NC.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID}
            )
        }
        $params.Roles=@("NetworkController","NetworkControllerTools")
        New-SDNExpressVM @params
    }

    write-SDNExpressLog "STAGE 1.2: Create Mux VMs"

    foreach ($Mux in $ConfigData.Muxes) {
        $params.ComputerName=$mux.HostName;
        $params.VMName=$mux.ComputerName;
        if ([string]::IsNullOrEmpty($Mux.ManagementIP)) {
            $params.Nics=@(
                @{Name="Management"; MacAddress=$Mux.MacAddress; VLANID=$ConfigData.ManagementVLANID},
                @{Name="HNVPA"; MacAddress=$Mux.PAMacAddress; IPAddress="$($Mux.PAIPAddress)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID; IsMuxPA=$true}
            )
        } else {
            $params.Nics=@(
                @{Name="Management"; MacAddress=$Mux.MacAddress; IPAddress="$($Mux.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID},
                @{Name="HNVPA"; MacAddress=$Mux.PAMacAddress; IPAddress="$($Mux.PAIPAddress)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID; IsMuxPA=$true}
            )
        }
        $params.Roles=@("SoftwareLoadBalancer")

        New-SDNExpressVM @params
    }

    write-SDNExpressLog "STAGE 1.3: Create Gateway VMs"

    foreach ($Gateway in $ConfigData.Gateways) {
        $params.ComputerName=$Gateway.HostName;
        $params.VMName=$Gateway.ComputerName;
        if ([string]::IsNullOrEmpty($Mux.ManagementIP)) {
            $params.Nics=@(
                @{Name="Management"; MacAddress=$Gateway.MacAddress; VLANID=$ConfigData.ManagementVLANID}
                @{Name="FrontEnd"; MacAddress=$Gateway.FrontEndMac; IPAddress="$($Gateway.FrontEndIp)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID},
                @{Name="BackEnd"; MacAddress=$Gateway.BackEndMac; VLANID=$ConfigData.PAVLANID}
            );
        } else {
            $params.Nics=@(
                @{Name="Management"; MacAddress=$Gateway.MacAddress; IPAddress="$($Gateway.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID}
                @{Name="FrontEnd"; MacAddress=$Gateway.FrontEndMac; IPAddress="$($Gateway.FrontEndIp)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID},
                @{Name="BackEnd"; MacAddress=$Gateway.BackEndMac; VLANID=$ConfigData.PAVLANID}
            );
        }
        $params.Roles=@("RemoteAccess", "RemoteAccessServer", "RemoteAccessMgmtTools", "RemoteAccessPowerShell", "RasRoutingProtocols", "Web-Application-Proxy")

        New-SDNExpressVM @params
    }


    if ($ConfigData.NCs.count -gt 0) {
        write-SDNExpressLog "STAGE 2: Network Controller Configuration"
        $NCNodes = @()
        foreach ($NC in $ConfigData.NCs) {
            $NCNodes += $NC.ComputerName
        }

        WaitforComputerToBeReady -ComputerName $NCNodes -Credential $Credential

        $params = @{
            'Credential'=$Credential
            'RestName'=$ConfigData.RestName
            'ComputerNames'=$NCNodes
        }

        if (![string]::IsNullOrEmpty($ConfigData.ManagementSecurityGroup)) {
            $params.ManagementSecurityGroupName = $ConfigData.ManagementSecurityGroup
            $params.ClientSecurityGroupName = $ConfigData.ClientSecurityGroup
        }
        New-SDNExpressNetworkController @params

        write-SDNExpressLog "STAGE 2.1: Getting REST cert thumbprint in order to find it in local root store."
        $NCHostCertThumb = invoke-command -ComputerName $NCNodes[0] -Credential $credential { 
            param(
                $RESTName
            )
            return (get-childitem "cert:\localmachine\my" | Where-Object {$_.Subject -eq "CN=$RestName"}).Thumbprint
        } -ArgumentList $ConfigData.RestName

        $NCHostCert = get-childitem "cert:\localmachine\root\$NCHostCertThumb"

        $params = @{
            'RestName' = $ConfigData.RestName;
            'MacAddressPoolStart' = $ConfigData.SDNMacPoolStart;
            'MacAddressPoolEnd' = $ConfigData.SDNMacPoolEnd;
            'NCHostCert' = $NCHostCert
            'NCUsername' = $ConfigData.NCUsername;
            'NCPassword' = $NCPassword
        }
        New-SDNExpressVirtualNetworkManagerConfiguration @Params -Credential $Credential

        if (![string]::IsNullOrEmpty($ConfigData.PrivateVIPSubnet)) {
            $params = @{
                'RestName' = $ConfigData.RestName;
                'PrivateVIPPrefix' = $ConfigData.PrivateVIPSubnet;
                'PublicVIPPrefix' = $ConfigData.PublicVIPSubnet
            }

            New-SDNExpressLoadBalancerManagerConfiguration @Params -Credential $Credential
        } else {
            write-SDNExpressLog "VIP subnets not specified in configuration, skipping load balancer manager configuration."
        }

        if (![string]::IsNullOrEmpty($ConfigData.PASubnet)) {
            $params = @{
                'RestName' = $ConfigData.RestName;
                'AddressPrefix' = $ConfigData.PASubnet;
                'VLANID' = $ConfigData.PAVLANID;
                'DefaultGateways' = $ConfigData.PAGateway;
                'IPPoolStart' = $ConfigData.PAPoolStart;
                'IPPoolEnd' = $ConfigData.PAPoolEnd
            }
            Add-SDNExpressVirtualNetworkPASubnet @params -Credential $Credential
        } else {
            write-SDNExpressLog "PA subnets not specified in configuration, skipping Virtual Network PA configuration."
        }
    } 
    else 
    {
        $NCHostCert = get-childitem "cert:\localmachine\root" | Where-Object {$_.Subject -eq "CN=$($configdata.RestName)"}
        if ($null -eq $NCHostCert) {
            $ErrorText = "Network Controller cert with CN=$($configdata.RestName) not found on $(hostname) in cert:\localmachine\root"
            write-SDNExpressLog $ErrorText
            throw $ErrorText
        }
        if ($NCHostCert.count -gt 1) {
            $ErrorText = "More than one Network Controller cert with CN=$($configdata.RestName) found on $(hostname) in cert:\localmachine\root.  Remove extras and redeploy."
            write-SDNExpressLog $ErrorText
            throw $ErrorText
        }
    }

    write-SDNExpressLog "STAGE 3: Host Configuration"
    $params = @{}

    if (![string]::IsNullOREmpty($ConfigData.PASubnet)) {
        $params.HostPASubnetPrefix = $ConfigData.PASubnet;
    }

    foreach ($h in $ConfigData.hypervhosts) {
        Add-SDNExpressHost @params -ComputerName $h -RestName $ConfigData.RestName -NCHostCert $NCHostCert -Credential $Credential -VirtualSwitchName $ConfigData.SwitchName
    }

    if ($ConfigData.Muxes.Count -gt 0) {
        write-SDNExpressLog "STAGE 4: Mux Configuration"

        WaitforComputerToBeReady -ComputerName $ConfigData.Muxes.ComputerName -Credential $Credential

        foreach ($Mux in $ConfigData.muxes) {
            Add-SDNExpressMux -ComputerName $Mux.ComputerName -PAMacAddress $Mux.PAMacAddress -PAGateway $ConfigData.PAGateway -LocalPeerIP $Mux.PAIPAddress -MuxASN $ConfigData.SDNASN -Routers $ConfigData.Routers -RestName $ConfigData.RestName -NCHostCert $NCHostCert -Credential $Credential
        }
    }


    if ($ConfigData.Gateways.Count -gt 0) {
        write-SDNExpressLog "STAGE 5: Gateway Configuration"

        if ([String]::IsNullOrEmpty($ConfigData.RedundantCount)) {
            $ConfigData.RedundantCount = 1
        } 
        New-SDNExpressGatewayPool -IsTypeAll -PoolName $ConfigData.PoolName -Capacity $ConfigData.Capacity -GreSubnetAddressPrefix $ConfigData.GreSubnet -RestName $ConfigData.RestName -Credential $Credential -RedundantCount $ConfigData.RedundantCount

        WaitforComputerToBeReady -ComputerName $ConfigData.Gateways.ComputerName -Credential $Credential

        foreach ($G in $ConfigData.Gateways) {
            $params = @{
                'RestName'=$ConfigData.RestName
                'ComputerName'=$g.computername
                'HostName'=$g.Hostname
                'NCHostCert'= $NCHostCert
                'PoolName'=$ConfigData.PoolName
                'FrontEndIp'=$G.FrontEndIP
                'FrontEndLogicalNetworkName'='HNVPA'
                'FrontEndAddressPrefix'=$ConfigData.PASubnet
                'FrontEndMac'=$G.FrontEndMac
                'BackEndMac'=$G.BackEndMac
                'Routers'=$ConfigData.Routers 
                'LocalASN'=$ConfigData.SDNASN
            }
            New-SDNExpressGateway @params  -Credential $Credential
        }

    }

    test-sdnexpresshealth -restname $ConfigData.RestName -Credential $Credential
}
catch
{
	$pscmdlet.throwterminatingerror($PSItem)
}

write-SDNExpressLog "SDN Express deployment complete."
