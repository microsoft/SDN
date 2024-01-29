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
$ScriptVersion = "3.0"


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


import-module .\SDNExpress.psm1 -force

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

# if FCNC is enabled, load the modules
if ($configdata.UseFCNC) {
  if(-not [string]::IsNullOrEmpty($Global:FCNC_MODULE_PATH_ROOT)) {
    ipmo  (Join-Path $Global:FCNC_MODULE_PATH_ROOT -ChildPath NetworkControllerFc.psd1) -Force -Scope Global
  } else {
    import-Module NetworkControllerFc -ErrorAction SilentlyContinue
    if ($null -eq (Get-Module NetworkControllerFc)) {
      ipmo ..\NetworkControllerFc\NetworkControllerFc.psd1 -Force -Scope Global
    }
  }  

  # rename and copy package 
  if([string]::IsNullOrEmpty($configdata.FCNCPackage) -eq $false) {    
    write-sdnexpresslog "looking for FCNC package $($configdata.FCNCPackage)"
    # check if the package exists
    if (Test-Path $configdata.FCNCPackage) {
      write-sdnexpresslog "FCNC package found"
      $configdata.FCNCBins = $configdata.FCNCPackage
    } else {
      write-sdnexpresslog "FCNC package not found"
      throw "FCNC package not found"
    }

    # copy the nuget to a temp file, rename to zip , decompress it and delete the temp file        
    write-sdnexpresslog "copying FCNC package to $($configdata.FCNCBins)"
    Copy-Item $configdata.FCNCPackage "$($configdata.FCNCPackage).zip" -Verbose
    $configdata.FCNCBins = $configdata.FCNCPackage.Replace(".nupkg", ".zip")
        
    Copy-Item $configdata.FCNCPackage $configdata.FCNCBins -Force
    write-sdnexpresslog "unzipping FCNC package"
    Expand-Archive -Path $configdata.FCNCBins -DestinationPath $configdata.FCNCBins.Replace(".zip", "") -Force
    $configdata.FCNCBins = $configdata.FCNCBins.Replace(".zip", "")
  }
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

    $createparams = @{
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
        $createparams.ProductKey = $ConfigData.ProductKey
    }
    if (![String]::IsNullOrEmpty($ConfigData.Locale)) {
        $createparams.Locale = $ConfigData.Locale
    }
    if (![String]::IsNullOrEmpty($ConfigData.TimeZone)) {
        $createparams.TimeZone = $ConfigData.TimeZone
    }

    write-SDNExpressLog "STAGE 1.0.1: Enable VFP"
    foreach ($h in $ConfigData.hypervhosts) {

        write-SDNExpressLog "Adding net virt feature to $($h)"
        invoke-command -ComputerName $h -credential $credential {
            add-windowsfeature NetworkVirtualization -IncludeAllSubFeature -IncludeManagementTools
        }
     
        write-SDNExpressLog "Enabling VFP on $($h) $($ConfigData.SwitchName)"
        invoke-command -ComputerName $h -credential $credential {
            param(
                [String] $VirtualSwitchName
                )
            Enable-VmSwitchExtension -VMSwitchName $VirtualSwitchName -Name "Microsoft Azure VFP Switch Extension"
        } -ArgumentList $ConfigData.SwitchName

        invoke-command -ComputerName $h -credential $credential {
          Set-Service -Name NCHostAgent  -StartupType Automatic; Start-Service -Name NCHostAgent 
        }
    }

    $HostNameIter = 0
    
    $useCertBySubject = $false

    if ($ConfigData.UseCertBySubject) { 
        $useCertBySubject = $true
    }

    if (-not $ConfigData.UseFCNC) {
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
    }


    foreach ($Mux in $ConfigData.Muxes) {
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


    if (-not $ConfigData.UseFCNC) {
        write-SDNExpressLog "STAGE 1.1: Create NC VMs"
        foreach ($NC in $ConfigData.NCs) {
            $createparams.ComputerName=$NC.HostName;
            $createparams.VMName=$NC.ComputerName;
            if ([string]::IsNullOrEmpty($NC.ManagementIP)) {
                $createparams.Nics=@(
                    @{Name="Management"; MacAddress=$NC.MacAddress; VLANID=$ConfigData.ManagementVLANID; SwitchName=$NC.ManagementSwitch}
                )
            } else {
                $createparams.Nics=@(
                    @{Name="Management"; MacAddress=$NC.MacAddress; IPAddress="$($NC.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID; SwitchName=$NC.ManagementSwitch}
                )
            }
            $createparams.Roles=@("NetworkController","NetworkControllerTools")
            New-SDNExpressVM @createparams
        }
    }


    write-SDNExpressLog "STAGE 1.2: Create Mux VMs"

    foreach ($Mux in $ConfigData.Muxes) {
        $createparams.ComputerName=$mux.HostName;
        $createparams.VMName=$mux.ComputerName;
        if ([string]::IsNullOrEmpty($Mux.ManagementIP)) {
            $createparams.Nics=@(
                @{Name="Management"; MacAddress=$Mux.MacAddress; VLANID=$ConfigData.ManagementVLANID; SwitchName=$Mux.ManagementSwitch},
                @{Name="HNVPA"; MacAddress=$Mux.PAMacAddress; IPAddress="$($Mux.PAIPAddress)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID; IsMuxPA=$true}
            )
        } else {
            $createparams.Nics=@(
                @{Name="Management"; MacAddress=$Mux.MacAddress; IPAddress="$($Mux.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID; SwitchName=$Mux.ManagementSwitch},
                @{Name="HNVPA"; MacAddress=$Mux.PAMacAddress; IPAddress="$($Mux.PAIPAddress)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID; IsMuxPA=$true}
            )
        }
        $createparams.Roles=@("SoftwareLoadBalancer")

        New-SDNExpressVM @createparams
    }


    if ($ConfigData.NCs.count -gt 0 -or $ConfigData.UseFCNC) {
        write-SDNExpressLog "STAGE 2: Network Controller Configuration"
        $NCNodes = @()

        
        if ($ConfigData.UseFCNC) {

            if ([string]::IsNullOrEmpty($ConfigData.FCNCBins))
            {
                $ConfigData.FCNCBins = "C:\Windows\NetworkController"
            }

            $NCNodes = $ConfigData.HyperVHosts

            $params = @{
                'Credential'=$Credential
                'RestName'=$ConfigData.RestName
                'RestIpAddress'=$ConfigData.RestIpAddress
                'ComputerNames'=$NCNodes
                'FCNCBins' = $ConfigData.FCNCBins
                'FCNCDBs' = $ConfigData.FCNCDBs
                'ClusterNetworkName' = $ConfigData.ClusterNetworkName
                'UseCertBySubject' = $useCertBySubject
            }
            
            New-FCNCNetworkController @params

        } else {
            foreach ($NC in $ConfigData.NCs) {
                $NCNodes += $NC.ComputerName
            }

            WaitforComputerToBeReady -ComputerName $NCNodes -Credential $Credential

            $params = @{
                'Credential'=$Credential
                'RestName'=$ConfigData.RestName
                'RestIpAddress'=$ConfigData.RestIpAddress
                'ComputerNames'=$NCNodes
                'UseCertBySubject' = $useCertBySubject
            }

            if (![string]::IsNullOrEmpty($ConfigData.ManagementSecurityGroup)) {
                $params.ManagementSecurityGroupName = $ConfigData.ManagementSecurityGroup
                $params.ClientSecurityGroupName = $ConfigData.ClientSecurityGroup
            }
            New-SDNExpressNetworkController @params
        }


        write-SDNExpressLog "STAGE 2.1: Getting REST cert thumbprint in order to find it in local root store."

        # Check through nodes until we find a node that was originally set up with 
        $NCHostCertThumb = $null
        $nodeIdx = 0
        while ($null -eq $NCHostCertThumb -and $nodeIdx -lt $NCNodes.length) {
            $NCHostCertThumb = invoke-command -ComputerName $NCNodes[$nodeIdx] -Credential $credential { 
                param(
                    $RESTName,
                    [String] $funcDefGetSdnCert
                )
                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $RestName.ToUpper()
                return $cert.Thumbprint        
            } -ArgumentList $ConfigData.RestName, $Global:fdGetSdnCert

            $nodeIdx++
        }

        $NCHostCert = get-childitem "cert:\localmachine\root\$NCHostCertThumb"

        $params = @{
            'RestName' = $ConfigData.RestName;
            'MacAddressPoolStart' = $ConfigData.SDNMacPoolStart;
            'MacAddressPoolEnd' = $ConfigData.SDNMacPoolEnd;
            'NCHostCert' = $NCHostCert
            'NCUsername' = $ConfigData.NCUsername;
            'NCPassword' = $NCPassword
            'UseCertBySubject' = $useCertBySubject
        }
        New-SDNExpressVirtualNetworkManagerConfiguration @Params -Credential $Credential

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
        $NCHostCert = GetSdnCert -subjectName $configdata.RestName -store "cert:\localmachine\root" 

        if ($null -eq $NCHostCert) {
            $ErrorText = "Network Controller cert with CN=$($configdata.RestName) not found on $(hostname) in cert:\localmachine\root"
            write-SDNExpressLog $ErrorText
            throw $ErrorText
        }        
    }

    $useFcNc = $false
    if ($ConfigData.UseFCNC)
    { 
        $useFcNc = $true
    } 

    if ($ConfigData.Muxes.Count -gt 0) {
        write-SDNExpressLog "STAGE 3: SLB Configuration"

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

        WaitforComputerToBeReady -ComputerName $ConfigData.Muxes.ComputerName -Credential $Credential

        foreach ($Mux in $ConfigData.muxes) {
            Add-SDNExpressMux -ComputerName $Mux.ComputerName -PAMacAddress $Mux.PAMacAddress -PAGateway $ConfigData.PAGateway -LocalPeerIP $Mux.PAIPAddress -MuxASN $ConfigData.SDNASN -Routers $ConfigData.Routers -RestName $ConfigData.RestName -NCHostCert $NCHostCert -Credential $Credential -IsFC $useFcNc
        }
    }


    write-SDNExpressLog "STAGE 4: Host Configuration"
    $params = @{}

    if (![string]::IsNullOREmpty($ConfigData.PASubnet)) {
        $params.HostPASubnetPrefix = $ConfigData.PASubnet;
    }

    foreach ($h in $ConfigData.hypervhosts) {
        if($ConfigData.Port -ne $null -and $ConfigData.Port -ne 0) {
            write-SDNExpressLog "Using port $($ConfigData.Port) for host $h"
            $params.Port = $ConfigData.Port
        }

        Add-SDNExpressHost @params -ComputerName $h `
                                -RestName $ConfigData.RestName `
                                -NCHostCert $NCHostCert `
                                -Credential $Credential `
                                -VirtualSwitchName $ConfigData.SwitchName `
                                -IsFC $useFcNc
    }

    if ($ConfigData.Gateways.Count -gt 0) {
        write-SDNExpressLog "STAGE 5.1: Create Gateway VMs"

        foreach ($Gateway in $ConfigData.Gateways) {
            $params = @{
                'RestName'=$ConfigData.RestName
                'ComputerName'=$gateway.computername
                'HostName'=$gateway.Hostname
                'JoinDomain'=$ConfigData.JoinDomain
                'FrontEndLogicalNetworkName'='HNVPA'
                'FrontEndAddressPrefix'=$ConfigData.PASubnet
            }
    
            $Result = Initialize-SDNExpressGateway @params -Credential $Credential
    
            $Gateway.FrontEndMac = $Result.FrontEndMac
            $Gateway.FrontEndIP = $Result.FrontEndIP
            $Gateway.BackEndMac = $Result.BackEndMac

            $createparams.ComputerName=$Gateway.HostName;
            $createparams.VMName=$Gateway.ComputerName;
            if ([string]::IsNullOrEmpty($Gateway.ManagementIP)) {
                $createparams.Nics=@(
                    @{Name="Management"; MacAddress=$Gateway.MacAddress; VLANID=$ConfigData.ManagementVLANID; SwitchName=$Mux.ManagementSwitch}
                    @{Name="FrontEnd"; MacAddress=$Gateway.FrontEndMac; IPAddress="$($Gateway.FrontEndIp)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID},
                    @{Name="BackEnd"; MacAddress=$Gateway.BackEndMac; VLANID=$ConfigData.PAVLANID}
                );
            } else {
                $createparams.Nics=@(
                    @{Name="Management"; MacAddress=$Gateway.MacAddress; IPAddress="$($Gateway.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID; SwitchName=$Mux.ManagementSwitch}
                    @{Name="FrontEnd"; MacAddress=$Gateway.FrontEndMac; IPAddress="$($Gateway.FrontEndIp)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID},
                    @{Name="BackEnd"; MacAddress=$Gateway.BackEndMac; VLANID=$ConfigData.PAVLANID}
                );
            }
            $createparams.Roles=@("RemoteAccess", "RemoteAccessServer", "RemoteAccessMgmtTools", "RemoteAccessPowerShell", "RasRoutingProtocols", "Web-Application-Proxy")
    
            New-SDNExpressVM @createparams
        }
    
        write-SDNExpressLog "STAGE 5.3: Configure Gateways"

        if ([String]::IsNullOrEmpty($ConfigData.RedundantCount)) {
            $ConfigData.RedundantCount = 1
        } 

        if ([string]::IsNullOrEmpty($configdata.GatewayPoolType) -or ($configdata.GatewayPoolType -eq "All")) {
            write-SDNExpressLog "Gateway pool type is All."
            New-SDNExpressGatewayPool -IsTypeAll -PoolName $ConfigData.PoolName -Capacity $ConfigData.Capacity -GreSubnetAddressPrefix $ConfigData.GreSubnet -RestName $ConfigData.RestName -Credential $Credential -RedundantCount $ConfigData.RedundantCount
        } elseif ($configdata.GatewayPoolType -eq "GRE") {
            write-SDNExpressLog "Gateway pool type is GRE."
            New-SDNExpressGatewayPool -IsTypeGRE -PoolName $ConfigData.PoolName -Capacity $ConfigData.Capacity -GreSubnetAddressPrefix $ConfigData.GreSubnet -RestName $ConfigData.RestName -Credential $Credential -RedundantCount $ConfigData.RedundantCount
        } elseif ($configdata.GatewayPoolType -eq "Forwarding") {
            write-SDNExpressLog "Gateway pool type is Forwarding."
            New-SDNExpressGatewayPool -IsTypeForwarding -PoolName $ConfigData.PoolName -Capacity $ConfigData.Capacity -RestName $ConfigData.RestName -Credential $Credential -RedundantCount $ConfigData.RedundantCount
        } elseif ($configdata.GatewayPoolType -eq "IPSec") {
            write-SDNExpressLog "Gateway pool type is IPSec."
            New-SDNExpressGatewayPool -IsTypeIPSec -PoolName $ConfigData.PoolName -Capacity $ConfigData.Capacity -RestName $ConfigData.RestName -Credential $Credential -RedundantCount $ConfigData.RedundantCount
        } else {
            write-SDNExpressLog "Gateway pool type is Invalid."
            throw "Invalid GatewayPoolType specified in config file."
        } 

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
                'PAGateway'=$ConfigData.PAGateway
                'ManagementRoutes'=$ConfigData.ManagementRoutes
                'LocalASN'=$ConfigData.SDNASN
            }

            if ($ConfigData.UseGatewayFastPath -eq $true) {
                New-SDNExpressGateway @params  -Credential $Credential -UseFastPath -IsFC $useFcNc
            } else {
                New-SDNExpressGateway @params  -Credential $Credential -IsFC $useFcNc
            }
        }

    }

    test-sdnexpresshealth -restname $ConfigData.RestName -Credential $Credential
}
catch
{
	$pscmdlet.throwterminatingerror($PSItem)
}

write-SDNExpressLog "SDN Express deployment complete."
