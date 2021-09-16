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

set-strictmode -version 5.0

$VerbosePreference = 'Continue'

$Errors = [ordered] @{
    WINDOWSEDITION = @{Code = 4; Message="Software Defined Networking (SDN) requires an OS containing Windows Server 2016 Datacenter, Windows Server 2019 Datacenter, or Azure Stack HCI."};
    INVALIDKEYUSAGE = @{Code = 11; Message="Certificate in store has invalid key usage."};
    CERTTHUMBPRINT = @{Code = 8; Message="Inconsistent thumbprint for certs with same subject name."};
    NOADAPTERS = @{Code = 6; Message="Network Controller node requires at least one network adapter."};
    INVALIDVSWITCH = @{Code = 9; Message="Invalid virtual switch configuration on host."};
    GENERALEXCEPTION = @{Code = 3; Message="A general exception has occurred.  Check ErrorMessage for details."}
    COMPUTEREXISTS = @{Code = 1; Message="Unable to register the computer name in Active Directory.  This is usually caused by a permission error due to the name already existing, lack of privilege, or inability to delegate credentials."}
}

#The timestamp for the log is set at the time the module is imported.  Re-import the module to reset the log name.
$Logname = "SDNExpress-$(get-date -Format 'yyyyMMdd-HHmmss').log"


 #     #                                           #####                                                                
 ##    # ###### ##### #    #  ####  #####  #    # #     #  ####  #    # ##### #####   ####  #      #      ###### #####  
 # #   # #        #   #    # #    # #    # #   #  #       #    # ##   #   #   #    # #    # #      #      #      #    # 
 #  #  # #####    #   #    # #    # #    # ####   #       #    # # #  #   #   #    # #    # #      #      #####  #    # 
 #   # # #        #   # ## # #    # #####  #  #   #       #    # #  # #   #   #####  #    # #      #      #      #####  
 #    ## #        #   ##  ## #    # #   #  #   #  #     # #    # #   ##   #   #   #  #    # #      #      #      #   #  
 #     # ######   #   #    #  ####  #    # #    #  #####   ####  #    #   #   #    #  ####  ###### ###### ###### #    # 
                                                                                                                                                                                                                                                
<#
.SYNOPSIS
Brings up a Network Controller cluster on a set of computers.

.DESCRIPTION
New-SDNExpressNetworkController takes in a set of computers and configures them as a Network Controller cluster.  Computers must be pre-provisioned with network connectivity, Windows Server 2016 Datacenter Edition (or newer) and joined to active directory.  New-SDNExpressVM is typically used for create or other compatible method.  When complete the Network Controller cluster then needs to be further confgiured for use.   

.PARAMETER ComputerNames
Computers to be configured into the cluster of network controllers.  This is an array of computer names, with 1, 3 or 5 members.

.PARAMETER RESTName
The fully qualified domain name (FQDN) to be used as the Rest endpoint for the newly created cluster.  The network controller cluster will automatically register and update this name in DNS pointing to the node which contains the API server for the cluster. 

.PARAMETER RESTIPAddress
Specifies the IP address and subnet bits to follows the active API server node.  Must be on the same subnet as the network controller nodes and in the format <Ip Address>/<Subnet Bits>.  When using RESTIPAddress the RESTName must be manually registered to this IP in DNS.

.PARAMETER ManagementSecurityGroupName
Management security group for the network controller cluster.  When specified the cluster is configured for Kerberos authentication.

.PARAMETER ClientSecurityGroupName
Client security group for the network controller.  When specified the Network Controller is configured for Kerberos authentication.

.PARAMETER Credential
Credential to use for remoting into the Network Controller computers.

.PARAMETER Force
Forces the cluster to be recreated even if one already exists.  Use with caution.

.PARAMETER OperationID
Externally supplied Id relayed into progress and error messages.

.EXAMPLE
New-SDNExpressNetworkController -ComputerNames "Computer1","Computer2","Computer3" -RestName "sdn.contoso.com" -Credential (get-credential)

This example configures three computers into a network controller cluster and registers the rest interface with sdn.contoso.com.
.EXAMPLE
New-SDNExpressNetworkController -ComputerNames "Computer1","Computer2","Computer3" -RestIPAddress "10.10.10.10/24" -Credential (get-credential)

This example configures three computers into a network controller cluster and adds the RestIPAddress to the API server.  
.EXAMPLE
New-SDNExpressNetworkController -ComputerNames "Computer1","Computer2","Computer3" -RestName "sdn.contoso.com" -ManagementSecurityGroup "NCManagement" -ClientSecurityGroup "NCClients" -Credential (get-credential)

.NOTES
General notes
#>
 function New-SDNExpressNetworkController
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [String[]] $ComputerNames,
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]        
        [String] $RESTName,
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [String] $ManagementSecurityGroupName,
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [String] $ClientSecurityGroupName,
        [Parameter(Mandatory=$false,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$false,ParameterSetName="Default")]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "RESTIPAddress parameter must match the syntax <IP Address>/<Subnet bits>."}
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "Invalid IP address specified in RESTIPAddress parameter."}
            if (($split[1] -le 0) -or ($split[1] -gt 32)) { throw "Invalid subnet bits specified in RESTIPAddress parameter."}
            return $true
        })]        
        [String] $RESTIPAddress = "",
        [Parameter(Mandatory=$false,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$false,ParameterSetName="Default")]        
        [PSCredential] $Credential = $null,
        [Parameter(Mandatory=$false)]        
        [Switch] $Force,
        [Parameter(Mandatory=$false,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$false,ParameterSetName="Default")]        
        [String] $OperationID = ""
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet

    $certpwdstring = -join ((48..122) | Get-Random -Count 30 | % {[char]$_})

    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $feature = get-windowsfeature "RSAT-NetworkController"
    if ($null -eq $feature) {
        write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors['WINDOWSEDITION'].Code -LogMessage $Errors['WINDOWSEDITION'].Message  #No errormessage because SDN Express generates error
        throw $Errors['WINDOWSEDITION'].Message
    }
    if (!$feature.Installed) {
        add-windowsfeature "RSAT-NetworkController" | out-null
    }
    
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 10 -context $restname

    $RESTName = $RESTName.ToUpper()

    write-sdnexpresslog ("Checking if Controller already deployed by looking for REST response.")
    try { 
        get-networkcontrollerCredential -ConnectionURI "https://$RestName" @CredentialParam  | out-null
        if (!$force) {
            write-sdnexpresslog "Network Controller at $RESTNAME already exists, exiting New-SDNExpressNetworkController."
            Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 100 -context $restname
            return
        }
    }
    catch {
        write-sdnexpresslog "Network Controller does not exist, will continue."
    }

    write-sdnexpresslog "Setting properties and adding NetworkController role on all computers in parallel."
    invoke-command -ComputerName $ComputerNames {
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        write-verbose "Setting registry keys and wsman parameters"
        reg add hklm\system\currentcontrolset\services\tcpip6\parameters /v DisabledComponents /t REG_DWORD /d 255 /f | out-null
        Set-Item WSMan:\localhost\Shell\MaxConcurrentUsers -Value 100 | out-null
        Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000 | out-null

        write-verbose "Adding NetworkController feature if not already installed offline."
        add-windowsfeature NetworkController -IncludeAllSubFeature -IncludeManagementTools -Restart | out-null
    } @CredentialParam  | Parse-RemoteOutput

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 20 -context $restname
    write-sdnexpresslog "Creating local temp directory."

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $TempDir = $TempFile.FullName
    New-Item -ItemType Directory -Force -Path $TempDir | out-null

    write-sdnexpresslog "Temp directory is: $($TempFile.FullName)"
    write-sdnexpresslog "Creating REST cert on: $($computernames[0])"

    try {
        $RestCertPfxData = invoke-command -computername $ComputerNames[0] @CredentialParam {
            param(
                [String] $RestName,
                [String] $certpwdstring
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            $Cert = get-childitem "Cert:\localmachine\my" | where-object {$_.Subject.ToUpper().StartsWith("CN=$RestName".ToUpper())}

            if ($null -eq $Cert) {
                write-verbose "Creating new REST certificate." 
                $Cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$RESTName" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")
            } else {
                write-verbose "Found existing REST certficate." 
                $HasServerEku = $null -ne ($cert.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"})
                $HasClientEku = $null -ne ($cert.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"})
            
                if (!$HasServerEku) {
                    throw "Rest cert exists on $(hostname) but is missing the EnhancedKeyUsage for Server Authentication."
                }
                if (!$HasClientEku) {
                    throw "Rest cert exists but $(hostname) is missing the EnhancedKeyUsage for Client Authentication."
                }
                write-verbose "Existing certificate meets criteria.  Exporting." 
            }

            $TempFile = New-TemporaryFile
            Remove-Item $TempFile.FullName -Force | out-null
            [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
            $CertData = Get-Content $TempFile.FullName -Encoding Byte
            Remove-Item $TempFile.FullName -Force | out-null

            write-verbose "Returning Cert Data." 

            write-output $CertData
        } -ArgumentList $RestName, $certpwdstring | Parse-RemoteOutput
    }
    catch
    {
        write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors['INVALIDKEYUSAGE'].Code -LogMessage $_.Exception.Message   #No errormessage because SDN Express generates error
        throw $_.Exception
    }
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 30 -context $restname

    write-sdnexpresslog "Temporarily exporting Cert to My store."
    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $RestCertPfxData | set-content $TempFile.FullName -Encoding Byte
    $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
    $RESTCertPFX = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\my" -password $certpwd -exportable
    Remove-Item $TempFile.FullName -Force

    $RESTCertThumbprint = $RESTCertPFX.Thumbprint
    write-sdnexpresslog "REST cert thumbprint: $RESTCertThumbprint"
    write-sdnexpresslog "Exporting REST cert to PFX and CER in temp directory."
    
    [System.io.file]::WriteAllBytes("$TempDir\$RESTName.pfx", $RestCertPFX.Export("PFX", $certpwdstring))
    Export-Certificate -Type CERT -FilePath "$TempDir\$RESTName" -cert $RestCertPFX | out-null
    
    write-sdnexpresslog "Importing REST cert (public key only) into Root store."
    $RestCert = import-certificate -filepath "$TempDir\$RESTName" -certstorelocation "cert:\localmachine\root"

    write-sdnexpresslog "Deleting REST cert from My store."
    remove-item -path cert:\localmachine\my\$RESTCertThumbprint

    write-sdnexpresslog "Installing REST cert to my and root store of each NC node."

    foreach ($ncnode in $ComputerNames) {
        write-sdnexpresslog "Installing REST cert to my and root store of: $ncnode"
        try {
            invoke-command -computername $ncnode  @CredentialParam {
                param(
                    [String] $RESTName,
                    [byte[]] $RESTCertPFXData,
                    [String] $RESTCertThumbprint,
                    [String] $certpwdstring
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
        
                $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  

                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force
                $RESTCertPFXData | set-content $TempFile.FullName -Encoding Byte

                $Cert = get-childitem "Cert:\localmachine\my" | where-object {$_.Subject.ToUpper().StartsWith("CN=$RestName".ToUpper())}
                write-verbose "Found $($cert.count) certificate(s) in my store with subject name matching $RestName"
                if ($Cert -eq $null) {
                    write-verbose "Importing new REST cert into My store."
                    $cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\my" -password $certpwd -Exportable
                } else {
                    if ($cert.Thumbprint -ne $RestCertThumbprint) {
                        Remove-Item $TempFile.FullName -Force
                        throw "REST cert already exists in My store on $(hostname), but thumbprint does not match cert on other nodes."
                    }
                }
                
                write-verbose "Setting permissions on REST cert."
                $targetCertPrivKey = $Cert.PrivateKey 
                $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object {$_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName} 
                $privKeyAcl = Get-Acl $privKeyCertFile
                $permission = "NT AUTHORITY\NETWORK SERVICE","Read","Allow" 
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
                $privKeyAcl.AddAccessRule($accessRule) 
                Set-Acl $privKeyCertFile.FullName $privKeyAcl

                $Cert = get-childitem "Cert:\localmachine\root\$RestCertThumbprint" -erroraction Ignore
                if ($cert -eq $Null) {
                    write-verbose "REST cert does not yet exist in Root store, adding."
                    $cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
                }

                Remove-Item $TempFile.FullName -Force
            } -Argumentlist $RESTName, $RESTCertPFXData, $RESTCertThumbprint,$certpwdstring  | Parse-RemoteOutput
        }
        catch
        {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors['CERTTHUMBPRINT'].code -LogMessage $_.Exception.Message   #No errormessage because SDN Express generates error
            throw $_.Exception
        }


    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 40 -context $restname
    # Create Node cert for each NC

    $AllNodeCerts = @()


    foreach ($ncnode in $ComputerNames) {
        write-sdnexpresslog "Creating node cert for: $ncnode"
        try 
        {
            [byte[]] $CertData = invoke-command -computername $ncnode  @CredentialParam {
                param(
                    [String] $certpwdstring
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
                $Cert = get-childitem "Cert:\localmachine\my" | where-object {$_.Subject.ToUpper().StartsWith("CN=$NodeFQDN".ToUpper())}

                write-verbose "Found $($cert.count) certificate(s) in my store with subject name matching $NodeFQDN"

                if ($Cert -eq $null) {
                    write-verbose "Creating new self signed certificate in My store."
                    $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") -DNSNAME $RESTName
                } else {
                    $HasServerEku = ($cert.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"}) -ne $null
                    $HasClientEku = ($cert.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"}) -ne $null
                
                    if (!$HasServerEku) {
                        throw "Node cert exists on $(hostname) but is missing the EnhancedKeyUsage for Server Authentication."
                    }
                    if (!$HasClientEku) {
                        throw "Node cert exists but $(hostname) is missing the EnhancedKeyUsage for Client Authentication."
                    }
                    write-verbose "Using existing certificate with thumbprint $($cert.thumbprint)" 
                }

                write-verbose "Setting permissions on node cert."
                $targetCertPrivKey = $Cert.PrivateKey 
                $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object {$_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName} 
                $privKeyAcl = Get-Acl $privKeyCertFile
                $permission = "NT AUTHORITY\NETWORK SERVICE","Read","Allow" 
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
                $privKeyAcl.AddAccessRule($accessRule) | out-null
                Set-Acl $privKeyCertFile.FullName $privKeyAcl | out-null

                write-verbose "Exporting node cert."
                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force | out-null
                [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
                $CertData = Get-Content $TempFile.FullName -Encoding Byte
                Remove-Item $TempFile.FullName -Force | out-null

                write-output $CertData
            } -ArgumentList $CertPwdString | Parse-RemoteOutput
        }
        catch
        {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors['INVALIDKEYUSAGE'].Code -LogMessage $_.Exception.Message   #No errormessage because SDN Express generates error
            throw $_.Exception
        }

        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force
        
        $CertData | set-content $TempFile.FullName -Encoding Byte
        $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
        $AllNodeCerts += import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
        Remove-Item $TempFile.FullName -Force

        foreach ($othernode in $ComputerNames) {
            write-sdnexpresslog "Installing node cert for $ncnode into root store of $othernode."

            invoke-command -computername $othernode  @CredentialParam {
                param(
                    [String] $CertPwdString,
                    [Byte[]] $CertData
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
                    
                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force
    
                $CertData | set-content $TempFile.FullName -Encoding Byte
                $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
                $cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
                Remove-Item $TempFile.FullName -Force
            } -ArgumentList $certPwdString,$CertData | Parse-RemoteOutput         
        }
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 50 -context $restname

    write-sdnexpresslog "Configuring Network Controller role using node: $($ComputerNames[0])"
  
    $controller = $null
    try { $controller = get-networkcontroller -computername $ComputerNames[0] -erroraction Ignore } catch {}
    if ($controller -ne $null) {
        if ($force) {
            write-SDNExpressLog "Controller role found, force option specified, uninstlling."
            uninstall-networkcontroller -ComputerName $ComputerNames[0] -force
            uninstall-networkcontrollercluster -ComputerName $ComputerNames[0] -force
        } else {
            write-SDNExpressLog "Controller role found, force option not specified, exiting."
            Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 100 -context $restname
            return
        }
    } 

    $Nodes = @()

    foreach ($cert in $AllNodeCerts) {
        $NodeFQDN = $cert.subject.substring(3)
        $server = $NodeFQDN.Split(".")[0]
        write-SDNExpressLog "Configuring Node $NodeFQDN with cert thumbprint $($cert.thumbprint)."

        $nic = @()
        $nic += invoke-command -computername $server @CredentialParam { get-netadapter }
        if ($nic.count -gt 1) {
            write-SDNExpressLog ("WARNING: Invalid number of network adapters found in network Controller node.")    
            write-SDNExpressLog ("WARNING: Using first adapter returned: $($nic[0].name)")
            $nic = $nic[0]    
        } elseif ($nic.count -eq 0) {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["NOADAPTERS"].code -logmessage $Errors["NOADAPTERS"].Message   #No errormessage because SDN Express generates error
            write-SDNExpressLog ("ERROR: No network adapters found in network Controller node.")
            throw $Errors["NOADAPTERS"].Message
        } 

        $nodes += New-NetworkControllerNodeObject -Name $server -Server $NodeFQDN -FaultDomain ("fd:/"+$server) -RestInterface $nic.Name -NodeCertificate $cert -verbose                    
    }

    $params = @{
        'Node'=$nodes;
        'CredentialEncryptionCertificate'=$RESTCert;
        'Credential'=$Credential;
    }

    if ([string]::isnullorempty($ManagementSecurityGroupName)) {
        $params.add('ClusterAuthentication', 'X509');
    } else {
        $params.add('ClusterAuthentication', 'Kerberos');
        $params.add('ManagementSecurityGroup', $ManagementSecurityGroupName)
    }

    write-SDNExpressLog "Install-NetworkControllerCluster with parameters:"
    foreach ($i in $params.getenumerator()) { write-SDNExpressLog "   $($i.key)=$($i.value)"}
    Install-NetworkControllerCluster @Params -Force | out-null
    write-SDNExpressLog "Finished Install-NetworkControllerCluster."
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 70 -context $restname

    $params = @{
        'ComputerName'=$ComputerNames[0]
        'Node'=$nodes;
        'ServerCertificate'=$RESTCert;
        'Credential'=$Credential;
    }

    if ([string]::isnullorempty($ClientSecurityGroupName)) {
        $params.add('ClientAuthentication', 'None');
    } else {
        $params.add('ClientAuthentication', 'Kerberos');
        $params.add('ClientSecurityGroup', $ClientSecurityGroupName)
    }

    if (![string]::isnullorempty($RestIpAddress)) {
        $params.add('RestIPAddress', $RestIpAddress);
    } else {
        $params.add('RestName', $RESTName);
    }

    write-SDNExpressLog "Install-NetworkController with parameters:"
    foreach ($i in $params.getenumerator()) { write-SDNExpressLog "   $($i.key)=$($i.value)"}
    Install-NetworkController @params -force | out-null
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 90 -context $restname

    write-SDNExpressLog "Install-NetworkController complete."
    Write-SDNExpressLog "Network Controller cluster creation complete."
    
    #Verify that SDN REST endpoint is working before returning
    Write-SDNExpressLog "Verifying Network Controller is operational."

    $dnsServers = (Get-DnsClientServerAddress -AddressFamily ipv4).ServerAddresses | select -uniq
    $dnsWorking = $true

    foreach ($dns in $dnsServers)
    {
        $dnsResponse = $null
        $count = 0

        while (($dnsResponse -eq $null) -and ($count -lt 90)) {
            $dnsResponse = Resolve-DnsName -name $RESTName -Server $dns -ErrorAction Ignore
            if ($dnsResponse -eq $null) {
                sleep 20
            }
            $count++
        }

        if ($count -eq 90) {
            write-sdnexpresslog "REST name not resolving from $dns after 30 minutes."
            $dnsWorking = $false
        } else {
            write-sdnexpresslog "REST name resolved from $dns after $count tries."
        }
    }

    if (!$dnsWorking) {
        Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 100 -context $restname
        return
    }

    write-sdnexpresslog ("Checking for REST response.")
    $NotResponding = $true
    while ($NotResponding) {
        try { 
            $NotResponding = $false
            clear-dnsclientcache
            get-networkcontrollerCredential -ConnectionURI "https://$RestName" @CredentialParam  | out-null
        }
        catch {
            write-sdnexpresslog "Network Controller is not responding.  Will try again in 10 seconds."
            sleep 10
            $NotResponding = $true
        }
    }

    Write-SDNExpressLog "Sleep 60 to allow controller time to settle down."
    Start-Sleep -Seconds 60

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 100 -context $restname
    write-sdnexpresslog ("Network controller setup is complete and ready to use.")
    write-sdnexpresslog "New-SDNExpressNetworkController Exit"
}





 #     # #     #               #####                                
 #     # ##    # ###### ##### #     #  ####  #    # ###### #  ####  
 #     # # #   # #        #   #       #    # ##   # #      # #    # 
 #     # #  #  # #####    #   #       #    # # #  # #####  # #      
  #   #  #   # # #        #   #       #    # #  # # #      # #  ### 
   # #   #    ## #        #   #     # #    # #   ## #      # #    # 
    #    #     # ######   #    #####   ####  #    # #      #  ####  
                                                                    


function New-SDNExpressVirtualNetworkManagerConfiguration
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [String] $MacAddressPoolStart,
        [String] $MacAddressPoolEnd,
        [Object] $NCHostCert,
        [String] $NCUsername,
        [String] $NCPassword,
        [PSCredential] $Credential = $null
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    $uri = "https://$RestName"

    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    write-sdnexpresslog "Writing Mac Pool."
    $MacAddressPoolStart = [regex]::matches($MacAddressPoolStart.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
    $MacAddressPoolEnd = [regex]::matches($MacAddressPoolEnd.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"

    $MacPoolProperties = new-object Microsoft.Windows.NetworkController.MacPoolProperties
    $MacPoolProperties.StartMacAddress = $MacAddressPoolStart
    $MacPoolProperties.EndMacAddress = $MacAddressPoolEnd
    $MacPoolObject = New-NetworkControllerMacPool -connectionuri $uri -ResourceId "DefaultMacPool" -properties $MacPoolProperties @CredentialParam -Force -passinnerexception

    write-sdnexpresslog "Writing controller credential."
    $CredentialProperties = new-object Microsoft.Windows.NetworkController.CredentialProperties
    $CredentialProperties.Type = "X509Certificate"
    $CredentialProperties.Value = $NCHostCert.thumbprint
    $HostCertObject = New-NetworkControllerCredential -ConnectionURI $uri -ResourceId "NCHostCert" -properties $CredentialProperties @CredentialParam -force -passinnerexception    

    write-sdnexpresslog "Writing domain credential."
    $CredentialProperties = new-object Microsoft.Windows.NetworkController.CredentialProperties
    $CredentialProperties.Type = "UsernamePassword"
    $CredentialProperties.UserName = $NCUsername
    $CredentialProperties.Value = $NCPassword
    $HostUserObject = New-NetworkControllerCredential -ConnectionURI $uri -ResourceId "NCHostUser" -properties $CredentialProperties @CredentialParam -force -passinnerexception    

    write-sdnexpresslog "Writing PA logical network."
    try {
        $LogicalNetworkObject = get-NetworkControllerLogicalNetwork -ConnectionURI $uri -ResourceID "HNVPA" @CredentialParam -passinnerexception    
    } 
    catch
    {
        $LogicalNetworkProperties = new-object Microsoft.Windows.NetworkController.LogicalNetworkProperties
        $LogicalNetworkProperties.NetworkVirtualizationEnabled = $true
        $LogicalNetworkObject = New-NetworkControllerLogicalNetwork -ConnectionURI $uri -ResourceID "HNVPA" -properties $LogicalNetworkProperties @CredentialParam -Force -passinnerexception    
    }
    write-sdnexpresslog "New-SDNExpressVirtualNetworkManagerConfiguration Exit"
}




 #     # #     #              ######     #     #####                                
 #     # ##    # ###### ##### #     #   # #   #     #  ####  #    # ###### #  ####  
 #     # # #   # #        #   #     #  #   #  #       #    # ##   # #      # #    # 
 #     # #  #  # #####    #   ######  #     # #       #    # # #  # #####  # #      
  #   #  #   # # #        #   #       ####### #       #    # #  # # #      # #  ### 
   # #   #    ## #        #   #       #     # #     # #    # #   ## #      # #    # 
    #    #     # ######   #   #       #     #  #####   ####  #    # #      #  ####  
                                                                                    


function Add-SDNExpressVirtualNetworkPASubnet
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [String] $AddressPrefix,
        [String] $VLANID,
        [String[]] $DefaultGateways,
        [Object] $IPPoolStart,
        [String] $IPPoolEnd,
        [PSCredential] $Credential = $null,
        [String] $LogicalNetworkName = "HNVPA",
        [string] $Servers = $null,
        [switch] $AllServers
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    $DefaultRestParams = @{
        'ConnectionURI'="https://$RestName";
        'PassInnerException'=$true;
        'Credential'=$credential
    }

    if ($null -ne $Credential) {
        $DefaultRestParams.Credential = $credential
    }
    
    $PALogicalSubnets = get-networkcontrollerLogicalSubnet @DefaultRestParams -LogicalNetworkId $LogicalNetworkName 
    $PALogicalSubnet = $PALogicalSubnets | where-object {$_.properties.AddressPrefix -eq $AddressPrefix}
    
    if ($PALogicalSubnet -eq $null) {
        write-sdnexpresslog "PA Logical subnet does not yet exist, creating."
        $LogicalSubnetProperties = new-object Microsoft.Windows.NetworkController.LogicalSubnetProperties
        $logicalSubnetProperties.VLANId = $VLANID
        $LogicalSubnetProperties.AddressPrefix = $AddressPrefix
        $LogicalSubnetProperties.DefaultGateways = $DefaultGateways
    
        $PALogicalSubnet = New-NetworkControllerLogicalSubnet @DefaultRestParams  -LogicalNetworkId $LogicalNetworkName -ResourceId $AddressPrefix.Replace("/", "_") -properties $LogicalSubnetProperties -Force 
    }
    
    $IPpoolProperties = new-object Microsoft.Windows.NetworkController.IPPoolproperties
    $ippoolproperties.startipaddress = $IPPoolStart
    $ippoolproperties.endipaddress = $IPPoolEnd

    $IPPoolObject = New-networkcontrollerIPPool @DefaultRestParams  -NetworkId $LogicalNetworkName -SubnetId $AddressPrefix.Replace("/", "_") -ResourceID $AddressPrefix.Replace("/", "_") -Properties $IPPoolProperties -force

    write-sdnexpresslog "Updating specified servers."
    $ServerObjects = get-networkcontrollerserver @DefaultRestParams

    if (!$AllServers) {
        $ServerObjects = $ServerObjects | ?{$_.properties.connections.managementaddresses -in $Servers}
    }

    if ($ServerObjects -ne $null) {
        write-sdnexpresslog "Found $($ServerObjects.count) servers."
    } else {
        write-sdnexpresslog "Found 0 servers."

    }

    foreach ($server in $ServerObjects) {
        if (($server.properties.networkinterfaces.properties.logicalsubnets.count -eq 0) -or !($PALogicalSubnet.resourceref -in $server.properties.networkinterfaces.properties.logicalsubnets.resourceref)) {
            write-sdnexpresslog "Adding subnet to $($server.resourceid)."
            $server.properties.networkinterfaces[0].properties.logicalsubnets += $PALogicalSubnet
            New-networkcontrollerserver @DefaultRestParams -resourceid $server.resourceid -properties $server.properties -force | out-null
        } else {
            write-sdnexpresslog "Subnet has already been added to $($server.resourceid)."
        }
    }
    write-sdnexpresslog "$($MyInvocation.InvocationName) Exit"
}




  #####  #       ######  #     #                                            #####                                
 #     # #       #     # ##   ##   ##   #    #   ##    ####  ###### #####  #     #  ####  #    # ###### #  ####  
 #       #       #     # # # # #  #  #  ##   #  #  #  #    # #      #    # #       #    # ##   # #      # #    # 
  #####  #       ######  #  #  # #    # # #  # #    # #      #####  #    # #       #    # # #  # #####  # #      
       # #       #     # #     # ###### #  # # ###### #  ### #      #####  #       #    # #  # # #      # #  ### 
 #     # #       #     # #     # #    # #   ## #    # #    # #      #   #  #     # #    # #   ## #      # #    # 
  #####  ####### ######  #     # #    # #    # #    #  ####  ###### #    #  #####   ####  #    # #      #  ####  
                                                                                                                 



function New-SDNExpressLoadBalancerManagerConfiguration
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "When calling function New-SDNExpressLoadBalancerManagerConfiguration, PrivateVIPPrefix must be in CIDR format with the syntax of <IP subnet>/<Subnet bits>."}
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "When calling function New-SDNExpressLoadBalancerManagerConfiguration, Invalid subnet portion of PrivateVIPPrefix parameter."}
            if (($split[1] -le 0) -or ($split[1] -gt 32)) { throw "When calling function New-SDNExpressLoadBalancerManagerConfiguration, Invalid subnet bits portion of PrivateVIPPrefix parameter."}
            return $true
        })]       
        [String] $PrivateVIPPrefix,
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "When calling function New-SDNExpressLoadBalancerManagerConfiguration, PublicVIPPrefix must be in CIDR format with the syntax of <IP subnet>/<Subnet bits>."}
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "When calling function New-SDNExpressLoadBalancerManagerConfiguration, Invalid subnet portion of PublicVIPPrefix parameter."}
            if (($split[1] -le 0) -or ($split[1] -gt 32)) { throw "When calling function New-SDNExpressLoadBalancerManagerConfiguration, Invalid subnet bits portion of PublicVIPPrefix parameter."}
            return $true
        })]       
        [String] $PublicVIPPrefix,
        [String] $SLBMVip = (get-ipaddressinsubnet -subnet $PrivateVIPPrefix -offset 1),
        [String] $PrivateVIPPoolStart = (get-ipaddressinsubnet -subnet $PrivateVIPPrefix -offset 1),
        [String] $PrivateVIPPoolEnd = (Get-IPLastAddressInSubnet -subnet $PrivateVIPPrefix),
        [String] $PublicVIPPoolStart = (get-ipaddressinsubnet -subnet $PublicVIPPrefix -offset 1),
        [String] $PublicVIPPoolEnd = (Get-IPLastAddressInSubnet -subnet $PublicVIPPrefix),
        [PSCredential] $Credential = $null
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    $DefaultRestParams = @{
        'ConnectionURI'="https://$RestName";
        'PassInnerException'=$true;
    }
    if ($null -ne $Credential) {
        $DefaultRestParams.Credential = $credential
    }
    #PrivateVIP LN
    try
    {
        $PrivateVIPLNObject = Get-NetworkControllerLogicalNetwork @DefaultRestParams -ResourceID "PrivateVIP"
    }
    catch 
    {
        $LogicalNetworkProperties = new-object Microsoft.Windows.NetworkController.LogicalNetworkProperties
        $LogicalNetworkProperties.NetworkVirtualizationEnabled = $false
        $LogicalNetworkProperties.Subnets = @()
        $LogicalNetworkProperties.Subnets += new-object Microsoft.Windows.NetworkController.LogicalSubnet
        $logicalNetworkProperties.Subnets[0].ResourceId = $PrivateVIPPrefix.Replace("/", "_")
        $logicalNetworkProperties.Subnets[0].Properties = new-object Microsoft.Windows.NetworkController.LogicalSubnetProperties
        $logicalNetworkProperties.Subnets[0].Properties.AddressPrefix = $PrivateVIPPrefix
        $logicalNetworkProperties.Subnets[0].Properties.DefaultGateways = @(get-ipaddressinsubnet -subnet $PrivateVIPPrefix)

        $PrivateVIPLNObject = New-NetworkControllerLogicalNetwork @DefaultRestParams -ResourceID "PrivateVIP" -properties $LogicalNetworkProperties -force
    }

    $IPpoolProperties = new-object Microsoft.Windows.NetworkController.IPPoolproperties
    $ippoolproperties.startipaddress = $PrivateVIPPoolStart
    $ippoolproperties.endipaddress = $PrivateVIPPoolEnd

    $PrivatePoolObject = new-networkcontrollerIPPool @DefaultRestParams -NetworkId "PrivateVIP" -SubnetId $PrivateVIPPrefix.Replace("/", "_") -ResourceID $PrivateVIPPrefix.Replace("/", "_") -Properties $IPPoolProperties -force
    
    #PublicVIP LN
    try
    {
        $PublicVIPLNObject = get-NetworkControllerLogicalNetwork @DefaultRestParams -ResourceID "PublicVIP"
    }
    catch 
    {
        $LogicalNetworkProperties = new-object Microsoft.Windows.NetworkController.LogicalNetworkProperties
        $LogicalNetworkProperties.NetworkVirtualizationEnabled = $false
        $LogicalNetworkProperties.Subnets = @()
        $LogicalNetworkProperties.Subnets += new-object Microsoft.Windows.NetworkController.LogicalSubnet
        $logicalNetworkProperties.Subnets[0].ResourceId = $PublicVIPPrefix.Replace("/", "_")
        $logicalNetworkProperties.Subnets[0].Properties = new-object Microsoft.Windows.NetworkController.LogicalSubnetProperties
        $logicalNetworkProperties.Subnets[0].Properties.AddressPrefix = $PublicVIPPrefix
        $logicalNetworkProperties.Subnets[0].Properties.DefaultGateways = @(get-ipaddressinsubnet -subnet $PublicVIPPrefix)
        $logicalnetworkproperties.subnets[0].properties.IsPublic = $true

        $PublicVIPLNObject = New-NetworkControllerLogicalNetwork @DefaultRestParams -ResourceID "PublicVIP" -properties $LogicalNetworkProperties -Force
    }

    $IPpoolProperties = new-object Microsoft.Windows.NetworkController.IPPoolproperties
    $ippoolproperties.startipaddress = $PublicVIPPoolStart
    $ippoolproperties.endipaddress = $PublicVIPPoolEnd

    $PublicPoolObject = new-networkcontrollerIPPool @DefaultRestParams -NetworkId "PublicVIP" -SubnetId $PublicVIPPrefix.Replace("/", "_") -ResourceID $PublicVIPPrefix.Replace("/", "_") -Properties $IPPoolProperties -force
    
    #SLBManager Config

    $managerproperties = new-object Microsoft.Windows.NetworkController.LoadBalancerManagerProperties
    $managerproperties.LoadBalancerManagerIPAddress = $SLBMVip
    $managerproperties.OutboundNatIPExemptions = @("$SLBMVIP/32")
    $managerproperties.VipIPPools = @($PrivatePoolObject, $PublicPoolObject)

    $SLBMObject = new-networkcontrollerloadbalancerconfiguration @DefaultRestParams -properties $managerproperties -resourceid "config" -Force
    write-sdnexpresslog "$($MyInvocation.InvocationName) Exit"
}



    #                   #####  #       ######  #     # ### ######   #####                                    
   # #   #####  #####  #     # #       #     # #     #  #  #     # #     # #    # #####  #    # ###### ##### 
  #   #  #    # #    # #       #       #     # #     #  #  #     # #       #    # #    # ##   # #        #   
 #     # #    # #    #  #####  #       ######  #     #  #  ######   #####  #    # #####  # #  # #####    #   
 ####### #    # #    #       # #       #     #  #   #   #  #             # #    # #    # #  # # #        #   
 #     # #    # #    # #     # #       #     #   # #    #  #       #     # #    # #    # #   ## #        #   
 #     # #####  #####   #####  ####### ######     #    ### #        #####   ####  #####  #    # ######   #   
                                                                                                             


function Add-SDNExpressLoadBalancerVIPSubnet
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [String] $VIPPrefix,
        [String] $VIPPoolStart = (get-ipaddressinsubnet -subnet $VIPPrefix -offset 1),
        [String] $VIPPoolEnd = (Get-IPLastAddressInSubnet -subnet $VIPPrefix),
        [Switch] $IsPrivate,
        [String] $LogicalNetworkName = "",
        [PSCredential] $Credential = $null
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    $DefaultRestParams = @{
        'ConnectionURI'="https://$RestName";
        'PassInnerException'=$true;
    }
    if ($null -ne $Credential) {
        $DefaultRestParams.Credential = $credential
    }
    if ([String]::IsNullOrEmpty($LogicalNetworkName)) {
        if ($isPrivate) {
            $logicalnetworkname = "PrivateVIP"
        } else {
            $logicalnetworkname = "PublicVIP"
        }
    } 
    write-sdnexpresslog "Logicalnetwork is $logicalnetworkname"

    $VIPLogicalSubnets = get-networkcontrollerLogicalSubnet @DefaultRestParams -LogicalNetworkId $LogicalNetworkName 
    $VIPLogicalSubnet = $VIPLogicalSubnets | where-object {$_.properties.AddressPrefix -eq $VIPPrefix}
    
    if ($VIPLogicalSubnet -eq $null) {
        write-sdnexpresslog "VIP Logical subnet does not yet exist, creating."
        $LogicalSubnetProperties = new-object Microsoft.Windows.NetworkController.LogicalSubnetProperties
        $LogicalSubnetProperties.AddressPrefix = $VIPPrefix
        $LogicalSubnetProperties.DefaultGateways = @(get-ipaddressinsubnet -subnet $VIPPrefix)
        $logicalsubnetproperties.IsPublic = !$IsPrivate
        $LogicalSubnet = New-NetworkControllerLogicalSubnet @DefaultRestParams  -LogicalNetworkId $LogicalNetworkName -ResourceId $VIPPrefix.Replace("/", "_") -properties $LogicalSubnetProperties -Force
    }

    $IPpoolProperties = new-object Microsoft.Windows.NetworkController.IPPoolproperties
    $ippoolproperties.startipaddress = $VIPPoolStart
    $ippoolproperties.endipaddress = $VIPPoolEnd

    $PoolObject = new-networkcontrollerIPPool @DefaultRestParams -NetworkId $logicalnetworkname -SubnetId $VIPPrefix.Replace("/", "_") -ResourceID $VIPPrefix.Replace("/", "_") -Properties $IPPoolProperties -force
        
    #SLBManager Config
    $manager = Get-NetworkControllerLoadBalancerConfiguration @DefaultRestParams  
    $manager.properties.VipIPPools += $PoolObject
    $SLBMObject = new-networkcontrollerloadbalancerconfiguration @DefaultRestParams -properties $manager.properties -resourceid $manager.resourceid -Force

    write-sdnexpresslog "$($MyInvocation.InvocationName) Exit"
}



   ######  #     #  #####   #####                                
 # #     # ##    # #     # #     #  ####  #    # ###### #  ####  
 # #     # # #   # #       #       #    # ##   # #      # #    # 
 # #     # #  #  #  #####  #       #    # # #  # #####  # #      
 # #     # #   # #       # #       #    # #  # # #      # #  ### 
 # #     # #    ## #     # #     # #    # #   ## #      # #    # 
 # ######  #     #  #####   #####   ####  #    # #      #  ####  
                                                                 


function New-SDNExpressiDNSConfiguration
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [String] $Username,
        [String] $Password,
        [String] $IPAddress,
        [String] $ZoneName,
        [PSCredential] $Credential = $null
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $uri = "https://$RestName"    

    $CredentialProperties = new-object Microsoft.Windows.NetworkController.CredentialProperties
    $CredentialProperties.Type = "UsernamePassword"
    $CredentialProperties.UserName = $Username
    $CredentialProperties.Value = $Password
    $iDNSUserObject = New-NetworkControllerCredential -ConnectionURI $uri -ResourceId "iDNSUser" -properties $CredentialProperties @CredentialParam -force  -passinnerexception   
    
    $iDNSProperties = new-object microsoft.windows.networkcontroller.InternalDNSServerProperties
    $iDNSProperties.Connections += new-object Microsoft.Windows.NetworkController.Connection
    $iDNSProperties.Connections[0].Credential = $iDNSUserObject
    $iDNSProperties.Connections[0].CredentialType = $iDNSUserObject.properties.Type
    $iDNSProperties.Connections[0].ManagementAddresses = $IPAddress

    $iDNSProperties.Zone = $ZoneName

    New-NetworkControllerIDnsServerConfiguration -connectionuri $RestName -ResourceId "configuration" -properties $iDNSProperties -force @CredentialParam  -passinnerexception   
}



 #     # #     # ######                       #####                                
 #     # ##   ## #     #  ####  #####  ##### #     #  ####  #    # ###### #  ####  
 #     # # # # # #     # #    # #    #   #   #       #    # ##   # #      # #    # 
 #     # #  #  # ######  #    # #    #   #   #       #    # # #  # #####  # #      
  #   #  #     # #       #    # #####    #   #       #    # #  # # #      # #  ### 
   # #   #     # #       #    # #   #    #   #     # #    # #   ## #      # #    # 
    #    #     # #        ####  #    #   #    #####   ####  #    # #      #  ####  
                                                                                   


function Enable-SDNExpressVMPort {
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $ComputerName,
        [String] $VMName,
        [String] $VMNetworkAdapterName,
        [int] $ProfileData = 1,
        [PSCredential] $Credential = $null        
    )
    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet

    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    invoke-command -ComputerName $ComputerName @CredentialParam -ScriptBlock {
        param(
            [String] $VMName,
            [String] $VMNetworkAdapterName,
            [int] $ProfileData
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
        $NcVendorId  = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"

        $vnic = Get-VMNetworkAdapter -VMName $VMName -Name $VMNetworkAdapterName

        $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vNic

        if ( $currentProfile -eq $null)
        {
            $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
        
            $portProfileDefaultSetting.SettingData.ProfileId = "{$([Guid]::Empty)}"
            $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
            $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
            $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
            $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
            $portProfileDefaultSetting.SettingData.VendorId = $NcVendorId 
            $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
            $portProfileDefaultSetting.SettingData.ProfileData = $ProfileData
            
            Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vNic | out-null
        }        
        else
        {
            $currentProfile.SettingData.ProfileId = "{$([Guid]::Empty)}"
            $currentProfile.SettingData.ProfileData = $ProfileData
            Set-VMSwitchExtensionPortFeature  -VMSwitchExtensionFeature $currentProfile  -VMNetworkAdapter $vNic | out-null
        }
    }    -ArgumentList $VMName, $VMNetworkAdapterName, $ProfileData | Parse-RemoteOutput
}


    #                  #     #                     
   # #   #####  #####  #     #  ####   ####  ##### 
  #   #  #    # #    # #     # #    # #        #   
 #     # #    # #    # ####### #    #  ####    #   
 ####### #    # #    # #     # #    #      #   #   
 #     # #    # #    # #     # #    # #    #   #   
 #     # #####  #####  #     #  ####   ####    #   
                                                   


Function Add-SDNExpressHost {
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Parameter(Mandatory=$true,ParameterSetName="iDNS")]
        [String] $RestName,
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Parameter(Mandatory=$true,ParameterSetName="iDNS")]
        [string] $ComputerName,
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [Parameter(Mandatory=$true,ParameterSetName="iDNS")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $NCHostCert,
        [Parameter(Mandatory=$true,ParameterSetName="iDNS")]
        [ValidateScript({
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "Invalid iDNSIPAddress specified."}
            return $true
        })]   
        [String] $iDNSIPAddress = "",
        [Parameter(Mandatory=$true,ParameterSetName="iDNS")]
        [String] $iDNSMacAddress = "",
        [Parameter(Mandatory=$false,ParameterSetName="Default")]
        [Parameter(Mandatory=$false,ParameterSetName="iDNS")]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "HostPASubnetPrefix must be in CIDR format with the syntax of <IP subnet>/<Subnet bits>."}
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "Invalid subnet portion of HostPASubnetPrefix parameter."}
            if (($split[1] -le 0) -or ($split[1] -gt 32)) { throw "Invalid subnet bits portion of HostPASubnetPrefix parameter."}
            return $true
        })]           
        [String] $HostPASubnetPrefix = "",
        [Parameter(Mandatory=$false,ParameterSetName="Default")]
        [Parameter(Mandatory=$false,ParameterSetName="iDNS")]
        [String] $VirtualSwitchName = "",
        [Parameter(Mandatory=$false,ParameterSetName="Default")]
        [Parameter(Mandatory=$false,ParameterSetName="iDNS")]
        [PSCredential] $Credential = $null,
        [Parameter(Mandatory=$false,ParameterSetName="Default")]
        [Parameter(Mandatory=$false,ParameterSetName="iDNS")]
        [String] $OperationID = ""
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $uri = "https://$RestName"    

    write-sdnexpresslog "Get the SLBM VIP"

    $SLBMConfig = $null
    try {
        $SLBMConfig = get-networkcontrollerloadbalancerconfiguration -connectionuri $uri @CredentialParam 
        $slbmvip = $slbmconfig.properties.loadbalancermanageripaddress
        write-sdnexpresslog "SLBM VIP is $slbmvip"
    } 
    catch 
    {
        $slbmvip = ""
        write-sdnexpresslog "SLB is not configured."
    }

    if ([String]::IsNullOrEmpty($VirtualSwitchName)) {
        try {
            $VirtualSwitchName = invoke-command -ComputerName $ComputerName @CredentialParam {
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

                $vmswitch = get-vmswitch
                if (($vmswitch -eq $null) -or ($vmswitch.count -eq 0)) {
                    throw "No virtual switch found on this host.  Please create the virtual switch before adding this host."
                }
                if ($vmswitch.count -gt 1) {
                    throw "More than one virtual switch exists on the specified host.  Use the VirtualSwitchName parameter to specify which switch you want configured for use with SDN."
                }

                write-output $vmswitch.Name
            } | parse-remoteoutput  
        } catch {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["INVALIDVSWITCH"].Code -LogMessage $_.Exception.Message  #No errormessage because SDN Express generates error
            throw $_.Exception
        }
    }

    invoke-command -ComputerName $ComputerName @CredentialParam {
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
    
        $feature = get-windowsfeature NetworkVirtualization
        if ($feature -ne $null) {
            write-verbose "Found network virtualization role, adding it."
            add-windowsfeature NetworkVirtualization -IncludeAllSubFeature -IncludeManagementTools -Restart | out-null
        }
    } | parse-remoteoutput

    $NodeFQDN = invoke-command -ComputerName $ComputerName @CredentialParam {
        param(
            [String] $RestName,
            [String] $iDNSIPAddress,
            [String] $iDNSMacAddress
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        write-verbose "Setting registry keys and firewall."
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

        $connections = "ssl:$($RestName):6640","pssl:6640"
        $peerCertCName = $RestName.ToUpper()
        $hostAgentCertCName = $NodeFQDN.ToUpper()

        Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000 | out-null
        
        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "Connections" -Value $connections -PropertyType "MultiString" -Force | out-null
        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "PeerCertificateCName" -Value $peerCertCName -PropertyType "String" -Force | out-null
        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "HostAgentCertificateCName" -Value $hostAgentCertCName -PropertyType "String" -Force | out-null

        if (![String]::IsNullOrEmpty($iDNSIPAddress) -and ![String]::IsNullOrEmpty($iDNSMacAddress)) {
            new-item -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet" -name "InfraServices" -force | out-null
            new-item -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices" -name "DnsProxyService" -force | out-null
            new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService" -Name "Port" -Value 53 -PropertyType "Dword" -Force | out-null
            new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService" -Name "ProxyPort" -Value 53 -PropertyType "Dword" -Force | out-null
            new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService" -Name "IP" -Value "169.254.169.254" -PropertyType "String" -Force | out-null
            new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService" -Name "MAC" -Value $iDNSMacAddress -PropertyType "String" -Force | out-null

            new-item -path "HKLM:\SYSTEM\CurrentControlSet\Services" -name "DnsProxy" -force | out-null
            new-item -path "HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy" -name "Parameters" -force | out-null
            new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\DNSProxy\Parameters" -Name "Forwarders" -Value $iDNSIPAddress -PropertyType "String" -Force | out-null
        
            Enable-NetFirewallRule -DisplayGroup 'DNS Proxy Service' -ErrorAction Ignore | out-null
        }

        
        $fwrule = Get-NetFirewallRule -Name "Firewall-REST" -ErrorAction SilentlyContinue
        if ($fwrule -eq $null) {
            New-NetFirewallRule -Name "Firewall-REST" -DisplayName "Network Controller Host Agent REST" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True | out-null
        }

        $fwrule = Get-NetFirewallRule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue
        if ($fwrule -eq $null) {
            New-NetFirewallRule -Name "Firewall-OVSDB" -DisplayName "Network Controller Host Agent OVSDB" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 6640 -Direction Inbound -Enabled True | out-null
        }

        $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue
        if ($fwrule -eq $null) {
            New-NetFirewallRule -Name "Firewall-HostAgent-TCP-IN" -DisplayName "Network Controller Host Agent (TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort Any -Direction Inbound -Enabled True | out-null
        }

        $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue
        if ($fwrule -eq $null) {
            New-NetFirewallRule -Name "Firewall-HostAgent-WCF-TCP-IN" -DisplayName "Network Controller Host Agent WCF(TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True | out-null
        }

        $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue
        if ($fwrule -eq $null) {
            New-NetFirewallRule -Name "Firewall-HostAgent-TLS-TCP-IN" -DisplayName "Network Controller Host Agent WCF over TLS (TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort 443 -Direction Inbound -Enabled True | out-null
        }

        write-verbose "Finished setting registry keys and firewall."
        write-output $NodeFQDN
    } -ArgumentList $RestName, $iDNSIPAddress, $iDNSMacAddress | parse-remoteoutput

    write-sdnexpresslog "Create and return host certificate."

    try {
        $CertData = invoke-command -ComputerName $ComputerName @CredentialParam {
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

            $cert = get-childitem "cert:\localmachine\my" | where-object {$_.Subject.ToUpper() -eq "CN=$NodeFQDN".ToUpper()}
            if ($Cert -eq $Null) {
                write-verbose "Creating new host certificate." 
                $Cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")
            } else {
                write-verbose "Found existing host certficate." 
                $HasServerEku = ($cert.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"}) -ne $null
                $HasClientEku = ($cert.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"}) -ne $null
            
                if (!$HasServerEku) {
                    throw "Host cert exists on $(hostname) but is missing the EnhancedKeyUsage for Server Authentication."
                }
                if (!$HasClientEku) {
                    throw "Host cert exists but $(hostname) is missing the EnhancedKeyUsage for Client Authentication."
                }
                write-verbose "Existing certificate meets criteria.  Exporting." 
            }

            write-verbose "Setting cert permissions."
            $targetCertPrivKey = $Cert.PrivateKey 
            $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object {$_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName} 
            $privKeyAcl = Get-Acl $privKeyCertFile
            $permission = "NT AUTHORITY\NETWORK SERVICE","Read","Allow" 
            $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
            $privKeyAcl.AddAccessRule($accessRule) | out-null 
            Set-Acl $privKeyCertFile.FullName $privKeyAcl | out-null

            write-verbose "Exporting certificate."
            $TempFile = New-TemporaryFile
            Remove-Item $TempFile.FullName -Force | out-null
            Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $cert | out-null

            $CertData = Get-Content $TempFile.FullName -Encoding Byte 
            Remove-Item $TempFile.FullName -Force | out-null

            write-output $CertData
        } | parse-remoteoutput
    } catch {
        write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["INVALIDKEYUSAGE"].Code -LogMessage $_.Exception.Message   #No errormessage because SDN Express generates error
        throw $_.Exception
    }

    #Hold on to CertData, we will need it later when adding the host to the NC.

    write-sdnexpresslog "Install NC host cert into Root store on host."
    
    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force | out-null
    Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $NCHostCert | out-null
    $NCHostCertData = Get-Content $TempFile.FullName -Encoding Byte
    Remove-Item $TempFile.FullName -Force | out-null

    invoke-command -ComputerName $ComputerName @CredentialParam {
        param(
            [byte[]] $CertData
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force

        write-verbose "Importing NC certificate into Root store."
        $CertData | set-content $TempFile.FullName -Encoding Byte
        import-certificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" | out-null
        Remove-Item $TempFile.FullName -Force
    } -ArgumentList (,$NCHostCertData) | parse-remoteoutput

    write-sdnexpresslog "Restart NC Host Agent and enable VFP."
    
    $VirtualSwitchId = invoke-command -ComputerName $ComputerName @CredentialParam {
        param(
            [String] $VirtualSwitchName
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $allnics = Get-VMNetworkAdapter -VMName * | ? {$_.SwitchName -eq $VirtualSwitchName}

        foreach ($nic in $allnics) {
            $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56" -VMNetworkAdapter $nic

            if ( $currentProfile -eq $null)
            {
                write-verbose "Adding Null port profile to $($nic.VMName) adapter $($nic.Name) so traffic is not blocked."

                #No port profile set yet, add a null profile so traffic isn't blocked
                $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56"
                $portProfileDefaultSetting.SettingData.ProfileId = "{$([Guid]::Empty)}"
                $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
                $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
                $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
                $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
                $portProfileDefaultSetting.SettingData.VendorId = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"
                $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
                $portProfileDefaultSetting.SettingData.ProfileData = 2 #Disable VFP on port so VMs continue to work as before
                
                Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $nic | out-null
            }        
            else
            {
                #Leave as-is
                write-verbose "$($nic.VMName) adapter $($nic.Name) already has port feature set, not changing."
            }
        }
        write-verbose "Configuring and restarting host agent."
        Stop-Service -Name NCHostAgent -Force | out-null
        Set-Service -Name NCHostAgent  -StartupType Automatic | out-null
        Start-Service -Name NCHostAgent  | out-null

        write-verbose "Enabling VFP."
        Disable-VmSwitchExtension -VMSwitchName $VirtualSwitchName -Name "Microsoft Windows Filtering Platform" | out-null
        Enable-VmSwitchExtension -VMSwitchName $VirtualSwitchName -Name "Microsoft Azure VFP Switch Extension" | out-null

        write-verbose "VFP is enabled."
        write-output (get-vmswitch -Name $VirtualSwitchName).Id
    } -ArgumentList $VirtualSwitchName | parse-remoteoutput

    if (![String]::IsNullOrEmpty($SLBMVIP)) {
        write-sdnexpresslog "Configure and start SLB Host Agent."

        invoke-command -computername $ComputerName @CredentialParam {
            param(
                [String] $SLBMVip,
                [String] $RestName
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

            $slbhpconfigtemplate = @"
<?xml version=`"1.0`" encoding=`"utf-8`"?>
<SlbHostPluginConfiguration xmlns:xsd=`"http://www.w3.org/2001/XMLSchema`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`">
    <SlbManager>
        <HomeSlbmVipEndpoints>
            <HomeSlbmVipEndpoint>$($SLBMVIP):8570</HomeSlbmVipEndpoint>
        </HomeSlbmVipEndpoints>
        <SlbmVipEndpoints>
            <SlbmVipEndpoint>$($SLBMVIP):8570</SlbmVipEndpoint>
        </SlbmVipEndpoints>
        <SlbManagerCertSubjectName>$RESTName</SlbManagerCertSubjectName>
    </SlbManager>
    <SlbHostPlugin>
        <SlbHostPluginCertSubjectName>$NodeFQDN</SlbHostPluginCertSubjectName>
    </SlbHostPlugin>
    <NetworkConfig>
        <MtuSize>0</MtuSize>
        <JumboFrameSize>4088</JumboFrameSize>
        <VfpFlowStatesLimit>500000</VfpFlowStatesLimit>
    </NetworkConfig>
</SlbHostPluginConfiguration>
"@
        
            set-content -value $slbhpconfigtemplate -path 'c:\windows\system32\slbhpconfig.xml' -encoding UTF8

            write-verbose "Configuring and starting SLB host agent."
            Stop-Service -Name SLBHostAgent -Force
            Set-Service -Name SLBHostAgent  -StartupType Automatic
            Start-Service -Name SLBHostAgent
            write-verbose "SLB host agent has been started." 
        } -ArgumentList $SLBMVIP, $RESTName  | parse-remoteoutput
    }
    else {
        write-sdnexpresslog "Skipping SLB host configuration."
    }

    write-sdnexpresslog "Prepare server object."

    $nchostcertObject = get-networkcontrollerCredential -Connectionuri $URI -ResourceId "NCHostCert" @CredentialParam -passinnerexception
    $nchostuserObject = get-networkcontrollerCredential -Connectionuri $URI -ResourceId "NCHostUser" @CredentialParam -passinnerexception

    if ([string]::IsNullOrEmpty($HostPASubnetPrefix)) {
        $PALogicalSubnets = @()
    } else {
        $PALogicalNetwork = get-networkcontrollerLogicalNetwork -Connectionuri $URI -ResourceId "HNVPA" @CredentialParam -passinnerexception
        $PALogicalSubnets = @($PALogicalNetwork.Properties.Subnets | where-object {$_.properties.AddressPrefix -eq $HostPASubnetPrefix})
    }

    $ServerProperties = new-object Microsoft.Windows.NetworkController.ServerProperties

    $ServerProperties.Connections = @()
    $ServerProperties.Connections += new-object Microsoft.Windows.NetworkController.Connection
    $ServerProperties.Connections[0].Credential = $nchostcertObject
    $ServerProperties.Connections[0].CredentialType = $nchostcertObject.properties.Type
    $ServerProperties.Connections[0].ManagementAddresses = @($NodeFQDN)

    $ServerProperties.Connections += new-object Microsoft.Windows.NetworkController.Connection
    $ServerProperties.Connections[1].Credential = $nchostuserObject
    $ServerProperties.Connections[1].CredentialType = $nchostuserObject.properties.Type
    $ServerProperties.Connections[1].ManagementAddresses = @($NodeFQDN)

    $ServerProperties.NetworkInterfaces = @()
    $serverProperties.NetworkInterfaces += new-object Microsoft.Windows.NetworkController.NwInterface
    $serverProperties.NetworkInterfaces[0].ResourceId = $VirtualSwitchName
    $serverProperties.NetworkInterfaces[0].Properties = new-object Microsoft.Windows.NetworkController.NwInterfaceProperties
    $ServerProperties.NetworkInterfaces[0].Properties.LogicalSubnets = $PALogicalSubnets

    write-sdnexpresslog "Certdata contains $($certdata.count) bytes."

    $ServerProperties.Certificate = [System.Convert]::ToBase64String($CertData)

    write-sdnexpresslog "New server object."
    $Server = New-NetworkControllerServer -ConnectionURI $uri -ResourceId $VirtualSwitchId -Properties $ServerProperties @CredentialParam -Force  -passinnerexception

    write-sdnexpresslog "Configure DNS PRoxy."

    invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $InstanceId
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "HostId" -Value $InstanceId -PropertyType "String" -Force | out-null

        $dnsproxy = get-service DNSProxy -ErrorAction Ignore
        if ($dnsproxy -ne $null) {
            write-verbose "Stopping DNS proxy service (2016 only)." 
            $dnsproxy | Stop-Service -Force
        }

        write-verbose "Restarting host agents." 
        $slbstatus = get-service slbhostagent
        if ($slbstatus.status -eq "Running") {
            Stop-Service SlbHostAgent -Force                
        }
        Stop-Service NcHostAgent -Force

        Start-Service NcHostAgent
        if ($slbstatus.status -eq "Running") {
            Start-Service SlbHostAgent
        }

        if ($dnsproxy -ne $null) {
            write-verbose "Starting DNS proxy service (2016 only)." 
            Set-Service -Name "DnsProxy" -StartupType Automatic
            $dnsproxy | Start-Service
        }
        write-verbose "DNS proxy config complete." 

    } -ArgumentList $Server.InstanceId | parse-remoteoutput

    write-sdnexpresslog "New-SDNExpressHost Exit"
}



 #     #                              
 #     # ##### # #      # ##### #   # 
 #     #   #   # #      #   #    # #  
 #     #   #   # #      #   #     #   
 #     #   #   # #      #   #     #   
 #     #   #   # #      #   #     #   
  #####    #   # ###### #   #     #   
                                      


function Write-SDNExpressLog
{
    Param([String] $Message)

    $FormattedDate = date -Format "yyyyMMdd-HH:mm:ss"
    $FormattedMessage = "[$FormattedDate] $Message"
    write-verbose $FormattedMessage

    $formattedMessage | out-file ".\$logname" -Append
}


function Write-SDNExpressLogParameter
{
    Param(
        [string] $paramname,
        [Object] $value

    )
    if ($null -eq $value) {
        Write-SDNExpressLog "  -$($paramname): null"
    } elseif ($value.gettype().Name -eq "Object[]") {
        for ($i = 0; $i -lt $value.count; $i++ ) {
            Write-SDNExpressLogParameter "$($paramname)[$i]" $value[$i]
        }
    } elseif ($value.getType().Name -eq "Hashtable") {
        foreach ($key in $value.keys) {
            Write-SDNExpressLogParameter "$paramname.$key" $value[$key]
        }
    } else {
        Write-SDNExpressLog "  -$($paramname): $($value)"
    }
}
function Write-SDNExpressLogFunction 
{
    Param(
        [String] $FunctionName,
        [Object] $BoundParameters,
        [String] $UnboundArguments,
        [object] $ParamSet
    )

    Write-SDNExpressLog "Enter Function: $FunctionName"
    foreach ($param in $BoundParameters.keys) {
        if ($param.ToUpper().Contains("PASSWORD") -or $param.ToUpper().Contains("KEY")) {
            Write-SDNExpressLog "  -$($param): ******"
        } else {
            $value = $BoundParameters[$param]
            Write-SDNExpressLogParameter $param $value
        }
    }
    Write-SDNExpressLog "Unbound Arguments: $UnboundArguments"
    if ($null -ne $pscmdlet) {
        write-SDNExpressLog "ParameterSet: $($paramset.ParameterSetName)"
    }
}

function write-LogProgress { 
    param([String] $OperationId, [String] $Source, [String] $Context, [Int] $Percent) 
    $message = "$OperationId;$Source;$Context;$Percent"
    Microsoft.PowerShell.Management\Write-EventLog -LogName "Microsoft-ServerManagementExperience" -Source "SmeHciScripts-SDN" -EventId 0 -Category 0 -EntryType Information -Message $message -ErrorAction SilentlyContinue 
}
function Write-LogError {
    param(
        [String] $OperationId, 
        [String] $Source, 
        [String] $ErrorCode, 
        [String] $LogMessage, 
        [String] $ErrorMessage = ""
    )
        $message = "$OperationId;$Source;$ErrorCode;$LogMessage;$ErrorMessage"
        write-sdnexpresslog "LogError: $message"
        Microsoft.PowerShell.Management\Write-EventLog -LogName "Microsoft-ServerManagementExperience" -Source "SmeHciScripts-SDN" -EventId 0 -Category 0 -EntryType Error -Message $message -ErrorAction SilentlyContinue
}

function Parse-RemoteOutput
{
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        $item
    )
    begin {
        write-sdnexpresslog "Begin Invoke-Command output:"
        $items = @()
        $ComputerStates = @{}
    }
    Process {
        switch ([Convert]::ToInt32($ComputerStates[$item.pscomputername])) {
            -1 { #Verbose output state
                write-sdnexpresslog "[$($item.pscomputername)] $item"
                $ComputerStates[$item.pscomputername] = 0
            }
            0 { # No state
                if ($item -eq "[V]") {
                    $ComputerStates[$item.pscomputername] = -1
                } else {
                    $ComputerStates[$item.pscomputername] = [Convert]::ToInt32($item)
                }
            } 
            default { #count of output objects to add
                $items += $item
                $ComputerStates[$item.pscomputername] = $ComputerStates[$item.pscomputername] - 1
            }
        }
    }
    end {
        write-sdnexpresslog "Finished Invoke-Command output."
        return $items
    }
}



function Get-IPAddressInSubnet
{
    param([string] $subnet, [uInt64] $offset)
    write-sdnexpresslog "$($MyInvocation.InvocationName)"
    write-sdnexpresslog "   -Subnet: $subnet"
    write-sdnexpresslog "   -Offset: $Offset"

    $prefix = ($subnet.split("/"))[0]

    $ip = [ipaddress] $prefix
 
    $bytes = $ip.getaddressbytes()
    $i = $bytes.count - 1
    while ($offset -gt 0) {
        $rem = $offset % 256
        $bytes[$i] += $rem
        $offset = $offset / 0xFF
        $i--
    }

    $ip2 = [IPAddress] $bytes 

    $return = $ip2.IPAddressToString
    write-sdnexpresslog "$($MyInvocation.InvocationName) Returns $return"
    $return
}


function Get-IPLastAddressInSubnet
{
    param([string] $subnet)
    write-sdnexpresslog "$($MyInvocation.InvocationName)"
    write-sdnexpresslog "   -Subnet: $subnet"

    $prefix = ($subnet.split("/"))[0]
    $bits = ($subnet.split("/"))[1]

    $ip = [IPAddress] $prefix
    if ($ip.AddressFamily -eq "InterNetworkV6") {
        $totalbits = 128
    } else {
        $totalbits = 32
    }

    $bytes = $ip.getaddressbytes()
    $rightbits = $totalbits - $bits
    
    write-sdnexpresslog "rightbits: $rightbits"
    $i = $bytes.count - 1
    while ($rightbits -gt 0) {
        if ($rightbits -gt 7) {
            write-sdnexpresslog "full byte"
            $bytes[$i] = $bytes[$i] -bor 0xFF
            $rightbits -= 8
        } else {
            write-sdnexpresslog "Final byte: $($bytes[$i])"
            $bytes[$i] = $bytes[$i] -bor (0xff -shr (8-$rightbits))
            write-sdnexpresslog "Byte: $($bytes[$i])"
            $rightbits = 0
        }
        $i--
    }

    $ip2 = [IPAddress] $bytes 

    $return = $ip2.IPAddressToString
    write-sdnexpresslog "$($MyInvocation.InvocationName) Returns $return"
    $return
}



function WaitForComputerToBeReady
{
    param(
        [string[]] $ComputerName,
        [Switch]$CheckPendingReboot,
        [PSCredential] $Credential = $null,
        [Int64] $LastBootUpTime = 0,
        [Int] $Timeout = 1200  # 20 minutes
    )

    write-SDNExpressLog "Entering WaitForComputerToBeReady."

    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $endtime = (get-date).ticks + ($timeout * 10000000)

    foreach ($computer in $computername) {        
        write-sdnexpresslog "Waiting up to $timeout seconds for $Computer to become active."
        
        $continue = $true
        while ($continue) {
            try {
                $ps = $null
                $result = ""
                
                klist purge | out-null  #clear kerberos ticket cache 
                Clear-DnsClientCache    #clear DNS cache in case IP address is stale
                
                write-sdnexpresslog "Attempting to contact $Computer."
                $ps = new-pssession -computername $Computer @CredentialParam -erroraction ignore
                if ($ps -ne $null) {
                    try {
                        if ($CheckPendingReboot.IsPresent) {                        
                            $result = Invoke-Command -Session $ps -ScriptBlock { 
                                if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                                    "Reboot pending"
                                } 
                                else {
                                    hostname 
                                }
                            }
                        }
                        elseif ($LastBootUpTime -gt 0) {
                            $result = Invoke-Command -Session $ps -ScriptBlock { (gcim Win32_OperatingSystem).LastBootUpTime.ticks }
                            write-sdnexpresslog "LastBootUpTime is $LastBootUpTime, Current BootUpTime is $result"
                            if ($result -ne $LastBootUpTime) {
                                $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
                            } else {
                                "Reboot pending"
                            }
                        }
                        else {
                            $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
                        }
                    } catch { 
                        write-sdnexpresslog "Ignoring exception from Invoke-Command, machine may not be rebooting."
                    }
                    remove-pssession $ps
                }
                if ($result -eq $Computer.split(".")[0]) {
                    $continue = $false
                    break
                }
                if ($result -eq "Reboot pending") {
                    if ($CheckPendingReboot.IsPresent) {
                        write-sdnexpresslog "Reboot pending on $Computer according to registry.  Waiting for restart."
                    } else {
                        write-sdnexpresslog "Reboot pending on $Computer according to last boot up time.  Waiting for restart."
                    }
                }
            }
            catch 
            {
                write-sdnexpresslog "Ignoring exception while waiting for computer to be ready, machine may not be rebooting."
            }

            if ((get-date).ticks -gt $endtime) {
                $message = "$Computer is not ready after $timeout second timeout."
                write-sdnexpresslog $message
                throw $message
            }

            write-sdnexpresslog "$Computer is not ready, sleeping for 10 seconds."
            sleep 10
        }
    write-sdnexpresslog "$Computer IS ACTIVE.  Continuing with deployment."
    }
}



    #                  #     #               
   # #   #####  #####  ##   ## #    # #    # 
  #   #  #    # #    # # # # # #    #  #  #  
 #     # #    # #    # #  #  # #    #   ##   
 ####### #    # #    # #     # #    #   ##   
 #     # #    # #    # #     # #    #  #  #  
 #     # #####  #####  #     #  ####  #    # 
                                                                                      
                                         

Function Add-SDNExpressMux {
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [string] $ComputerName,
        [Object] $NCHostCert,
        [String] $PAMacAddress,
        [String] $LocalPeerIP,
        [String] $MuxASN,
        [Object] $Routers,
        [String] $PAGateway = "",
        [PSCredential] $Credential = $null
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet
 
    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $uri = "https://$RestName"    

    $PASubnets = @()
    $LogicalNetworkObject = get-NetworkControllerLogicalNetwork -ConnectionURI $uri -ResourceID "HNVPA" @CredentialParam
    $PASubnets += $LogicalNetworkObject.properties.subnets.properties.AddressPrefix
    foreach ($Router in $Routers) {
        $PASubnets += "$($Router.RouterIPAddress)/32"
    }

    Write-SDNExpressLog "PA Subnets to add to PA adapter in mux: $PASubnets"
    
    invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $PAMacAddress,
            [String] $PAGateway,
            [String[]] $PASubnets
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $PAMacAddress = [regex]::matches($PAMacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
        $nic = Get-NetAdapter -ErrorAction Ignore | where-object {$_.MacAddress -eq $PAMacAddress}

        if ($nic -eq $null)
        {
            throw "No adapter with the HNVPA MAC $PAMacAddress was found"
        }

        if (![String]::IsNullOrEmpty($PAGateway)) {
            foreach ($PASubnet in $PASubnets) {
                remove-netroute -DestinationPrefix $PASubnet -InterfaceIndex $nic.ifIndex -Confirm:$false -erroraction ignore | out-null
                new-netroute -DestinationPrefix $PASubnet -InterfaceIndex $nic.ifIndex -NextHop $PAGateway  -erroraction ignore | out-null
            }
        }

        $nicProperty = Get-NetAdapterAdvancedProperty -Name $nic.Name -AllProperties -RegistryKeyword *EncapOverhead -ErrorAction Ignore
        if($nicProperty -eq $null) 
        {
            New-NetAdapterAdvancedProperty -Name $nic.Name -RegistryKeyword *EncapOverhead -RegistryValue 160 | out-null
        }
        else
        {
            Set-NetAdapterAdvancedProperty -Name $nic.Name -AllProperties -RegistryKeyword *EncapOverhead -RegistryValue 160
        }

        add-windowsfeature SoftwareLoadBalancer -Restart | out-null
    } -argumentlist $PAMacAddress, $PAGateway, $PASubnets | parse-remoteoutput
    
    WaitforComputerToBeReady -ComputerName $ComputerName -CheckPendingReboot @CredentialParam

    $MuxFQDN = invoke-command -computername $ComputerName @CredentialParam {
            Return (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    }

    #wait for comptuer to restart.

    $CertData = invoke-command -computername $ComputerName @CredentialParam {
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        write-verbose "Creating self signed certificate...";

        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

        $cert = get-childitem "cert:\localmachine\my" | where-object {$_.Subject.ToUpper() -eq "CN=$NodeFQDN".ToUpper()}
        if ($cert -eq $null) {
            $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")
        }

        $targetCertPrivKey = $Cert.PrivateKey 
        $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object {$_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName} 
        $privKeyAcl = Get-Acl $privKeyCertFile
        $permission = "NT AUTHORITY\NETWORK SERVICE","Read","Allow" 
        $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
        $privKeyAcl.AddAccessRule($accessRule) 
        Set-Acl $privKeyCertFile.FullName $privKeyAcl

        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force | out-null
        Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $cert | out-null

        $CertData = Get-Content $TempFile.FullName -Encoding Byte
        Remove-Item $TempFile.FullName -Force | out-null

        write-output $CertData
    } | Parse-RemoteOutput

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force | out-null
    Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $NCHostCert | out-null
    $NCHostCertData = Get-Content $TempFile.FullName -Encoding Byte
    Remove-Item $TempFile.FullName -Force | out-null

    invoke-command -ComputerName $ComputerName @CredentialParam {
        param(
            [byte[]] $CertData
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force

        $CertData | set-content $TempFile.FullName -Encoding Byte
        import-certificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" | out-null
        Remove-Item $TempFile.FullName -Force
    } -ArgumentList (,$NCHostCertData) | parse-remoteoutput
    

    $vmguid = invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $RestName
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
        $cert = get-childitem "cert:\localmachine\my" | where-object {$_.Subject.ToUpper() -eq "CN=$NodeFQDN".ToUpper()}
        
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Force -Name SlbmThumb -PropertyType String -Value $RestName | out-null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Force -Name MuxCert -PropertyType String -Value $NodeFQDN | out-null

        Get-ChildItem -Path WSMan:\localhost\Listener | where-object {$_.Keys.Contains("Transport=HTTPS") } | Remove-Item -Recurse -Force | out-null
        New-Item -Path WSMan:\localhost\Listener -Address * -HostName $NodeFQDN -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force | out-null

        Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule | out-null

        start-service slbmux | out-null

        write-output (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid
    } -ArgumentList $RestName | parse-remoteoutput

    write-sdnexpresslog "Add VirtualServerToNC";
    $nchostcertObject = get-networkcontrollerCredential -Connectionuri $URI -ResourceId "NCHostCert" @CredentialParam
    $nchostuserObject = get-networkcontrollerCredential -Connectionuri $URI -ResourceId "NCHostUser" @CredentialParam
    
    $VirtualServerProperties = new-object Microsoft.Windows.NetworkController.VirtualServerProperties
    $VirtualServerProperties.Connections = @()
    $VirtualServerProperties.Connections += new-object Microsoft.Windows.NetworkController.Connection
    $VirtualServerProperties.Connections[0].Credential = $nchostcertObject
    $VirtualServerProperties.Connections[0].CredentialType = $nchostcertObject.properties.Type
    $VirtualServerProperties.Connections[0].ManagementAddresses = @($MuxFQDN)
    $VirtualServerProperties.Connections += new-object Microsoft.Windows.NetworkController.Connection
    $VirtualServerProperties.Connections[1].Credential = $nchostuserObject
    $VirtualServerProperties.Connections[1].CredentialType = $nchostuserObject.properties.Type
    $VirtualServerProperties.Connections[1].ManagementAddresses = @($MuxFQDN)
    write-sdnexpresslog "Certdata contains $($certdata.count) bytes."
    $VirtualServerProperties.Certificate = [System.Convert]::ToBase64String($CertData)
    $VirtualServerProperties.vmguid = $vmGuid

    $VirtualServer = new-networkcontrollervirtualserver -connectionuri $uri @CredentialParam -MarkServerReadOnly $false -ResourceId $MuxFQDN -Properties $VirtualServerProperties -force  -passinnerexception
    
    $MuxProperties = new-object Microsoft.Windows.NetworkController.LoadBalancerMuxProperties
    $muxProperties.RouterConfiguration = new-object Microsoft.Windows.NetworkController.RouterConfiguration
    $muxProperties.RouterConfiguration.LocalASN = $MuxASN
    $muxProperties.RouterConfiguration.PeerRouterConfigurations = @()
    foreach ($router in $routers) {
        $peerRouter = new-object Microsoft.Windows.NetworkController.PeerRouterConfiguration
        $peerRouter.LocalIPAddress = $LocalPeerIP
        $peerRouter.PeerASN = $Router.RouterASN
        $peerRouter.RouterIPAddress = $Router.RouterIPAddress
        $peerRouter.RouterName = $Router.RouterIPAddress.Replace(".", "_")
        $muxProperties.RouterConfiguration.PeerRouterConfigurations += $PeerRouter
    }
    $muxProperties.VirtualServer = $VirtualServer
    
    $Mux = new-networkcontrollerloadbalancermux -connectionuri $uri @CredentialParam -ResourceId $MuxFQDN -Properties $MuxProperties -force -passinnerexception
    write-sdnexpresslog "New-SDNExpressMux Exit"
}


    #                   #####                                          ######                       
   # #   #####  #####  #     #   ##   ##### ###### #    #   ##   #   # #     #  ####   ####  #      
  #   #  #    # #    # #        #  #    #   #      #    #  #  #   # #  #     # #    # #    # #      
 #     # #    # #    # #  #### #    #   #   #####  #    # #    #   #   ######  #    # #    # #      
 ####### #    # #    # #     # ######   #   #      # ## # ######   #   #       #    # #    # #      
 #     # #    # #    # #     # #    #   #   #      ##  ## #    #   #   #       #    # #    # #      
 #     # #####  #####   #####  #    #   #   ###### #    # #    #   #   #        ####   ####  ###### 
                                                                                                    
 

function New-SDNExpressGatewayPool
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [PSCredential] $Credential,
        [String] $PoolName,
        [Parameter(Mandatory=$true,ParameterSetName="TypeAll")]
        [Switch] $IsTypeAll,
        [Parameter(Mandatory=$true,ParameterSetName="TypeIPSec")]
        [Switch] $IsTypeIPSec,
        [Parameter(Mandatory=$true,ParameterSetName="TypeGre")]
        [Switch] $IsTypeGre,
        [Parameter(Mandatory=$true,ParameterSetName="TypeForwarding")]
        [Switch] $IsTypeForwarding,
        [Parameter(Mandatory=$false,ParameterSetName="TypeAll")]
        [Parameter(Mandatory=$false,ParameterSetName="TypeGre")]
        [String] $PublicIPAddress,  
        [Parameter(Mandatory=$false,ParameterSetName="TypeAll")]
        [Parameter(Mandatory=$true,ParameterSetName="TypeGre")]
        [String] $GreSubnetAddressPrefix,
        [Parameter(Mandatory=$false,ParameterSetName="TypeGre")]
        [String] $GrePoolStart = (Get-IPAddressInSubnet -subnet $GreSubnetAddressPrefix -offset 1),
        [Parameter(Mandatory=$false,ParameterSetName="TypeGre")]
        [String] $GrePoolEnd = (Get-IPLastAddressInSubnet -subnet $GreSubnetAddressPrefix),
        [String] $Capacity,
        [Int] $RedundantCount = -1
        )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet
    
    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $uri = "https://$RestName"

    $gresubnet = $null
    if (-1 -eq $Redundantcount) {
        write-sdnexpresslog "RedundantCount not set, defaulting to 1." 
        $RedundantCount = 1
    }

    if ($IsTypeAll -or $IsTypeIPSec) {
        $PublicIPProperties = new-object Microsoft.Windows.NetworkController.PublicIPAddressProperties
        $publicIPProperties.IdleTimeoutInMinutes = 4

        if ([String]::IsNullOrEmpty($PublicIPAddress)) {
            $PublicIPProperties.PublicIPAllocationMethod = "Dynamic"
        } else {
            $PublicIPProperties.PublicIPAllocationMethod = "Static"
            $PublicIPProperites.IPAddress = $PublicIPAddress
        }
        $PublicIPAddressObject = New-NetworkControllerPublicIPAddress -connectionURI $uri -ResourceId $PoolName -Properties $PublicIPProperties -Force @CredentialParam -passinnerexception
    }

    if ($IsTypeGre -or $IsTypeAll) {
        $logicalNetwork = try { get-networkcontrollerlogicalnetwork -ResourceId "GreVIP" -connectionuri $uri @CredentialParam } catch {}
    
        if ($logicalNetwork -eq $null) {
            $LogicalNetworkProperties = new-object Microsoft.Windows.NetworkController.LogicalNetworkProperties
            $LogicalNetworkProperties.NetworkVirtualizationEnabled = $false
            $LogicalNetwork = New-NetworkControllerLogicalNetwork -ConnectionURI $uri -ResourceID "GreVIP" -properties $LogicalNetworkProperties @CredentialParam -Force -passinnerexception
        }

        foreach ($subnet in $logicalnetwork.properties.subnets) {
            if ($Subnet.properties.AddressPrefix -eq $GreSubnetAddressPrefix) {
                $GreSubnet = $subnet
            }
        }

        if ($GreSubnet -eq $Null) {
            $LogicalSubnetProperties = new-object Microsoft.Windows.NetworkController.LogicalSubnetProperties
            $LogicalSubnetProperties.AddressPrefix = $GreSubnetAddressPrefix
            $logicalSubnetProperties.DefaultGateways = @(get-ipaddressinsubnet -subnet $GreSubnetAddressPrefix)
        
            $greSubnet = New-NetworkControllerLogicalSubnet -ConnectionURI $uri -LogicalNetworkId "GreVIP" -ResourceId $GreSubnetAddressPrefix.Replace("/", "_") -properties $LogicalSubnetProperties @CredentialParam -Force -passinnerexception
        
            $IPpoolProperties = new-object Microsoft.Windows.NetworkController.IPPoolproperties
            $ippoolproperties.startipaddress = $GrePoolStart
            $ippoolproperties.endipaddress = $GrePoolEnd
        
            $IPPoolObject = New-networkcontrollerIPPool -ConnectionURI $uri -NetworkId "GreVIP" -SubnetId $GreSubnetAddressPrefix.Replace("/", "_") -ResourceID $GreSubnetAddressPrefix.Replace("/", "_") -Properties $IPPoolProperties @CredentialParam -force -passinnerexception
        }
    }

    $GatewayPoolProperties = new-object Microsoft.Windows.NetworkController.GatewayPoolProperties
    $GatewayPoolProperties.RedundantGatewayCount = "$RedundantCount"
    $GatewayPoolProperties.GatewayCapacityKiloBitsPerSecond = $Capacity

    if ($IsTypeAll) {
        $GatewayPoolProperties.Type = "All"

        $GatewayPoolProperties.IPConfiguration = new-object Microsoft.Windows.NetworkController.IPConfig
        $GatewayPoolProperties.IPConfiguration.PublicIPAddresses = @()
        $GatewayPoolProperties.IPConfiguration.PublicIPAddresses += $PublicIPAddressObject

        $GatewayPoolProperties.IpConfiguration.GreVipSubnets = @()
        $GatewayPoolProperties.IPConfiguration.GreVipSubnets += $GreSubnet
    } elseif ($IsTypeIPSec) {
        $GatewayPoolProperties.Type = "S2sIpSec"

        $GatewayPoolProperties.IPConfiguration = new-object Microsoft.Windows.NetworkController.IPConfig
        $GatewayPoolProperties.IPConfiguration.PublicIPAddresses = @()
        $GatewayPoolProperties.IPConfiguration.PublicIPAddresses += $PublicIPAddressObject
    } elseif ($IsTypeGre) {
        $GatewayPoolProperties.Type = "S2sGre"

        $GatewayPoolProperties.IPConfiguration = new-object Microsoft.Windows.NetworkController.IPConfig
        $GatewayPoolProperties.IpConfiguration.GreVipSubnets = @()
        $GatewayPoolProperties.IPConfiguration.GreVipSubnets += $GreSubnet
    } elseif ($IsForwarding) {
        $GatewayPoolProperties.Type = "Forwarding"
    }

    $GWPoolObject = new-networkcontrollergatewaypool -connectionURI $URI -ResourceId $PoolName -Properties $GatewayPoolProperties -Force @CredentialParam -passinnerexception
    write-sdnexpresslog "New-SDNExpressGatewayPool Exit"
}



    #                   #####                                          
   # #   #####  #####  #     #   ##   ##### ###### #    #   ##   #   # 
  #   #  #    # #    # #        #  #    #   #      #    #  #  #   # #  
 #     # #    # #    # #  #### #    #   #   #####  #    # #    #   #   
 ####### #    # #    # #     # ######   #   #      # ## # ######   #   
 #     # #    # #    # #     # #    #   #   #      ##  ## #    #   #   
 #     # #####  #####   #####  #    #   #   ###### #    # #    #   #   
                                                                       


Function New-SDNExpressGateway {
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [string] $ComputerName,
        [String] $HostName,
        [Object] $NCHostCert,
        [String] $PoolName,
        [String] $FrontEndLogicalNetworkName,
        [String] $FrontEndAddressPrefix,
        [String] $FrontEndIp,
        [String] $FrontEndMac,
        [String] $BackEndMac,
        [Parameter(Mandatory=$true,ParameterSetName="SinglePeer")]        
        [String] $RouterASN = $null,
        [Parameter(Mandatory=$true,ParameterSetName="SinglePeer")]        
        [String] $RouterIP = $null,
        [String] $LocalASN = $null,
        [Parameter(Mandatory=$true,ParameterSetName="MultiPeer")]        
        [Object] $Routers,
        [PSCredential] $Credential = $null
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet


    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $uri = "https://$RestName"    

    $RebootRequired = invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $FrontEndMac,
            [String] $BackEndMac            
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $feature = get-windowsfeature -Name RemoteAccess

        if (!$feature.Installed) {
            write-verbose "Adding RemoteAccess feature."
            Add-WindowsFeature -Name RemoteAccess -IncludeAllSubFeature -IncludeManagementTools | out-null
            return $true
        } else {
            return $false
        }

    } | Parse-RemoteOutput

    if ($rebootrequired) {
        write-sdnexpresslog "Restarting $computername, waiting up to 10 minutes for powershell remoting to return."
        restart-computer -computername $computername @CredentialParam -force -wait -for powershell -timeout 600 -Protocol WSMan -verbose
        write-sdnexpresslog "Restart complete, installing RemoteAccess multitenancy and GatewayService."
    }

    invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $FrontEndMac,
            [String] $BackEndMac            
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        # Get-NetAdapter returns MacAddresses with hyphens '-'
        $FrontEndMac = [regex]::matches($FrontEndMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
        $BackEndMac = [regex]::matches($BackEndMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
    
        Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000 | out-null

        write-verbose "Renaming Network Adapters"

        $adapters = Get-NetAdapter

        $adapter = $adapters | where-object {$_.MacAddress -eq $BackEndMac}
        $adapter | Rename-NetAdapter -NewName "Internal" -Confirm:$false -ErrorAction Ignore | out-null

        $adapter = $adapters | where-object {$_.MacAddress -eq $FrontEndMac}
        $adapter | Rename-NetAdapter -NewName "External" -Confirm:$false -ErrorAction Ignore | out-null

        $RemoteAccess = get-RemoteAccess
        if ($RemoteAccess -eq $null -or $RemoteAccess.VpnMultiTenancyStatus -ne "Installed")
        {
            write-verbose "Enabling remote access multi-tenancy"
            Install-RemoteAccess -MultiTenancy | out-null
        } else {
            write-verbose "Remote Access multi-tenancy already enabled."
        }

        Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule

        $GatewayService = get-service GatewayService -erroraction Ignore
        if ($gatewayservice -ne $null) {
            write-verbose "Enabling gateway service."
            Set-Service -Name GatewayService -StartupType Automatic | out-null
            Start-Service -Name GatewayService  | out-null
        }
    } -ArgumentList $FrontEndMac, $BackEndMac | Parse-RemoteOutput

    write-sdnexpresslog "Configuring certificates."

    $GatewayFQDN = invoke-command -computername $ComputerName @CredentialParam {
        Return (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    }

    $vmGuid = invoke-command -computername $ComputerName @CredentialParam {
        return (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid
    }

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force | out-null
    Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $NCHostCert | out-null
    $NCHostCertData = Get-Content $TempFile.FullName -Encoding Byte
    Remove-Item $TempFile.FullName -Force | out-null

    invoke-command -ComputerName $ComputerName @CredentialParam {
        param(
            [byte[]] $CertData
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force

        $CertData | set-content $TempFile.FullName -Encoding Byte
        import-certificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" | out-null
        Remove-Item $TempFile.FullName -Force
    } -ArgumentList (,$NCHostCertData) | Parse-RemoteOutput
    
    write-sdnexpresslog "Adding Network Interfaces to network controller."

    # Get-VMNetworkAdapter returns MacAddresses without hyphens '-'.  NetworkInterface prefers without hyphens also.

    $FrontEndMac = [regex]::matches($FrontEndMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join ""
    $BackEndMac = [regex]::matches($BackEndMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join ""
    
    $LogicalSubnet = get-networkcontrollerlogicalSubnet -LogicalNetworkId $FrontEndLogicalNetworkName -ConnectionURI $uri @CredentialParam
    $LogicalSubnet = $LogicalSubnet | where-object {$_.properties.AddressPrefix -eq $FrontEndAddressPrefix }

    $NicProperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
    $nicproperties.PrivateMacAddress = $BackEndMac
    $NicProperties.privateMacAllocationMethod = "Static"
    $BackEndNic = new-networkcontrollernetworkinterface -connectionuri $uri @CredentialParam -ResourceId "$($GatewayFQDN)_BackEnd" -Properties $NicProperties -force -passinnerexception

    $NicProperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
    $nicproperties.PrivateMacAddress = $FrontEndMac
    $NicProperties.privateMacAllocationMethod = "Static"
    $NicProperties.IPConfigurations = @()
    $NicProperties.IPConfigurations += new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
    $NicProperties.IPConfigurations[0].ResourceId = "FrontEnd" 
    $NicProperties.IPConfigurations[0].Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
    $NicProperties.IPConfigurations[0].Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
    $nicProperties.IpConfigurations[0].Properties.Subnet.ResourceRef = $LogicalSubnet.ResourceRef
    $NicProperties.IPConfigurations[0].Properties.PrivateIPAddress = $FrontEndIp
    $NicProperties.IPConfigurations[0].Properties.PrivateIPAllocationMethod = "Static"
    $FrontEndNic = new-networkcontrollernetworkinterface -connectionuri $uri @CredentialParam -ResourceId "$($GatewayFQDN)_FrontEnd" -Properties $NicProperties -force -passinnerexception

    write-sdnexpresslog "Setting port data on gateway VM NICs."

    $SetPortProfileBlock = {
        param(
            [String] $VMName,
            [String] $MacAddress,
            [String] $InstanceId
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
        $NcVendorId  = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"

        $vnic = Get-VMNetworkAdapter -VMName $VMName | where-object {$_.MacAddress -eq $MacAddress}

        $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vNic

        if ( $currentProfile -eq $null)
        {
            $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
            $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
            $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
            $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
            $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
            $portProfileDefaultSetting.SettingData.VendorId = $NcVendorId 
            $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"

            $portProfileDefaultSetting.SettingData.ProfileId = "{$InstanceId}"
            $portProfileDefaultSetting.SettingData.ProfileData = 1
            
            Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vNic | out-null
        }        
        else
        {
            $currentProfile.SettingData.ProfileId = "{$InstanceId}"
            $currentProfile.SettingData.ProfileData = 1
            Set-VMSwitchExtensionPortFeature  -VMSwitchExtensionFeature $currentProfile  -VMNetworkAdapter $vNic | out-null
        }
    }

    invoke-command -ComputerName $HostName @CredentialParam -ScriptBlock $SetPortProfileBlock -ArgumentList $ComputerName, $BackEndMac, $BackEndNic.InstanceId | Parse-RemoteOutput
    invoke-command -ComputerName $HostName @CredentialParam -ScriptBlock $SetPortProfileBlock -ArgumentList $ComputerName, $FrontEndMac, $FrontEndNic.InstanceId | Parse-RemoteOutput

    write-sdnexpresslog "Adding Virtual Server to Network Controller."

    $nchostUserObject = get-networkcontrollerCredential -Connectionuri $URI -ResourceId "NCHostUser" @CredentialParam
    $GatewayPoolObject = get-networkcontrollerGatewayPool -Connectionuri $URI -ResourceId $PoolName @CredentialParam
    
    $VirtualServerProperties = new-object Microsoft.Windows.NetworkController.VirtualServerProperties
    $VirtualServerProperties.Connections = @()
    $VirtualServerProperties.Connections += new-object Microsoft.Windows.NetworkController.Connection
    $VirtualServerProperties.Connections[0].Credential = $nchostUserObject
    $VirtualServerProperties.Connections[0].CredentialType = $nchostUserObject.properties.Type
    $VirtualServerProperties.Connections[0].ManagementAddresses = @($GatewayFQDN)
    $VirtualServerProperties.vmguid = $vmGuid

    $VirtualServerObject = new-networkcontrollervirtualserver -connectionuri $uri @CredentialParam -MarkServerReadOnly $false -ResourceId $GatewayFQDN -Properties $VirtualServerProperties -force -passinnerexception

    write-sdnexpresslog "Adding Gateway to Network Controller."

    $GatewayProperties = new-object Microsoft.Windows.NetworkController.GatewayProperties
    $GatewayProperties.NetworkInterfaces = new-object Microsoft.Windows.NetworkController.NetworkInterfaces
    $GatewayProperties.NetworkInterfaces.InternalNetworkInterface = $BackEndNic 
    $GatewayProperties.NetworkInterfaces.ExternalNetworkInterface = $FrontEndNic
    $GatewayProperties.Pool = $GatewayPoolObject
    $GatewayProperties.VirtualServer = $VirtualServerObject

    if (($GatewayPoolObject.Properties.Type -eq "All") -or ($GatewayPoolObject.Properties.Type -eq "S2sIpsec" )) {
        $GatewayProperties.BGPConfig = new-object Microsoft.Windows.NetworkController.GatewayBgpConfig

        $GatewayProperties.BGPConfig.BgpPeer = @()

        if ($psCmdlet.ParameterSetName -eq "SinglePeer") {
            $GatewayProperties.BGPConfig.BgpPeer += new-object Microsoft.Windows.NetworkController.GatewayBgpPeer
            $GatewayProperties.BGPConfig.BgpPeer[0].PeerExtAsNumber = "0.$RouterASN"
            $GatewayProperties.BGPConfig.BgpPeer[0].PeerIP = $RouterIP
        } else {
            foreach ($router in $routers) {
                $NewPeer = new-object Microsoft.Windows.NetworkController.GatewayBgpPeer
                $NewPeer.PeerExtAsNumber = "0.$($Router.RouterASN)"
                $NewPeer.PeerIP = $Router.RouterIPAddress
                $GatewayProperties.BGPConfig.BgpPeer +=  $NewPeer
            }
        }

        $GatewayProperties.BgpConfig.ExtASNumber = "0.$LocalASN"
    }

    $Gw = new-networkcontrollerGateway -connectionuri $uri @CredentialParam -ResourceId $GatewayFQDN -Properties $GatewayProperties -force -passinnerexception

    write-sdnexpresslog "New-SDNExpressGateway Exit"
}




 #     #               #     # #     # 
 ##    # ###### #    # #     # ##   ## 
 # #   # #      #    # #     # # # # # 
 #  #  # #####  #    # #     # #  #  # 
 #   # # #      # ## #  #   #  #     # 
 #    ## #      ##  ##   # #   #     # 
 #     # ###### #    #    #    #     # 
                                       
function New-SDNExpressVM
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [Parameter(Mandatory=$true)]
        [String] $ComputerName,
        [Parameter(Mandatory=$false)]
        [String] $VMLocation = "",
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            if ($_.length -gt 15) { throw "VMName must be 15 characters or less."}
            if ($_ -match "[{|}~[\\\]^':;<=>?@!`"#$%``()+/.,*&]") { throw 'VMName cannot contain the following characters: { | } ~ [ \ ] ^ ' + "'" + ': ; < = > ? @ ! " # $ % ` ( ) + / . , * &'}
            if ($_ -match " ") { throw 'VMName cannot contain spaces.'}
            return $true
        })]        
        [String] $VMName,
        [Parameter(Mandatory=$true)]
        [String] $VHDSrcPath,
        [Parameter(Mandatory=$true)]
        [String] $VHDName,
        [Parameter(Mandatory=$false)]
        [Int64] $VMMemory=8GB,
        [Parameter(Mandatory=$false)]
        [String] $SwitchName="",
        [Object] $Nics,
        [Parameter(Mandatory=$true,ParameterSetName="UserName")]      
        [String] $CredentialDomain,
        [Parameter(Mandatory=$true,ParameterSetName="UserName")]      
        [String] $CredentialUserName,
        [Parameter(Mandatory=$true,ParameterSetName="UserName")]      
        [String] $CredentialPassword,
        [Parameter(Mandatory=$true,ParameterSetName="Creds")]      
        [PSCredential] $Credential = $null,
        [Parameter(Mandatory=$true)]
        [String] $JoinDomain,
        [Parameter(Mandatory=$true)]
        [String] $LocalAdminPassword,
        [Parameter(Mandatory=$false)]
        [String] $DomainAdminDomain = $null,
        [Parameter(Mandatory=$false)]
        [String] $DomainAdminUserName = $null,
        [Parameter(Mandatory=$false)]
        [String] $ProductKey="",
        [Parameter(Mandatory=$false)]
        [int] $VMProcessorCount = 8,
        [Parameter(Mandatory=$false)]
        [String] $Locale = [System.Globalization.CultureInfo]::CurrentCulture.Name,
        [Parameter(Mandatory=$false)]
        [String] $TimeZone = [TimeZoneInfo]::Local.Id,
        [Parameter(Mandatory=$false)]
        [String[]] $Roles = @(),
        [Parameter(Mandatory=$false)]
        [String] $OperationID = ""
        )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet

    if ($psCmdlet.ParameterSetName -eq "UserName") {
        $CredentialSecurePassword = $CredentialPassword | convertto-securestring -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PsCredential("$CredentialDomain\$CredentialUserName", $credentialSecurePassword)
    }

    $vm = get-vm -computername $ComputerName -Name $VMName -erroraction Ignore
    if ($null -ne $vm) {
        Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 100 -context $VMName
        write-sdnexpresslog "VM named $VMName already exists on $ComputerName."
        return
    }

    $hostprocessorcount = (get-vmhost -computername $computername).logicalprocessorcount
    if ($vmprocessorcount -gt $hostprocessorcount) {
        write-sdnexpresslog "VMProcessorCount is greater than logical processors on $ComputerName.  Lowering VM processor count from $vmprocessorcount to $hostprocessorcount to match host."
        $vmprocessorcount = $hostprocessorcount
    }

    if ([string]::IsNullOrEmpty($DomainAdminUserName)) {
        if ($null -eq $Credential) {
            $DomainAdminDomain = $env:USERDOMAIN
            $DomainAdminUsername = $env:USERNAME
        } else {
            $DomainAdminDomain = $credential.UserName.Split('\')[0]
            $DomainAdminUsername = $credential.UserName.Split('\')[1]
        }
    }

    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    if ([String]::IsNullOrEmpty($VMLocation)) {
        $VHDLocation = invoke-command -computername $computername  @CredentialParam {
            return (get-vmhost).virtualharddiskpath
        }
        $VMLocation = invoke-command -computername $computername  @CredentialParam {
            return (get-vmhost).virtualmachinepath
        }
        write-sdnexpresslog "Using Hyper-V configured VM Location: $VMLocation"
        write-sdnexpresslog "Using Hyper-V configured VHD Location: $VHDLocation"
    } else {
        $VHDLocation = $VMLocation
    }

    $LocalVMPath = "$vmLocation\$VMName"
    $LocalVHDPath = "$vhdlocation\$VMName\$VHDName"
    $VHDFullPath = "$VHDSrcPath\$VHDName" 
    $VMPath = "$VHDLocation\$VMName"
    $IsSMB = $VMLocation.startswith("\\")
    $IsCSV = $false

    $VM = $null

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 10 -context $VMName

    $NodeFQDN = invoke-command -ComputerName $ComputerName @CredentialParam {
        return (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    }
    $thisFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    $IsLocal = $NodeFQDN -eq $thisFQDN
    if ($IsLocal) {
        write-sdnexpresslog "VM is created on same machine as script."
    }

    if (!$IsSMB -and !$IsLocal) {
        write-sdnexpresslog "Checking if path is CSV on $computername."
        $IsCSV = invoke-command -computername $computername  @CredentialParam {
            param([String] $VMPath)
            try {
                $csv = get-clustersharedvolume -ErrorAction Ignore
            } catch {}

            $volumes = $csv.sharedvolumeinfo.friendlyvolumename
            foreach ($volume in $volumes) {
                if ($VMPath.ToUpper().StartsWith("$volume\".ToUpper())) {
                    return $true
                }
            }
            return $false
        } -ArgumentList $VMPath
        if ($IsCSV) {
            write-sdnexpresslog "Path is CSV."
            $VMPath = "\\$computername\$VMPath".Replace(":", "$")
        } else {
            write-sdnexpresslog "Path is not CSV."
            $VMPath = "\\$ComputerName\VMShare\$VMName"
        }
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 20 -context $VMName
    write-sdnexpresslog "Using $VMPath as destination for VHD copy."

    $VHDVMPath = "$VMPath\$VHDName"

    write-sdnexpresslog "Checking for previously mounted image."

    $mounted = get-WindowsImage -Mounted
    foreach ($mount in $mounted) 
    {
        if ($mount.ImagePath -eq $VHDVMPath) {
            DisMount-WindowsImage -Discard -path $mount.Path | out-null
        }
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 30 -context $VMName

    if ([String]::IsNullOrEmpty($SwitchName)) {
        write-sdnexpresslog "Finding virtual switch."
        try {
            $SwitchName = invoke-command -computername $computername  @CredentialParam  {
                $VMSwitches = Get-VMSwitch
                if ($VMSwitches -eq $Null) {
                    throw "No Virtual Switches found on the host.  Can't create VM.  Please create a virtual switch before continuing."
                }
                if ($VMSwitches.count -gt 1) {
                    throw "More than one virtual switch found on host.  Please specify virtual switch name using SwitchName parameter."
                }

                return $VMSwitches.Name
            }
        }
        catch
        {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["INVALIDVSWITCH"].Code -LogMessage $Errors["INVALIDVSWITCH"].Message   #No errormessage because SDN Express generates error
            throw $_.Exception
        }
    }
    write-sdnexpresslog "Will attach VM to virtual switch: $SwitchName"

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 40 -context $VMName

    if (!($IsLocal -or $IsCSV -or $IsSMB)) {
        write-sdnexpresslog "Creating VM root directory and share on host."

        invoke-command -computername $computername @CredentialParam {
            param(
                [String] $VMLocation,
                [String] $UserName
            )
            New-Item -ItemType Directory -Force -Path $VMLocation | out-null
            get-SmbShare -Name VMShare -ErrorAction Ignore | remove-SMBShare -Force
            New-SmbShare -Name VMShare -Path $VMLocation -FullAccess $UserName -Temporary | out-null
        } -ArgumentList $VHDLocation, ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 50 -context $VMName
    
    write-sdnexpresslog "Creating VM directory and copying VHD.  This may take a few minutes."
    write-sdnexpresslog "Copy from $VHDFullPath to $VMPath"

    New-Item -ItemType Directory -Force -Path $VMPath | out-null
    copy-item -Path $VHDFullPath -Destination $VMPath | out-null

    write-sdnexpresslog "Creating mount directory and mounting VHD."

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $MountPath = $TempFile.FullName

    New-Item -ItemType Directory -Force -Path $MountPath | out-null

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 60 -context $VMName


    write-sdnexpresslog "Generating unattend.xml"

    $count = 1
    $TCPIPInterfaces = ""
    $dnsinterfaces = ""
    $dnssection = ""

    foreach ($nic in $Nics) {
        
        $MacAddress = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"

        if ($Nic.keys -contains "IPAddress" -and ![String]::IsNullOrEmpty($Nic.IPAddress)) {
            $sp = $NIC.IPAddress.Split("/")
            $IPAddress = $sp[0]
            $SubnetMask = $sp[1]
    
            if ($Nic.Keys -contains "Gateway" -and ![String]::IsNullOrEmpty($Nic.Gateway)) {
                $gatewaysnippet = @"
                <routes>
                    <Route wcm:action="add">
                        <Identifier>0</Identifier>
                        <Prefix>0.0.0.0/0</Prefix>
                        <Metric>20</Metric>
                        <NextHopAddress>$($Nic.Gateway)</NextHopAddress>
                    </Route>
                </routes>
"@
            } else {
                $gatewaysnippet = ""
            }
    
            $TCPIPInterfaces += @"
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <Identifier>$MacAddress</Identifier>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$SubnetMask</IpAddress>
                    </UnicastIpAddresses>
                    $gatewaysnippet
                </Interface>
"@ 
            $alldns = ""
            $dnsregistration = "false"
            if ($Nic.Keys -contains "DNS" -and ![String]::IsNullOrEmpty($Nic.DNS)) {
                foreach ($dns in $Nic.DNS) {
                        $alldns += '<IpAddress wcm:action="add" wcm:keyValue="{1}">{0}</IpAddress>' -f $dns, $count++
                }

                $dnsregistration = "true"
            }
            $dnsinterfaces += @"
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                    $alldns
                    </DNSServerSearchOrder>
                    <Identifier>$MacAddress</Identifier>
                    <EnableAdapterDomainNameRegistration>$DNSRegistration</EnableAdapterDomainNameRegistration>
                </Interface>
"@

            $dnsSection = @"
            <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
$DNSInterfaces
            </Interfaces>
        </component>
"@
        } else {
            $TCPIPInterfaces += @"
            <Interface wcm:action="add">
                <Ipv4Settings>
                    <DhcpEnabled>true</DhcpEnabled>
                </Ipv4Settings>
                <Identifier>$MacAddress</Identifier>
            </Interface>
"@ 

        }        
    }

    $ProductKeyField = ""
    if (![String]::IsNullOrEmpty($ProductKey)) {
        $ProductKeyField = "<ProductKey>$ProductKey</ProductKey>"
    }

    $unattendfile = @"
    <?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend">
        <settings pass="specialize">
            <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Interfaces>
    $TCPIPInterfaces
                </Interfaces>
            </component>
    $DNSSection
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <ComputerName>$VMName</ComputerName>
    $ProductKeyField
            </component>
        </settings>
        <settings pass="oobeSystem">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <UserAccounts>
                    <AdministratorPassword>
                        <Value>$LocalAdminPassword</Value>
                        <PlainText>true</PlainText>
                    </AdministratorPassword>
                    <DomainAccounts>
                        <DomainAccountList wcm:action="add">
                            <DomainAccount wcm:action="add">
                                <Name>$DomainAdminUserName</Name>
                                <Group>Administrators</Group>
                            </DomainAccount>
                            <Domain>$DomainAdminDomain</Domain>
                        </DomainAccountList>
                    </DomainAccounts>
                </UserAccounts>
                <TimeZone>$TimeZone</TimeZone>
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
                <UserLocale>$Locale</UserLocale>
                <SystemLocale>$Locale</SystemLocale>
                <InputLocale>$Locale</InputLocale>
                <UILanguage>$Locale</UILanguage>
            </component>
        </settings>
        <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
    </unattend>
"@

    try {
        $WindowsImage = Mount-WindowsImage -ImagePath $VHDVMPath -Index 1 -path $MountPath

        $Edition = get-windowsedition -path $MountPath

        if (!(@("ServerDatacenterCor", "ServerDatacenter", "ServerAzureStackHCICor") -contains $Edition.Edition)) {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["WINDOWSEDITION"].Code -LogMessage $Errors["WINDOWSEDITION"].Message   #No errormessage because SDN Express generates error
            throw $Errors["WINDOWSEDITION"].Message        
        }

        if ($Roles.count -gt 0) {
            write-sdnexpresslog "Adding Roles ($Roles) offline to save reboot later"

            foreach ($role in $Roles) {
                Enable-WindowsOptionalFeature -Path $MountPath -FeatureName $role -All -LimitAccess | Out-Null
            }
        }

        Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 70 -context $VMName

        write-sdnexpresslog "Offline Domain Join"
        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force
        $DJoinOutput = djoin /provision /domain $JoinDomain /machine $VMName /savefile $tempfile.fullname /REUSE
        if ($LASTEXITCODE -ne "0") {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["COMPUTEREXISTS"].Code -LogMessage $Errors["COMPUTEREXISTS"].Message   #No errormessage because SDN Express generates error
            throw $Errors["COMPUTEREXISTS"].Message    
        }
        write-sdnexpresslog $DJoinOutput
        $DJoinOutput = djoin /requestODJ /loadfile $tempfile.fullname /windowspath "$MountPath\Windows" /localos
        if ($LASTEXITCODE -ne "0") {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["COMPUTEREXISTS"].Code -LogMessage $Errors["COMPUTEREXISTS"].Message   #No errormessage because SDN Express generates error
            throw $Errors["COMPUTEREXISTS"].Message    
        }    
        write-sdnexpresslog $DJoinOutput
        Remove-Item $TempFile.FullName -Force
        

        write-sdnexpresslog "Writing unattend.xml to $MountPath\unattend.xml"
        Set-Content -value $UnattendFile -path "$MountPath\unattend.xml" | out-null

        New-Item -ItemType Directory -Force -Path "$MountPath\Windows\Setup\Scripts" | out-null

        $setupcompletecmdfile = 'PowerShell -file "\Windows\Setup\Scripts\SetupComplete.ps1"'
        Set-Content -value $SetupCompleteCMDFile -path "$MountPath\Windows\Setup\Scripts\SetupComplete.cmd" | out-null

        $setupcompleteps1file = @'
new-eventlog -logname "Application" -source "SDNExpress" -ErrorAction SilentlyContinue
Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "NetworkCategory check." -ErrorAction SilentlyContinue 
$try = 0
while ($true) {
    $try++

    $Profiles = get-netconnectionprofile

    foreach ($profile in $profiles) { 
        Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "$($profile.interfacealias) NetworkCategory is $($profile.NetworkCategory)." -ErrorAction SilentlyContinue 
        if ($profile.NetworkCategory -eq "DomainAuthenticated") {
            return
        }
    }

    Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Not DomainAuthenticated. Reset attempt $try." -ErrorAction SilentlyContinue 

    foreach ($profile in $profiles) { 
        disable-netadapter -interfaceindex $profile.InterfaceIndex
        enable-netadapter -interfaceindex $profile.InterfaceIndex
    }

    sleep 60
}
'@
        Set-Content -value $SetupCompletePS1File -path "$MountPath\Windows\Setup\Scripts\SetupComplete.ps1" | out-null
    }
    catch
    {
        write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["GENERALEXCEPTION"].Code -LogMessage $_.Exception.Message -ErrorMessage $_.Exception.Message
        throw $_.Exception    
    }
    finally
    {        
        write-sdnexpresslog "Cleaning up"
        DisMount-WindowsImage -Save -path $MountPath | out-null
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 80 -context $VMName

    write-sdnexpresslog "Removing temp path"
    Remove-Item $MountPath -Force
    write-sdnexpresslog "removing smb share"
    Invoke-Command -computername $computername  @CredentialParam {
        Get-SmbShare -Name VMShare -ErrorAction Ignore | remove-SMBShare -Force | out-null
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 90 -context $VMName
    write-sdnexpresslog "Creating VM: $computername"
    try 
    {
        invoke-command -ComputerName $ComputerName  @CredentialParam -ScriptBlock {
            param(
                [String] $VMName,
                [String] $LocalVMPath,
                [Int64] $VMMemory,
                [Int] $VMProcessorCount,
                [String] $LocalVHDPath,
                [String] $SwitchName,
                [Object] $Nics
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            write-verbose "Creating VM $VMName in $LocalVMPath using $LocalVHDPath."
            $NewVM = New-VM -Generation 2 -Name $VMName -Path $LocalVMPath -MemoryStartupBytes $VMMemory -VHDPath $LocalVHDPath -SwitchName $SwitchName
            write-verbose "Setting processor count to $VMProcessorCount."
            $NewVM | Set-VM -processorcount $VMProcessorCount | out-null

            $first = $true
            foreach ($nic in $Nics) {
                $FormattedMac = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
                if ($first) {
                    write-verbose "Configuring first network adapter with mac $formattedmac."
                    $vnic = $NewVM | get-vmnetworkadapter 
                    $vnic | rename-vmnetworkadapter -newname $Nic.Name
                    $vnic | Set-vmnetworkadapter -StaticMacAddress $FormattedMac
                    $first = $false
                } else {
                    write-verbose "Configuring additional network adapters with mac $formattedmac."
                    #Note: add-vmnetworkadapter doesn't actually return the vnic object for some reason which is why this does a get immediately after.
                    $vnic = $NewVM | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $Nic.Name -StaticMacAddress $FormattedMac
                    $vnic = $NewVM | get-vmnetworkadapter -Name $Nic.Name  
                }

                $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56"
           
                $portProfileDefaultSetting.SettingData.ProfileId = "{$([Guid]::Empty)}"
                $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
                $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
                $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
                $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
                $portProfileDefaultSetting.SettingData.VendorId =  "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"
                $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"

                if ($nic.IsMuxPA) {
                    $portProfileDefaultSetting.SettingData.ProfileData = 2
                    if ($nic.vlanid) {
                        #Profile data 2 means VFP is disbled on the port (for higher Mux throughput), and so you must set the VLAN ID using Set-VMNetworkAdapterVLAN for ports where VFP is disabled
                        write-verbose "Setting VLAN $($nic.vlanid) via Set-VMNetworkAdapterVLAN."
                        $vnic | Set-VMNetworkAdapterVLAN -Access -VLANID $nic.vlanid | out-null
                    }
                } else {
                    $portProfileDefaultSetting.SettingData.ProfileData = 1
                    if ($nic.vlanid) {
                        #Profile data 1 means VFP is enabled, but unblocked with default allow-all acls.  For VFP enabled ports, VFP enforces VLAN isolation so you must set using set-VMNetworkAdapterIsolation  
                        write-verbose "Setting VLAN $($nic.vlanid) via Set-VMNetworkIsolation."
                        $vnic | Set-VMNetworkAdapterIsolation -AllowUntaggedTraffic $true -IsolationMode VLAN -defaultisolationid $nic.vlanid | out-null
                    }
                }
        
                write-verbose "Adding port feature."
                
                Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vNic | out-null
            }
                            
            $NewVM | Start-VM | out-null

        } -ArgumentList $VMName, $LocalVMPath, $VMMemory, $VMProcessorCount, $LocalVHDPath, $SwitchName, $Nics | Parse-RemoteOutput
                
    } catch {
        write-sdnexpresslog "Exception creating VM: $($_.Exception.Message)"
        write-sdnexpresslog "Deleting VM."
        $vm = get-vm -computername $ComputerName -Name $VMName -erroraction Ignore
        if ($null -ne $vm) {
            $vm | stop-vm -turnoff -force -erroraction Ignore
            $vm | remove-vm -force -erroraction Ignore
        }
        write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors["GENERALEXCEPTION"].Code -LogMessage $_.Exception.Message -ErrorMessage $_.Exception.Message
        throw $_.Exception
    }
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 100 -context $VMName
    write-sdnexpresslog "Exit Function: $($MyInvocation.InvocationName)"
}


function Test-SDNExpressHealth
{
    param(
        [String] $RestName,
        [PSCredential] $Credential = $null
    )
    write-sdnexpresslog "Test-SDNExpressHealth"
    write-sdnexpresslog "  -RestName: $RestName"
    write-sdnexpresslog "  -Credential: $($Credential.UserName)"

    $uri = "https://$RestName"    
    
    $DefaultRestParams = @{
        'ConnectionURI'=$uri;
        'Credential'=$Credential;
    }
    if ($null -ne $Credential) {
        $DefaultRestParams.Credential = $credential
    }

    write-sdnexpresslog "Server Status:"
    $servers = get-networkcontrollerserver @DefaultRestParams
    foreach ($server in $servers) {
        write-sdnexpresslog "$($Server.properties.connections.managementaddresses) status: $($server.properties.configurationstate.status)"
    }
    write-sdnexpresslog "Mux Status:"
    $muxes = get-networkcontrollerloadbalancermux @DefaultRestParams
    foreach ($mux in $muxes) {
        write-sdnexpresslog "$($mux.ResourceId) status: $($mux.properties.configurationstate.status)"
    }
    write-sdnexpresslog "Gateway Status:"
    $gateways = get-networkcontrollergateway @DefaultRestParams
    foreach ($gateway in $gateways) {
        write-sdnexpresslog "$($gateway.ResourceId) status: $($gateway.properties.State), $($gateway.properties.HealthState)"
    }
}

Export-ModuleMember -Function New-SDNExpressVM
Export-ModuleMember -Function New-SDNExpressNetworkController
Export-ModuleMember -Function Add-SDNExpressHost
Export-ModuleMember -Function Add-SDNExpressMux
Export-ModuleMember -Function New-SDNExpressGatewayPool
Export-ModuleMember -Function New-SDNExpressGateway

Export-ModuleMember -Function New-SDNExpressLoadBalancerManagerConfiguration
Export-ModuleMember -Function New-SDNExpressVirtualNetworkManagerConfiguration
Export-ModuleMember -Function New-SDNExpressiDNSConfiguration
Export-ModuleMember -Function Add-SDNExpressLoadBalancerVIPSubnet
Export-ModuleMember -Function Add-SDNExpressVirtualNetworkPASubnet

Export-ModuleMember -Function Test-SDNExpressHealth
Export-ModuleMember -Function Enable-SDNExpressVMPort

Export-ModuleMember -Function WaitForComputerToBeReady
Export-ModuleMember -Function write-SDNExpressLog
Export-ModuleMember -Function Get-IPAddressInSubnet