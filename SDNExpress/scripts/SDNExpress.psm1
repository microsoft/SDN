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

# todo : does it matter to have this enabled ?
#set-strictmode -version 5.0

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

<#
    Checks is a certificate in file format is self signed
#>
function IsSelfSignedCert(
    [parameter(Mandatory=$true)] [string] $filePath, 
    [parameter(Mandatory=$false)] [System.Security.SecureString] $secPwd
    )
{
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

    if ($secPwd -ne $null)
    {
        $cert.Import($filePath, $secPwd, 0)
    }
    else
    { 
        $cert.Import($filePath)
    }

    return $cert.Issuer -eq $cert.Subject
}

<#
.DESCRIPTION
Selects the best certificate for SDN when searching using subject name

Certs with NC OID have precedence
#>
function GetSdnCert(
    [parameter(Mandatory=$true)] [string] $subjectName, 
    [parameter(Mandatory=$false)][string] $store = "cert:\localmachine\my"
    )
{  
  $certs = get-childitem $store `
    | where-object {$_.Subject.ToUpper() -eq "CN=$($subjectName)" } `
    | where-object {$_.NotAfter -ge (get-date) } `
    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"}} `
    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"}} `
    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.4.1.311.95.1.1.1"}} `
    | Sort-Object -Property NotAfter -Descending

  if ($certs -ne $null) {    
    return $certs[0]
  }

  $certs = get-childitem $store `
    | where-object {$_.Subject.ToUpper() -eq "CN=$($subjectName)" } `
    | where-object {$_.NotAfter -ge (get-date) } `
    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"}} `
    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"}} `
    | Sort-Object -Property NotAfter -Descending

  if ($certs -ne $null) {
    return $certs[0]
  }

  return $null
}

$Global:fdGetSdnCert = "function GetSdnCert { ${function:GetSdnCert} }"

# Get all nodes that are up and included as servers in a given failover cluster and SDN deployment.
function Get-NodesInSDNCluster(
    [parameter(Mandatory=$true)] [string] $ComputerName,
    [parameter(Mandatory=$true)] [string] $uri,
    [parameter(Mandatory=$true)] [object] $CredentialParam
    )
{
    try {
        $nodes = Invoke-Command $ComputerName @CredentialParam { get-clusternode | Where-Object { $_.State -eq "Up" } | Select-Object -ExpandProperty Name }
        $sdnNodes = (Get-NetworkControllerServer -ConnectionUri $uri).properties.connections.managementaddresses
        $domainName = Invoke-Command $ComputerName @CredentialParam { (get-ciminstance win32_computersystem).Domain }
        $nodesInSdnCluster = $nodes | Where-Object { ("$($_).$($domainName)" -in $sdnNodes) -or ($_ -in $sdnNodes)}

        return $nodesInSdnCluster
    }
    catch {
        # In case FC is not used with SF based deployment, skip and return an empty list
        return @()
    }
}

function Get-RestCertificate(
    [parameter(Mandatory=$true)] [string[]] $ComputerNames,
    [parameter(Mandatory=$true)] [string] $RestName,
    [parameter(Mandatory=$true)] [string] $certPwdString,
    [parameter(Mandatory=$true)] [object] $CredentialParam
)
{
    [byte[]] $RestCertPfxData = @()
    $nodeIdx = 0
    while ($RestCertPfxData.length -eq 0 -and $nodeIdx -lt $ComputerNames.length) {
        $RestCertPfxData = invoke-command -computername $ComputerNames[$nodeIdx] @CredentialParam {
            param(
                [String] $RestName,
                [String] $certpwdstring,
                [String] $funcDefGetSdnCert
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
            . ([ScriptBlock]::Create($funcDefGetSdnCert))
            $Cert = GetSdnCert -subjectName $RestName.ToUpper()

            if ($null -ne $Cert) {
                write-verbose "Existing certificate meets criteria. Exporting." 
            }

            if ($null -ne $Cert) {
                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force | out-null
                [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
                $CertData = Get-Content $TempFile.FullName -Encoding Byte
                Remove-Item $TempFile.FullName -Force | out-null
                write-verbose "Returning Cert Data found on $(hostname)" 
                write-output $CertData
            } else {
                write-verbose "No certificate found on $(hostname)"
                write-output @()
            }
        } -ArgumentList $RestName, $certpwdstring, $Global:fdGetSdnCert | Parse-RemoteOutput
        $nodeIdx += 1
    }

    $RestCertPfxData
}

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
            if ([string]::isnullorempty($_)) { return $true }
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
        [String] $OperationID = "",
        [Parameter(Mandatory=$false)] 
        [bool] $UseCertBySubject = $false

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
                [String] $certpwdstring,
                [String] $funcDefGetSdnCert
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
            . ([ScriptBlock]::Create($funcDefGetSdnCert))
            $Cert = GetSdnCert -subjectName $RestName.ToUpper()
            if ($null -eq $Cert) {
                write-verbose "Creating new REST certificate." 
                $Cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$RESTName" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1")
            } else {
                write-verbose "Existing certificate meets criteria. Exporting." 
            }
            $TempFile = New-TemporaryFile
            Remove-Item $TempFile.FullName -Force | out-null
            [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
            $CertData = Get-Content $TempFile.FullName -Encoding Byte
            Remove-Item $TempFile.FullName -Force | out-null
            write-verbose "Returning Cert Data." 
            write-output $CertData
        } -ArgumentList $RestName, $certpwdstring, $Global:fdGetSdnCert | Parse-RemoteOutput
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
    
    # Import only self signed certs in root
    if ($RESTCertPFX.Issuer -eq $RESTCertPFX.Subject)
    {
        write-sdnexpresslog "Importing REST cert (public key only) into Root store."
        $RestCert = import-certificate -filepath "$TempDir\$RESTName" -certstorelocation "cert:\localmachine\root"
    }
    else
    { 
        $RestCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2        
        $RestCert.Import("$TempDir\$RESTName")
    }

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
                    [String] $certpwdstring,
                    [String] $funcDefGetSdnCert
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
        
                $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  

                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force
                $RESTCertPFXData | set-content $TempFile.FullName -Encoding Byte

                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $RestName.ToUpper()

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
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($TempFile.FullName, $certpwd, 0)
                    if ($cert.Issuer -eq $cert.Subject) {
                        write-verbose "REST cert does not yet exist in Root store, adding."
                        $cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
                    }
                }

                Remove-Item $TempFile.FullName -Force
            } -Argumentlist $RESTName, $RESTCertPFXData, $RESTCertThumbprint,$certpwdstring,$Global:fdGetSdnCert | Parse-RemoteOutput
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
                    [String] $certpwdstring,
                    [String] $funcDefGetSdnCert
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $NodeFQDN.ToUpper()

                write-verbose "Found $($cert.count) certificate(s) in my store with subject name matching $NodeFQDN"

                if ($Cert -eq $null) {
                    write-verbose "Creating new self signed certificate in My store."
                    $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1") -DNSNAME $RESTName
                } else {                    
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
            } -ArgumentList $CertPwdString, $Global:fdGetSdnCert | Parse-RemoteOutput
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

        $certFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certFromFile.Import($TempFile.FullName, $certpwd, 0)

        $AllNodeCerts += $certFromFile
        
        $isCertDataSelfSigned = $certFromFile.Issuer -eq $certFromFile.Subject
        # Import only self signed certs
        if ($isCertDataSelfSigned )
        {
            import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
        }
        Remove-Item $TempFile.FullName -Force

        if ($isCertDataSelfSigned) {
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
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 50 -context $restname

    $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    $HostCert = GetSdnCert -subjectName $NodeFQDN.ToUpper()
    if ($HostCert -ne $null -and $HostCert.Issuer -ne $HostCert.Subject -and $HostCert.Issuer -eq "CN=AzureStackCertificationAuthority" ) {
        write-sdnexpresslog "Importing AS CA root cert $($HostCert.Issuer) into NC VMs"  
        $rootCert = get-childitem "cert:\localmachine\root" | where-object {$_.Subject.ToUpper() -eq "$($HostCert.Issuer)" } | Select-Object -First 1 

        if ($rootCert -ne $null) {
            [Byte[]] $CertBytes = $rootCert.GetRawCertData()
   
            foreach ($node in $ComputerNames) {
                write-sdnexpresslog "Installing CA root cert into root store of $node."

                invoke-command -computername $node  @CredentialParam {
                    param(
                        [Byte[]] $CertData
                    )

                    $TempFile = New-TemporaryFile
                    Remove-Item $TempFile.FullName -Force    
                    $CertData | set-content $TempFile.FullName -Encoding Byte
                    import-certificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" | out-null
                    Remove-Item $TempFile.FullName -Force
                } -ArgumentList @(, $CertBytes ) | Parse-RemoteOutput         
            }
        }
    }

    write-sdnexpresslog "Configuring Network Controller role using node: $($ComputerNames[0])"
  
    $controller = $null
    try { $controller = get-networkcontroller -computername $ComputerNames[0] -erroraction Ignore } catch {}
    if ($controller -ne $null) {
        if ($force) {
            write-SDNExpressLog "Controller role found, force option specified, uninstalling."
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

        if ($UseCertBySubject)
        {
            $nodes += New-NetworkControllerNodeObject -Name $server -Server $NodeFQDN -FaultDomain ("fd:/"+$server) -RestInterface $nic.Name -NodeCertificateFindBy FindBySubjectName -CertificateSubjectName $NodeFQDN 
        }
        else
        {
            $nodes += New-NetworkControllerNodeObject -Name $server -Server $NodeFQDN -FaultDomain ("fd:/"+$server) -RestInterface $nic.Name -NodeCertificate $cert -verbose                    
        } 
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
        if ($nodes.Length -eq 1 -and $nodes[0].Server -eq $RESTName) {
            write-SDNExpressLog "The RestName paramter is not used because it is a single node cluster and the node name is the same as the REST name $($nodes[0].Server)"
        }
        else {    
            $params.add('RestName', $RESTName);
        }
    }

    write-SDNExpressLog "Install-NetworkController with parameters:"
    foreach ($i in $params.getenumerator()) { write-SDNExpressLog "   $($i.key)=$($i.value)"}
    Install-NetworkController @params -force | out-null
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 90 -context $restname

    write-SDNExpressLog "Install-NetworkController complete."
    Write-SDNExpressLog "Network Controller cluster creation complete."
    
    #Verify that SDN REST endpoint is working before returning
    Write-SDNExpressLog "Verifying Network Controller is operational."

    if (!($RESTName -as [IPAddress] -as [bool]))
    {
        $dnsServers = (Get-DnsClientServerAddress -AddressFamily ipv4).ServerAddresses | select -uniq
        $dnsWorking = $true

        foreach ($dns in $dnsServers)
        {
            $dnsResponse = $null
            $count = 0

            while (($dnsResponse -eq $null) -and ($count -lt 90)) {
                $dnsResponse = Resolve-DnsName -name $RESTName -Server $dns -ErrorAction Ignore
                if ($dnsResponse -eq $null) {
                   write-sdnexpresslog "No response from the DNS server. Sleeping for 20 seconds"
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

function New-FCNCNetworkController
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [String[]] $ComputerNames, # may or may not be all the cluster node names because stretch deployments occur on partial clusters
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]        
        [String] $RESTName,
        # [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        # [String] $ManagementSecurityGroupName,
        # [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        # [String] $ClientSecurityGroupName,
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "RESTIPAddress parameter must match the syntax <IP Address>/<Subnet bits>."} #WARNING!/SUBNET CAUSES ERROR FOR TEMP FILE ie Exception calling "WriteAllBytes" with "2" argument(s): "Could not find a part of the path 'C:\Users\wolfpack\AppData\Local\Temp\tmp6D40.tmp\10.127.131.60\32.pfx'.
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
        [String] $OperationID = "",
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [String] $FCNCBins,
        [Parameter(Mandatory=$true,ParameterSetName="Kerberos")]        
        [Parameter(Mandatory=$true,ParameterSetName="Default")]
        [String] $FCNCDBs,
        [string] $ClusterNetworkName,
        [Parameter(Mandatory=$false)] 
        [bool] $UseCertBySubject = $false
    )

    $RESTName = $RESTName.ToUpper()

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

    $isAlreadyDeployed = $false
    
    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 10 -context $restname

    write-sdnexpresslog ("Checking if Controller already deployed by looking for REST response.")
    try { 
        get-networkcontrollerCredential -ConnectionURI "https://$RestName" @CredentialParam  | out-null
        if (!$force) {
            write-sdnexpresslog "Network Controller at $RESTNAME already exists. Reusing REST cert and continuing"
            $isAlreadyDeployed = $true
        }
    }
    catch {
       write-sdnexpresslog "Network Controller does not exist, will continue."
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 20 -context $restname
    if (-not $isAlreadyDeployed) {
        write-sdnexpresslog "Creating local temp directory."

        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force
        $TempDir = $TempFile.FullName
        New-Item -ItemType Directory -Force -Path $TempDir | out-null

        write-sdnexpresslog "Temp directory is: $($TempFile.FullName)"
        write-sdnexpresslog "Creating REST cert on: $($computernames[0])"
        Write-SDNExpressLog "ClusterNetworkName:$ClusterNetworkName"

        try {
            $RestCertPfxData = invoke-command -computername $ComputerNames[0] @CredentialParam {
                param(
                    [String] $RestName,
                    [String] $certpwdstring,
                    [String] $funcDefGetSdnCert
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $RestName.ToUpper()
                if ($null -eq $Cert) {
                    write-verbose "Creating new REST certificate." 
                    $Cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$RESTName" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1")
                } else {
                    write-verbose "Existing certificate meets criteria. Exporting." 
                }
                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force | out-null
                [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
                $CertData = Get-Content $TempFile.FullName -Encoding Byte
                Remove-Item $TempFile.FullName -Force | out-null
                write-verbose "Returning Cert Data." 
                write-output $CertData
            } -ArgumentList $RestName, $certpwdstring, $Global:fdGetSdnCert | Parse-RemoteOutput
        }
        catch
        {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors['INVALIDKEYUSAGE'].Code -LogMessage $_.Exception.Message   #No errormessage because SDN Express generates error
            throw $_.Exception
        }
    } else {
        write-sdnexpresslog "Finding existing REST cert"
        Write-SDNExpressLog "ClusterNetworkName:$ClusterNetworkName"

        $RestCertPfxData = Get-RestCertificate -ComputerNames $ComputerNames -RestName $RESTName -certPwdString $certpwdstring -CredentialParam $CredentialParam 
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
    
    if ($RESTCertPFX.Issuer -eq $RESTCertPFX.Subject)
    {
        write-sdnexpresslog "Importing REST cert (public key only) into Root store."
        $RestCert = import-certificate -filepath "$TempDir\$RESTName" -certstorelocation "cert:\localmachine\root"
    } 
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
                    [String] $certpwdstring,
                    [String] $funcDefGetSdnCert
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
        
                $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  

                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force
                $RESTCertPFXData | set-content $TempFile.FullName -Encoding Byte

                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $RestName.ToUpper()

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
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($TempFile.FullName, $certpwd, 0)
                    if ($cert.Issuer -eq $cert.Subject) {
                        write-verbose "REST cert does not yet exist in Root store, adding."
                        $cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
                    }
                }

                Remove-Item $TempFile.FullName -Force
            } -Argumentlist $RESTName, $RESTCertPFXData, $RESTCertThumbprint,$certpwdstring,$Global:fdGetSdnCert | Parse-RemoteOutput
        }
        catch
        {
            write-logerror -OperationId $operationId -Source $MyInvocation.MyCommand.Name -ErrorCode $Errors['CERTTHUMBPRINT'].code -LogMessage $_.Exception.Message   #No errormessage because SDN Express generates error
            throw $_.Exception
        }
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 40 -context $restname


    $AllNodeCerts = @()

    foreach ($ncnode in $ComputerNames) {
        write-sdnexpresslog "Creating node cert for: $ncnode"
        try 
        {
            [byte[]] $CertData = invoke-command -computername $ncnode  @CredentialParam {
                param(
                    [String] $certpwdstring,
                    [String] $funcDefGetSdnCert
                )
                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $NodeFQDN.ToUpper()

                write-verbose "Found $($cert.count) certificate(s) in my store with subject name matching $NodeFQDN"

                if ($Cert -eq $null) {
                    write-verbose "Creating new self signed certificate in My store."
                    $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1") -DNSNAME $RESTName
                } else {                    
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
            } -ArgumentList $CertPwdString, $Global:fdGetSdnCert | Parse-RemoteOutput
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

        $isCertDataSelfSigned = IsSelfSignedCert -filePath $TempFile.FullName -secPwd $certpwd
        if ($isCertDataSelfSigned)
        {
            $AllNodeCerts += import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
        }
        Remove-Item $TempFile.FullName -Force
 
        if ($isCertDataSelfSigned) {
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
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 50 -context $restname

    if (-not $isAlreadyDeployed) {       
    
        mkdir $FCNCDBs -ErrorAction SilentlyContinue -Verbose
        foreach ($ncnode in $ComputerNames)
        {
            Enable-NetworkControllerOnFailoverClusterLoggingOnDevice -DeviceName $ncnode -Device 'Server'
        }

        if ($UseCertBySubject) 
        {
            write-SDNExpressLog "Install-NetworkControllerOnFailoverCluster using cert by subject name $($RestName)"

            Install-NetworkControllerOnFailoverCluster -PackagePath $FCNCBins `
                                                       -DatabasePath $FCNCDBs `
                                                       -RestIPAddress $RestIPAddress `
                                                       -ClientAuthentication None `
                                                       -ClusterAuthentication X509 `
                                                       -RestCertificateSubjectName $RestName `
                                                       -ClusterNetworkName $ClusterNetworkName `
                                                       -RestName $RESTName
        }
        else
        {
            write-SDNExpressLog "Install-NetworkControllerOnFailoverCluster using cert by thumbprint $($RESTCertThumbprint)"

            Install-NetworkControllerOnFailoverCluster -PackagePath $FCNCBins `
                                                       -DatabasePath $FCNCDBs `
                                                       -RestIPAddress $RestIPAddress `
                                                       -ClientAuthentication None `
                                                       -ClusterAuthentication X509 `
                                                       -RestCertificateThumbPrint $RESTCertThumbprint `
                                                       -ClusterNetworkName $ClusterNetworkName `
                                                       -RestName $RESTName
       }
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 90 -context $restname

    write-SDNExpressLog "Install-NetworkControllerOnFailoverCluster complete."
    Write-SDNExpressLog "Network Controller cluster creation complete."
    
    #Verify that SDN REST endpoint is working before returning
    Write-SDNExpressLog "Verifying Network Controller is operational."

    $dnsWorking = $true
    if (!($RESTName -as [IPAddress] -as [bool]))
    {
        $dnsServers = (Get-DnsClientServerAddress -AddressFamily ipv4).ServerAddresses | select -uniq

        foreach ($dns in $dnsServers)
        {
            $dnsResponse = $null
            $count = 0

            while (($dnsResponse -eq $null) -and ($count -lt 90)) {
                $dnsResponse = Resolve-DnsName -name $RESTName -Server $dns -ErrorAction Ignore
                if ($dnsResponse -eq $null) {
                   write-sdnexpresslog "No response from the DNS server. Sleeping for 20 seconds"
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
        [PSCredential] $Credential = $null,
        [bool] $UseCertBySubject = $false
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

    if ($UseCertBySubject)
    {
        $CredentialProperties.Type = "X509CertificateSubjectName"
        $CredentialProperties.Value = $NCHostCert.Subject
    }
    else
    {
        $CredentialProperties.Type = "X509Certificate"
        $CredentialProperties.Value = $NCHostCert.thumbprint
    }

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
        [string[]] $Servers = $null,
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
        $ServerObjects = $ServerObjects | ? {$_.properties.connections.managementaddresses -in $Servers}
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
        [String] $VMNetworkAdapterName = "",
        [int] $ProfileData = 1,
        [string] $InstanceId = "{$([Guid]::Empty)}",
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
            [int] $ProfileData,
            [String] $InstanceId
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
        $NcVendorId  = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"

        if ([string]::IsNullOREmpty($VMNetworkAdapterName))
        {
            $vnic = Get-VMNetworkAdapter -VMName $VMName
            if ($vnic.count -gt 1) {
                throw "More than one VNIC on VM.  Use VMNetworkAdapterName to specify which VNIC."
            }
        } else {
            $vnic = Get-VMNetworkAdapter -VMName $VMName -Name $VMNetworkAdapterName
        }

        $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vNic

        if ( $currentProfile -eq $null)
        {
            $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
        
            $portProfileDefaultSetting.SettingData.ProfileId = $InstanceId
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
            $currentProfile.SettingData.ProfileId = $InstanceId
            $currentProfile.SettingData.ProfileData = $ProfileData
            Set-VMSwitchExtensionPortFeature  -VMSwitchExtensionFeature $currentProfile  -VMNetworkAdapter $vNic | out-null
        }
    }    -ArgumentList $VMName, $VMNetworkAdapterName, $ProfileData, $InstanceId | Parse-RemoteOutput
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
        [ValidateScript({
            if ($_ -eq $null) { return $true }
            if ($_.StartsWith("https://")) { throw "The Rest Name must not start with https://" }
            return $true
        })]
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
        [String] $OperationID = "",
        [Parameter(Mandatory=$false)]
        [String[]] $NCNodes,
        [Parameter(Mandatory=$false)]
        [int] $port = 6645,
        [Bool] $IsFC = $false
    )

    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyInvocation.UnboundArguments -ParamSet $psCmdlet


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

    # Get a list of "other nodes in the cluster" for FCNC purposes
    if ($isFC) {
        $nodesInSdnCluster = Get-NodesInSDNCluster -ComputerName $ComputerName -uri $uri -CredentialParam $credentialParam
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
    
        $feature = get-windowsfeature RSAT-NetworkController
        if ($feature -ne $null) {
            write-verbose "Found RSAT-NetworkController role, adding it."
            add-windowsfeature "RSAT-NetworkController" | out-null
        }

        $feature = get-windowsfeature NetworkVirtualization
        if ($feature -ne $null) {
            write-verbose "Found network virtualization role, adding it."
            add-windowsfeature NetworkVirtualization -IncludeAllSubFeature -IncludeManagementTools -Restart | out-null
        }
    } | parse-remoteoutput

    if ($IsFC)
    {
        Enable-NetworkControllerOnFailoverClusterLoggingOnDevice -DeviceName $ComputerName -Device 'Server'
    }

    $NodeFQDN = invoke-command -ComputerName $ComputerName @CredentialParam {
        param(
            [String] $RestName,
            [String] $iDNSIPAddress,
            [String] $iDNSMacAddress,
            [String[]] $NCNodes,
            [String] $port
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        write-verbose "Setting registry keys and firewall."
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

        $connections = "ssl:$($RestName):6640","pssl:$($port)"
        write-verbose "Port: $($connections)"
        $peerCertCName = $RestName.ToUpper()
        $hostAgentCertCName = $NodeFQDN.ToUpper()

        Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000 | out-null
        
        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "Connections" -Value $connections -PropertyType "MultiString" -Force | out-null
        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "PeerCertificateCName" -Value $peerCertCName -PropertyType "String" -Force | out-null
        new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "HostAgentCertificateCName" -Value $hostAgentCertCName -PropertyType "String" -Force | out-null

        if ($null -ne $NCNodes) {
          # add Network Controller Nodes to reg key
          new-itemproperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\' -Name "NetworkControllerNodeNames" -Value $NCNodes -PropertyType "MultiString" -Force | out-null
        }

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
    } -ArgumentList $RestName, $iDNSIPAddress, $iDNSMacAddress, $NCNodes, $port | parse-remoteoutput

    write-sdnexpresslog "Create and return host certificate."

    try {
        [byte[]] $CertData = invoke-command -ComputerName $ComputerName @CredentialParam {
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            if ((Get-Module -name "SdnExpressModule") -ne $null) {
                Import-Module -name "SdnExpressModule"
                New-SdnExpressHostCertificate
            }
            else {
                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
                $cert = $null
                $certs = get-childitem "cert:\localmachine\my" `
                    | where-object {$_.Subject.ToUpper() -eq "CN=$($NodeFQDN)" } `
                    | where-object {$_.NotAfter -ge (get-date) } `
                    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"}} `
                    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"}} `
                    | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.4.1.311.95.1.1.1"}} `
                    | Sort-Object -Property NotAfter -Descending

                if ($certs -ne $null) {    
                    $cert = $certs[0]
                }
                else {
                    $certs = get-childitem "cert:\localmachine\my" `
                       | where-object {$_.Subject.ToUpper() -eq "CN=$($NodeFQDN)" } `
                       | where-object {$_.NotAfter -ge (get-date) } `
                       | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.1"}} `
                       | where-object {$_.EnhancedKeyUsageList | where-object {$_.ObjectId -eq "1.3.6.1.5.5.7.3.2"}} `
                       | Sort-Object -Property NotAfter -Descending

                    if ($certs -ne $null) {
                        $cert = $certs[0]
                    }
                }

                if ($cert -eq $null) {
                    write-verbose "Creating new host certificate." 
                    $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1")
                } else {
                    write-verbose "Existing certificate meets criteria. Exporting." 
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
            }
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

    if ($NCHostCert.Subject -eq $NCHostCert.Issuer) {
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
    }

    # Install host-to-host certs if needed for FCNC
    if ($IsFC) {
        write-verbose "Importing new server's certificate into Root store of other servers."
        # Install this host's cert onto all other hosts, and get their certs while we're there

        [byte[][]] $HostCerts = @()

        foreach ($node in $nodesInSdnCluster) {
            [byte[]] $returnedCert = invoke-command -ComputerName $node @CredentialParam {
                param(
                    [byte[]] $CertData,
                    [String] $funcDefGetSdnCert
                )

                function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certData)
                if ($cert.Issuer -eq $cert.Subject) {
                    $TempFile = New-TemporaryFile
                    Remove-Item $TempFile.FullName -Force

                    write-verbose "Importing newly added host certificate into Root store of " + $NodeFQDN
                    $CertData | set-content $TempFile.FullName -Encoding Byte
                    import-certificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" | out-null
                    Remove-Item $TempFile.FullName -Force
                }
                . ([ScriptBlock]::Create($funcDefGetSdnCert))
                $Cert = GetSdnCert -subjectName $NodeFQDN

                #Only export if the cert is self signed
                if ($Cert.Issuer -eq $Cert.Subject) {
                    write-verbose "Exporting host certificate for $($NodeFQDN)"

                    $TempFile = New-TemporaryFile
                    Remove-Item $TempFile.FullName -Force | out-null
                    Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $cert | out-null

                    $HostCertData = Get-Content $TempFile.FullName -Encoding Byte
                    Remove-Item $TempFile.FullName -Force | out-null

                    write-output $HostCertData
                } else {
                    write-verbose "Skipping host certificate export for $($NodeFQDN), cert not self signed"
                }
            } -ArgumentList ($CertData, $Global:fdGetSdnCert) | parse-remoteoutput
            $hostCerts += ,$returnedCert
        }

        # Install all other non-selfsigned host's certs onto this host
        write-verbose "Importing all other self signed server's certificates into Root store of new server."

        foreach($hostCert in $hostCerts) {
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
            } -ArgumentList (,$HostCert) | parse-remoteoutput
        }
    }

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
    $ServerProperties.Connections[0].Port = $port

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

    if( Test-Path variable:\pscmdlet) {
        if($null -ne $pscmdlet) {
            write-SDNExpressLog "ParameterSet: $($paramset.ParameterSetName)"
        }
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


function IPv4toUInt32 {
    param(
        [string] $ip
    )
    $b = ([ipaddress]$ip).GetAddressBytes()
    [array]::Reverse($b)
    return [bitconverter]::ToUInt32($b,0)
 }
 
 function UInt32toIPv4 {
    param(
        [UInt32] $ip
    )

    $b = [bitconverter]::GetBytes($ip)
    [array]::Reverse($b)
    return ([ipaddress]$b).IPAddressToString
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
        [Int] $Timeout = 1800  # 30 minutes
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
                try {
                    $ps = new-pssession -computername $Computer @CredentialParam -ErrorAction Stop
                }
                catch {
                    write-sdnexpresslog "Unable to create PowerShell session on $Computer : $($_.Exception.Message)"
                }
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
        [String] $PAMacAddress = "",  
        [String] $LocalPeerIP,
        [String] $MuxASN,
        [Object] $Routers,
        [String] $PAGateway = "",
        [PSCredential] $Credential = $null,
        [Bool] $IsFC = $false
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
            [String] $LocalPeerIP,
            [String] $PAGateway,
            [String[]] $PASubnets
        )
        
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
        function private:IPv4toUInt32 {
            param( [string] $ip)
            $b = ([ipaddress]$ip).GetAddressBytes()
            [array]::Reverse($b)
            return [bitconverter]::ToUInt32($b,0)
         }
         
        function private:UInt32toIPv4 {
        param( [UInt32] $ip )
    
        $b = [bitconverter]::GetBytes($ip)
        [array]::Reverse($b)
        return ([ipaddress]$b).IPAddressToString
        }

        $ipa = get-netipaddress -ipaddress $LocalPeerIP
        $nic = Get-NetAdapter -interfaceindex $ipa.interfaceindex -ErrorAction Ignore

        if ($nic -eq $null)
        {
            throw "No adapter with LocalPeer/PA IP address $LocalPeerIP found"
        }

        if (![String]::IsNullOrEmpty($PAGateway)) {
            $subnetprefix = UInt32toIPv4 ((IPv4toUInt32 $ipa.ipaddress) -shr (32-$ipa.prefixlength) -shl (32-$ipa.prefixlength))
            $subnetprefix = "$subnetprefix/$($ipa.prefixlength)"

            foreach ($PASubnet in $PASubnets) {
                if ($pasubnet -ne $subnetprefix) {
                    remove-netroute -DestinationPrefix $PASubnet -InterfaceIndex $nic.ifIndex -Confirm:$false -erroraction ignore | out-null
                    new-netroute -DestinationPrefix $PASubnet -InterfaceIndex $nic.ifIndex -NextHop $PAGateway  -erroraction ignore | out-null
            
                }
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
    } -argumentlist $LocalPeerIP, $PAGateway, $PASubnets | parse-remoteoutput
    
    WaitforComputerToBeReady -ComputerName $ComputerName -CheckPendingReboot @CredentialParam

    if ($IsFC)
    {
        Enable-NetworkControllerOnFailoverClusterLoggingOnDevice -DeviceName $ComputerName -Device 'Mux'
    }

    $MuxFQDN = invoke-command -computername $ComputerName @CredentialParam {
            Return (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    }

    #wait for computer to restart.
    
    $CertData = invoke-command -computername $ComputerName @CredentialParam {
       param(
               [String] $funcDefGetSdnCert
            )

        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        write-verbose "Creating self signed certificate...";

        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

        . ([ScriptBlock]::Create($funcDefGetSdnCert))
        $Cert = GetSdnCert -subjectName $NodeFQDN
        if ($cert -eq $null) {
            $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1")
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
    } -ArgumentList $Global:fdGetSdnCert | Parse-RemoteOutput

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force | out-null
    Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $NCHostCert | out-null
    $NCHostCertData = Get-Content $TempFile.FullName -Encoding Byte
    Remove-Item $TempFile.FullName -Force | out-null

    if ($NCHostCert.Issuer -eq $NCHostCert.Subject) { 
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
    }

    $vmguid = invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $RestName,
            [String] $funcDefGetSdnCert
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
        
        . ([ScriptBlock]::Create($funcDefGetSdnCert))
        $Cert = GetSdnCert -subjectName $NodeFQDN        
        
        write-output "RestName $($RestName) NodeFQDN $($NodeFQDN) Thumbprint $($Cert.Thumbprint)"

        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Force -Name SlbmThumb -PropertyType String -Value $RestName | out-null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Force -Name MuxCert -PropertyType String -Value $NodeFQDN | out-null

        Get-ChildItem -Path WSMan:\localhost\Listener | where-object {$_.Keys.Contains("Transport=HTTPS") } | Remove-Item -Recurse -Force | out-null
        New-Item -Path WSMan:\localhost\Listener -Address * -HostName $NodeFQDN -Transport HTTPS -CertificateThumbPrint $cert.Thumbprint -Force | out-null

        Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule | out-null

        start-service slbmux | out-null

        write-output (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid
    } -ArgumentList $RestName, $Global:fdGetSdnCert | parse-remoteoutput

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
        [String] $GrePoolStart = $null,
        [Parameter(Mandatory=$false,ParameterSetName="TypeGre")]
        [String] $GrePoolEnd = $null,
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
        if ([string]::IsNullOrEmpty($grePoolStart)) { 
            $GrePoolStart = (Get-IPAddressInSubnet -subnet $GreSubnetAddressPrefix -offset 1)
        }
        if ([string]::IsNullOrEmpty($grePoolEnd)) { 
            $GrePoolEnd = (Get-IPLastAddressInSubnet -subnet $GreSubnetAddressPrefix)
        }

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
    } elseif ($IsTypeForwarding) {
        $GatewayPoolProperties.Type = "Forwarding"
    }

    $GWPoolObject = new-networkcontrollergatewaypool -connectionURI $URI -ResourceId $PoolName -Properties $GatewayPoolProperties -Force @CredentialParam -passinnerexception
    write-sdnexpresslog "New-SDNExpressGatewayPool Exit"
}


 ###                                                       #####  ######  #     # #######                                            #####                                          
  #  #    # # ##### #   ##   #      # ###### ######       #     # #     # ##    # #       #    # #####  #####  ######  ####   ####  #     #   ##   ##### ###### #    #   ##   #   # 
  #  ##   # #   #   #  #  #  #      #     #  #            #       #     # # #   # #        #  #  #    # #    # #      #      #      #        #  #    #   #      #    #  #  #   # #  
  #  # #  # #   #   # #    # #      #    #   #####  #####  #####  #     # #  #  # #####     ##   #    # #    # #####   ####   ####  #  #### #    #   #   #####  #    # #    #   #   
  #  #  # # #   #   # ###### #      #   #    #                  # #     # #   # # #         ##   #####  #####  #           #      # #     # ######   #   #      # ## # ######   #   
  #  #   ## #   #   # #    # #      #  #     #            #     # #     # #    ## #        #  #  #      #   #  #      #    # #    # #     # #    #   #   #      ##  ## #    #   #   
 ### #    # #   #   # #    # ###### # ###### ######        #####  ######  #     # ####### #    # #      #    # ######  ####   ####   #####  #    #   #   ###### #    # #    #   #   
 
function Initialize-SDNExpressGateway {
    [cmdletbinding(DefaultParameterSetName="Default")]
    param(
        [String] $RestName,
        [string] $ComputerName,
        [string] $JoinDomain,  
        [string] $HostName,
        [String] $FrontEndLogicalNetworkName = "HNVPA",  
        [String] $FrontEndAddressPrefix,
        [PSCredential] $Credential = $null
    )
    Write-SDNExpressLogFunction -FunctionName $MyInvocation.MyCommand.Name -boundparameters $psboundparameters -UnboundArguments $MyINvocation.UnboundArguments -ParamSet $psCmdlet

    if ($null -eq $Credential) {
        $CredentialParam = @{ }
    } else {
        $CredentialParam = @{ Credential = $credential}
    }

    $uri = "https://$RestName"    

    $GatewayFQDN = "$computername.$JoinDomain"

    $LogicalSubnet = get-networkcontrollerlogicalSubnet -LogicalNetworkId $FrontEndLogicalNetworkName -ConnectionURI $uri @CredentialParam
    $LogicalSubnet = $LogicalSubnet | where-object {$_.properties.AddressPrefix -eq $FrontEndAddressPrefix }

    write-sdnexpresslog "Found logical subnet $($logicalsubnet.resourceid)"

    $backendNic = $null
    try { $backendNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($GatewayFQDN)_BackEnd"  } catch { }
    if (!$backendNic) {
        write-sdnexpresslog "Creating backend NIC"
        $NicProperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
        $NicProperties.privateMacAllocationMethod = "Dynamic"
        $BackEndNic = new-networkcontrollernetworkinterface -connectionuri $uri @CredentialParam -ResourceId "$($GatewayFQDN)_BackEnd" -Properties $NicProperties -force -passinnerexception

        while ($backendNic.Properties.ProvisioningState -ne "Succeeded" -and $backendnic.Properties.ProvisioningState -ne "Failed") {
            $backendNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($GatewayFQDN)_BackEnd"
        }
    }

    write-sdnexpresslog "Backend MAC Address is $($BackendNic.properties.PrivateMacAddress)"

    $frontendNic = $null
    try { $frontendNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($GatewayFQDN)_FrontEnd"  } catch { }
    if (!$frontendNic) {
        write-sdnexpresslog "Creating frontend NIC"
        $NicProperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
        $NicProperties.privateMacAllocationMethod = "Dynamic"
        $NicProperties.IPConfigurations = @()
        $NicProperties.IPConfigurations += new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
        $NicProperties.IPConfigurations[0].ResourceId = "FrontEnd" 
        $NicProperties.IPConfigurations[0].Properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
        $NicProperties.IPConfigurations[0].Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
        $nicProperties.IpConfigurations[0].Properties.Subnet.ResourceRef = $LogicalSubnet.ResourceRef
        $NicProperties.IPConfigurations[0].Properties.PrivateIPAllocationMethod = "Dynamic"
        $FrontEndNic = new-networkcontrollernetworkinterface -connectionuri $uri @CredentialParam -ResourceId "$($GatewayFQDN)_FrontEnd" -Properties $NicProperties -force -passinnerexception

        while ($frontendNic.Properties.ProvisioningState -ne "Succeeded" -and $frontendNic.Properties.ProvisioningState -ne "Failed") {
            $frontendNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($GatewayFQDN)_FrontEnd"
        }
    }

    write-sdnexpresslog "Frontend IP Address is [$($frontendNic.properties.IPConfigurations[0].Properties.PrivateIPAddress)]"
    write-sdnexpresslog "Frontend MAC Address is $($FrontendNic.properties.PrivateMacAddress)"
    
    if ([string]::IsNullOrEmpty($frontendNic.properties.IPConfigurations[0].Properties.PrivateIPAddress)) {
        #need to find an address that is not in use
        $ips = @()

        #1 - get-pacamapping from a host to find PAs and add to list of IPs to not use
        $PACAIps = invoke-command -computername $hostname {
            ((get-pacamapping) | select-object 'PA IP Address').'PA IP Address'
        }

        if ($null -ne $PACAIps) {
            $ips += $PACAIps
        }

        #2 - get network interfaces and reservations from subnet so we know which IPs to skip over
        foreach ($ipconfig in $logicalsubnet.properties.ipconfigurations) {
            $ipconfig = get-networkcontrollernetworkinterfaceipconfiguration -connectionuri $uri @CredentialParam -NetworkInterfaceId $ipconfig.resourceRef.split('/')[2] -ResourceId $ipconfig.resourceRef.split('/')[4]
            if (![string]::IsNullOrEmpty($ipconfig.properties.privateipaddress)) {
                $ips += $ipconfig.properties.privateipaddress
            }
        }

        # Reserved IP addresses aren't in a IP configuration, but we still shouldn't use them for our front end IP - skip over
        foreach ($res in $logicalsubnet.Properties.IpReservations) {
            $res = get-networkcontrollerIpReservation -connectionUri $uri @CredentialParam -NetworkId $FrontEndLogicalNetworkName -SubnetId $LogicalSubnet.resourceId
            if (![string]::IsNullOrEmpty($res.properties.reservedAddresses)) {
                write-sdnexpresslog "Appending IP $($res.properties.reservedAddresses)"
                $ips += $res.properties.reservedAddresses
            }
        }
        
        $lastIPString = Get-IPLastAddressInSubnet $logicalsubnet.properties.addressprefix
        $firstIPString = get-ipaddressinsubnet $logicalsubnet.properties.addressprefix 1

        write-sdnexpresslog "Last IP in PA subnet: $lastipstring"
        #3 - convert to numbers and put in sorted array
        $lastIP = IPv4toUInt32 $lastIPString
        write-sdnexpresslog "First IP in PA subnet: $firstipstring"
        $firstIP = IPv4toUInt32 $firstIPString

        $intips = @()
        foreach ($ip in $ips) {
            write-sdnexpresslog "Checking IP : $ip"
            $checkIP = IPv4toUInt32 $ip

            if ($checkIP -ge $firstIP -and $checkip -lt $lastip) {
                $intIPs += $checkIP
            }
        }

        $ips = $intips | Sort-Object -Unique 

        #4 - iterate to find an unused address
        $useaddress = $null

        foreach ($ipp in $logicalsubnet.properties.ippools) {
            write-sdnexpresslog "Checking Pool range : $($ipp.properties.startipaddress) - $($ipp.properties.endipaddress))"
            $PoolStart = IPv4toUInt32 $ipp.properties.startipaddress
            $PoolEnd = IPv4toUInt32 $ipp.properties.endipaddress

            for ($i = $PoolEnd; $i -ge $PoolStart; $i--) {
                if (!($i -in $ips)) {
                    write-sdnexpresslog "Address match : $i"
                    $useaddress = UInt32ToIPv4 $i
                    break
                }
            }

            if ($useaddress) {
                write-sdnexpresslog "Updating frontend NIC to IP: $UseAddress"
                #5 - set static address on network interface
                $frontendNic.properties.IPConfigurations[0].Properties.PrivateIPAddress = $UseAddress
                $frontendNic.properties.IPConfigurations[0].Properties.PrivateIPAllocationMethod = "Static"
                $FrontEndNic = new-networkcontrollernetworkinterface -connectionuri $uri @CredentialParam -ResourceId $frontendNic.Resourceid -Properties $frontendNic.properties -force -passinnerexception
                break
            }
        }

    } 

    write-sdnexpresslog "Initialize-sdnexpressgateway results:"

    $Result = @{
        'BackEndMac' = $BackendNic.properties.PrivateMacAddress;
        'FrontEndMac' = $FrontendNic.properties.PrivateMacAddress;
        'FrontEndIP' = $FrontendNic.properties.ipconfigurations[0].properties.privateIPAddress
    }

    write-sdnexpresslog "   BackEndMac: $($result.frontendmac)"
    write-sdnexpresslog "   FrontEndMac: $($result.backendmac)"
    write-sdnexpresslog "   FrontEndIP: $($result.frontendIP)"

    return $Result
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
        [String] $PAGateway = "",
        [String[]] $ManagementRoutes,
        [PSCredential] $Credential = $null,
        [Switch] $UseFastPath,
        [Bool] $IsFC = $false
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

    if ($IsFC)
    {
        Enable-NetworkControllerOnFailoverClusterLoggingOnDevice -DeviceName $ComputerName -Device 'Gateway'
    }

    $PASubnets = @()
    $LogicalNetworkObject = get-NetworkControllerLogicalNetwork -ConnectionURI $uri -ResourceID "HNVPA" -Credential $Credential

    $PASubnets += $LogicalNetworkObject.properties.subnets.properties.AddressPrefix
    foreach ($Router in $Routers) {
        $PASubnets += "$($Router.RouterIPAddress)/32"
    }


    invoke-command -computername $ComputerName @CredentialParam {
        param(
            [String] $FrontEndMac,
            [String] $BackEndMac,
            [String[]] $ManagementRoutes,
            [String] $PAGateway,
            [String[]] $PASubnets
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

        Start-Sleep 10

        write-verbose "Configure Managment Routes"
        if($ManagementRoutes -ne $null) {
            $mgmtNicIndex = (Get-NetAdapter | WHERE { $_.Name -ne "Internal" -AND $_.Name -ne "External"} ).ifIndex
            [string] $mgmtNextHop = (Get-NetRoute -InterfaceIndex $mgmtNicIndex | where {$_.DestinationPrefix -eq '0.0.0.0/0'} | select NextHop).NextHop
            foreach($route in $ManagementRoutes) {
                write-verbose "new-netroute -DestinationPrefix $($route) -InterfaceIndex $($mgmtNicIndex) -NextHop $($mgmtNextHop) -erroraction ignore"
                new-netroute -DestinationPrefix $route -InterfaceIndex $mgmtNicIndex -NextHop $mgmtNextHop -erroraction ignore | out-null
            }
            write-verbose "remove-netroute -DestinationPrefix 0.0.0.0/0 -InterfaceIndex $($mgmtNicIndex) -Confirm:$false -erroraction ignore"
            remove-netroute -DestinationPrefix 0.0.0.0/0 -InterfaceIndex $mgmtNicIndex -Confirm:$false -erroraction ignore
            Start-Sleep 10

            $externalNicIndex = (Get-NetAdapter | where { $_.MacAddress -eq $FrontEndMac } ).ifIndex
            if (![String]::IsNullOrEmpty($PAGateway)) {
                foreach ($PASubnet in $PASubnets) {
                   write-verbose "new-netroute -DestinationPrefix $($PASubnet ) -InterfaceIndex $($externalNicIndex) -NextHop $($PAGateway) -erroraction ignore"
                   remove-netroute -DestinationPrefix $PASubnet -InterfaceIndex $externalNicIndex -Confirm:$false -erroraction ignore | out-null
                   new-netroute -DestinationPrefix $PASubnet -InterfaceIndex $externalNicIndex -NextHop $PAGateway  -erroraction ignore | out-null
                }
                Start-Sleep 10
            }
        }

        $RemoteAccess = get-RemoteAccess
        if ($RemoteAccess -eq $null -or $RemoteAccess.VpnMultiTenancyStatus -ne "Installed")
        {
            write-verbose "Enabling remote access multi-tenancy"
            Install-RemoteAccess -MultiTenancy | out-null
        } else {
            write-verbose "Remote Access multi-tenancy already enabled."
        }

        Get-Netfirewallrule -Group "@%SystemRoot%\system32\firewallapi.dll,-36902" | Enable-NetFirewallRule

        if ($UseFastPath) {
            $GatewayService = get-service GatewayService -erroraction Ignore
            if ($gatewayservice -ne $null) {
                write-verbose "Enabling gateway service."
                Set-Service -Name GatewayService -StartupType Automatic | out-null
                Start-Service -Name GatewayService  | out-null
            }
        }
    } -ArgumentList $FrontEndMac, $BackEndMac, $ManagementRoutes,$PAGateway, $PASubnets | Parse-RemoteOutput

    write-sdnexpresslog "Configuring certificates."

    $GatewayFQDN = invoke-command -computername $ComputerName @CredentialParam {
        Return (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain
    }

    $vmGuid = invoke-command -computername $ComputerName @CredentialParam {
        return (get-childitem -Path "HKLM:\software\microsoft\virtual machine\guest" | get-itemproperty).virtualmachineid
    }

    invoke-command -computername $ComputerName @CredentialParam {
        $raService = get-service RemoteAccess -erroraction Ignore

        if ($raService -ne $null) {
           # PS versions before 6.0 do not make a distinction between automatic and automatic delayed, need to use sc.exe 
           # auto start for remoteaccess removes at least one minute of delay in making the GW ready after reboot
           if ($raService.StartType -eq "Automatic") {
               sc.exe config remoteaccess start=auto | out-null;
               sc.exe config sstpsvc start=auto | out-null;
           }
        }
    }

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force | out-null
    Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $NCHostCert | out-null
    $NCHostCertData = Get-Content $TempFile.FullName -Encoding Byte
    Remove-Item $TempFile.FullName -Force | out-null

    # Only self signed cert may be imported in root
    if ($NCHostCert.Subect -eq $NCHostCert.Issuer)
    {
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
    }
    write-sdnexpresslog "Adding Network Interfaces to network controller."

    # Get-VMNetworkAdapter returns MacAddresses without hyphens '-'.  NetworkInterface prefers without hyphens also.

    $FrontEndMac = [regex]::matches($FrontEndMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join ""
    $BackEndMac = [regex]::matches($BackEndMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join ""
    
    $LogicalSubnet = get-networkcontrollerlogicalSubnet -LogicalNetworkId $FrontEndLogicalNetworkName -ConnectionURI $uri @CredentialParam
    $LogicalSubnet = $LogicalSubnet | where-object {$_.properties.AddressPrefix -eq $FrontEndAddressPrefix }

    try { 
        $BackEndNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($GatewayFQDN)_BackEnd"  
    } catch { 
        $NicProperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
        $nicproperties.PrivateMacAddress = $BackEndMac
        $NicProperties.privateMacAllocationMethod = "Static"
        $BackEndNic = new-networkcontrollernetworkinterface -connectionuri $uri @CredentialParam -ResourceId "$($GatewayFQDN)_BackEnd" -Properties $NicProperties -force -passinnerexception
    }

    try { 
        $FrontEndNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($GatewayFQDN)_FrontEnd"  
    } catch { 
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
    }

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

    $LocalVMTempPath = "$vmLocation\Temp\$VMName"
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
    $VHDTempVMPath = "$LocalVMTempPath\$VHDName"

    write-sdnexpresslog "Checking for previously mounted image."

    $mounted = get-WindowsImage -Mounted
    foreach ($mount in $mounted) 
    {
        if ($mount.ImagePath -eq $VHDTempVMPath) {
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
            If (-not (Test-Path -Path $VMLocation)) {
                throw "$($VMLocation) should exist, but doesn't"
            }
            get-SmbShare -Name VMShare -ErrorAction Ignore | remove-SMBShare -Force
            New-SmbShare -Name VMShare -Path $VMLocation -FullAccess $UserName -Temporary | out-null
        } -ArgumentList $VHDLocation, ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 50 -context $VMName
    
    $Generation = 1
    if (($VHDName).EndsWith('vhdx')) {
      $Generation = 2 # if a vhdx is provided, create a generation 2 vm, otherwise create a generation 1 vm
    }
    
    write-sdnexpresslog "Creating VM directory and copying VHD.  This may take a few minutes."
    write-sdnexpresslog "Copy from $VHDFullPath to $LocalVMTempPath"

    New-Item -ItemType Directory -Force -Path $LocalVMTempPath | out-null
    if (Test-Path -Path $VHDFullPath) {
        Write-SDNExpressLog "$($VHDFullPath) exists, copying can continue"
    } else {
        Write-SDNExpressLog "$($VHDFullPath) doesn't appear to exist.  This is needed to setup SDN."
        throw "Failed to find $($VHDFullPath)"
    }

    try {
        robocopy $VHDSrcPath $LocalVMTempPath $VHDName /R:10 /W:30 /V /NP

        Write-SDNExpressLog "Robocopy ExitCode: $($LastExitCode)"

        $destVHDName = "$LocalVMTempPath\$VHDName"
        if (Test-Path $destVHDName) {
            Write-SDNExpressLog "$($destVHDName) was found"
        }
        else {
            throw "File copy didn't appear to work.  $($destVHDName) was not found"
        }
    } catch {
        Write-SDNExpressLog "Failed to copy VHD.  Exception Message: "
        Write-SDNExpressLog $_
        throw "Copy of $($VHDFullPath) to $($LocalVMTempPath) failed"
    }
    
    write-sdnexpresslog "Creating mount directory and mounting VHD."

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $MountPath = $TempFile.FullName

    New-Item -ItemType Directory -Force -Path $MountPath

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 60 -context $VMName

    New-Item -ItemType Directory -Force -Path $VMPath | out-null
    copy-item -Path $VHDFullPath -Destination $VMPath | out-null

    write-sdnexpresslog "Creating mount directory and mounting VHD."

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $MountPath = $TempFile.FullName

    New-Item -ItemType Directory -Force -Path $MountPath | out-null

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 60 -context $VMName

    write-sdnexpresslog "Creating VM: $computername"
    try 
    {
        invoke-command -ComputerName $ComputerName  @CredentialParam -ScriptBlock {
            param(
                [String] $VMName,
                [String] $LocalVMPath,
                [Int64] $VMMemory,
                [Int] $VMProcessorCount,
                [String] $SwitchName,
                [Object] $Nics
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            write-verbose "Creating VM $VMName in $LocalVMPath."
            #note: we'll add the VHDX later after we customize it
            if (![string]::IsNullOrEmpty($nics[0].switchname)) {
                $FirstSwitch = $Nics[0].SwitchName
            } else {
                $FirstSwitch = $SwitchName
            }
            write-verbose "Creating Generation $using:Generation VM $VMName Switch $FirstSwitch with Memory $VMMemory and VHD to be added later $using:VHDName."
            $NewVM = New-VM -Generation $using:Generation -Name $VMName -Path $LocalVMPath -MemoryStartupBytes $VMMemory -novhd -SwitchName $FirstSwitch
            write-verbose "Setting processor count to $VMProcessorCount."
            $NewVM | Set-VM -processorcount $VMProcessorCount | out-null

            $first = $true
            foreach ($nic in $Nics) {
                if ($first) {
                    write-verbose "Configuring first network adapter."
                    $vnic = $NewVM | get-vmnetworkadapter 
                    $vnic | rename-vmnetworkadapter -newname $Nic.Name
                    $first = $false
                } else {
                    write-verbose "Configuring additional network adapters."
                    if (![string]::IsNullOrEmpty($nic.switchname)) {
                        $UseSwitch = $Nic.SwitchName
                    } else {
                        $UseSwitch = $SwitchName
                    }
                    #Note: add-vmnetworkadapter doesn't actually return the vnic object for some reason which is why this does a get immediately after.
                    $NewVM | Add-VMNetworkAdapter -SwitchName $UseSwitch -Name $Nic.Name | out-null
                    $vnic = $NewVM | get-vmnetworkadapter -Name $Nic.Name  
                }

                if (![string]::IsNullOrempty($nic.MacAddress)) {
                    $FormattedMac = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
                    write-verbose "Configuring mac address as: $formattedmac from $nic.MacAddress"
                    $vnic | Set-vmnetworkadapter -StaticMacAddress $FormattedMac
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
                            
            #Start, then immediately stop the VM in order to allocate dynamic mac addresses
            $NewVM | Start-VM | out-null
            $newVM | stop-vm -turnoff -force | out-null

        } -ArgumentList $VMName, $LocalVMPath, $VMMemory, $VMProcessorCount, $SwitchName, $Nics | Parse-RemoteOutput
                
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

    write-sdnexpresslog "Generating unattend.xml"

    $count = 1
    $TCPIPInterfaces = ""
    $dnsinterfaces = ""
    $dnssection = ""

    foreach ($nic in $Nics) {
        
        write-host "NIC: $nic"

        $vmMacAddress = invoke-command -ComputerName $ComputerName  @CredentialParam -ScriptBlock {
            param(
                [String] $VMName,
                [String] $NicName
            )
            function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

            write-verbose "Getting MAC address for VM $VMName NIC $NicName."
            $vnic = get-vmnetworkadapter -vmname $VMName -vmnetworkadaptername $NicName
            write-output ($vnic.macaddress)
        } -ArgumentList $VMName, $Nic.Name | Parse-RemoteOutput

        write-sdnexpresslog "Done nic processing"
        write-sdnexpresslog "MAC: $vmMacAddress"

        $MacAddress = [regex]::matches($vmMacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"

        write-verbose "Formatted Mac Address is: $macaddress"
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

                if ($Nic.DNS.count -gt 0) {
                    $dnsregistration = "true"
                }
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
            <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
               <RunSynchronous>
                  <RunSynchronousCommand wcm:action="add">
                     <Description>Add AlwaysExpecteDomainController RegKey</Description>
                     <Order>1</Order>
                     <Path>cmd /c reg add HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters /v AlwaysExpectDomainController /t REG_DWORD /d 255 /f</Path>
                  </RunSynchronousCommand>
               </RunSynchronous>
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
        $WindowsImage = Mount-WindowsImage -ImagePath $VHDTempVMPath -Index 1 -path $MountPath

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

Function Test-Endpoint($endpoint)
{
    Write-Host "Testing ICMP to $($endpoint)"
    [int]$retries = 5
    while($retries -gt 0)
    {
        $retries--
        if(Test-Connection $endpoint -quiet)
        {
            Write-Host "ICMP to $($endpoint) Successful"
            return $true
        }
        Write-Host "ICMP to $($endpoint) Failed.  Retries left $($retries)"
        Start-Sleep 5

    }
    return $false

}

new-eventlog -logname "Application" -source "SDNExpress" -ErrorAction SilentlyContinue
Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "NetworkCategory check." -ErrorAction SilentlyContinue 

$hopLine = Select-String -Path C:\unattend.xml -Pattern "NextHopAddress"
$defaultGateway = $hopLine.Line.Trim().Replace("<NextHopAddress>", "").Replace("</NextHopAddress>", "")
$dnsServerAddress = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses

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
    
    if(Test-Endpoint $defaultGateway -quiet)
    {
        Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Can Ping Default Gateway $($defaultGateway)" -ErrorAction SilentlyContinue 
    }
    else
    {
        Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Can Not Ping Default Gateway $($defaultGateway)" -ErrorAction SilentlyContinue 
    }

    foreach ($profile in $profiles) { 
        disable-netadapter -interfaceindex $profile.InterfaceIndex
        enable-netadapter -interfaceindex $profile.InterfaceIndex
    }

    foreach($dnsAddr in $dnsServerAddress)
    {
        if(Test-Endpoint $dnsAddr -quiet)
        {
            Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Can Ping DNS Server $($dnsAddr)" -ErrorAction SilentlyContinue 
        }
        else
        {
            Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Can Not Ping DNS Server $($dnsAddr)" -ErrorAction SilentlyContinue 
        }
    }

    $domainName = "TempDomainName"
 
    $testResult = Test-ComputerSecureChannel
    
    if($testResult -eq $true)
    {
        Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Test-ComputerSecureChannel results no problems with domain: $($domainName)" -ErrorAction SilentlyContinue     
    }
    else
    {
        Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Test-ComputerSecureChannel results failure with domain: $($domainName).  Running Repair" -ErrorAction SilentlyContinue

        $domainPswd = ConvertTo-SecureString "TempDomainPassword" -AsPlainText -Force
        $domainUser = "TempDomainUser"
        $domainCreds = New-Object System.Management.Automation.PSCredential ($domainUser, $domainPswd)
        
        $testResult = Test-ComputerSecureChannel -Repair -Server $domainName -Credential $domainCreds
        if($testResult -eq $true)
        {
            Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Test-ComputerSecureChannel repaired failure for domain $($domainName) as expected" -ErrorAction SilentlyContinue
        }
        else
        {
            Write-EventLog -LogName "Application" -Source "SDNExpress" -EventId 0 -Category 0 -EntryType Information -Message "Test-ComputerSecureChannel failed to repair failure for domain: $($domainName)." -ErrorAction SilentlyContinue
        }
        # Sleep to let repair complete
        Start-Sleep 15
    }

    foreach ($profile in $profiles)
    { 
        Get-NetAdapter -InterfaceIndex $profile.InterfaceIndex | Disable-NetAdapter -Confirm:$false
        Get-NetAdapter -InterfaceIndex $profile.InterfaceIndex | Enable-NetAdapter -Confirm:$false
    }
    Start-Sleep 60
}
'@
        $SetupCompletePS1File = $SetupCompletePS1File -replace "TempDomainPassword", $CredentialPassword
        $SetupCompletePS1File = $SetupCompletePS1File -replace "TempDomainUser", "$JoinDomain\$DomainAdminUserName"
        $SetupCompletePS1File = $SetupCompletePS1File -replace "TempDomainName", "$JoinDomain"
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
        $mountPathExists = Test-Path $MountPath
        $vhdPathExists = Test-Path $VHDTempVMPath

        if ($mountPathExists -and $vhdPathExists)
        {
            Write-SDNExpressLog "'$MountPath' and '$VHDTempVMPath' exists, now dismounting."
        }
        else {
            Write-SDNExpressLog "'$VHDVMPath' should be mounted at '$mountPath', but something doesn't exist.  VHDPath exists = '$vhdPathExists', Mountpoint exists = '$mountPathExists'"
            Write-SDNExpressLog "Trying DisMount-WindowsImage anyway."
        }

        # Sometimes dismount throws exception stating a file handle is still open.  Retrying to give any running process to close, releasing handle.
        $retryCount = 4

        while ($retryCount -gt 0)
        {
            try {
                DisMount-WindowsImage -Save -path $MountPath
                Write-SDNExpressLog "Dismount successful"
                break
            }
            catch
            {
                Write-SDNExpressLog "Dismount Failed"
                Write-SDNExpressLog $_.Exception.Message
                if ($retryCount -eq 1) {
                    throw $_.Exception
                }

                Write-SDNExpressLog "Retrying dismount (after sleep of 45 seconds)"
                $retryCount--
                Start-Sleep -Seconds 45
            }
        }
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 80 -context $VMName

    try {
        robocopy $LocalVMTempPath $VMPath $VHDName /R:10 /W:30 /V /NP

        $robocopyExitCode = $LastExitCode

        Write-SDNExpressLog "Robocopy ExitCode: $($LastExitCode)"

        $destVHDName = "$VMPath\$VHDName"
        if (Test-Path $destVHDName) {
            Write-SDNExpressLog "$($destVHDName) was found"
        }
        else {
            throw "File copy didn't appear to work.  $($destVHDName) was not found"
        }
    } catch {
        Write-SDNExpressLog "Failed to copy VHD.  Exception Message: "
        Write-SDNExpressLog $_
        throw "Copy of $($LocalVMTempPath) to $($VMPath) failed"
    }

    write-sdnexpresslog "Removing temp path"
    Remove-Item $LocalVMTempPath -Force -Recurse
    Remove-Item $MountPath -Force
    write-sdnexpresslog "removing smb share"
    Invoke-Command -computername $computername  @CredentialParam {
        Get-SmbShare -Name VMShare -ErrorAction Ignore | remove-SMBShare -Force | out-null
    }

    Write-LogProgress -OperationId $operationId -Source $MyInvocation.MyCommand.Name -Percent 90 -context $VMName

    invoke-command -ComputerName $ComputerName  @CredentialParam -ScriptBlock {
        param(
            [String] $VMName,
            [String] $VHDPath
        )
        function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
        function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

        write-verbose "Adding VHD $vhdpath to $vmname."
        $vm = get-vm $vmname
        $vm | add-vmharddiskdrive -path $vhdpath
        
        write-verbose "Making VHD first boot device."
        $vhdd = $vm | get-vmharddiskdrive
        if ($using:Generation -eq 2) {
          $vm | set-vmfirmware -firstbootdevice $vhdd
        }

        write-verbose "Starting VM $vmname."
        $vm | start-vm
    } -ArgumentList $VMName, $LocalVHDPath | Parse-RemoteOutput
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
    [int]$muxRetries = 10
    $muxSuccess = $false
    while($muxRetries -gt 0)
    {
        $muxes = get-networkcontrollerloadbalancermux @DefaultRestParams

        foreach ($mux in $muxes) {
            if($null -eq $mux.properties.configurationstate.status)
            {
                $muxRetries--
                break
            }
            else
            {
                write-sdnexpresslog "$($mux.ResourceId) status: $($mux.properties.configurationstate.status)"
                $muxRetries = 0
                $muxSuccess = $true
                break
            }
        }
        if($muxSuccess -eq $false)
        {
            write-sdnexpresslog "Unable to get Mux Status.  Waiting 30 seconds."
            $muxRetries--
            Start-Sleep 30
        }
    }
    if($muxSuccess -eq $false)
    {
        write-sdnexpresslog "Unable to get Mux Status"
    }
    write-sdnexpresslog "Gateway Status:"
    $gateways = get-networkcontrollergateway @DefaultRestParams
    foreach ($gateway in $gateways) {
        write-sdnexpresslog "$($gateway.ResourceId) status: $($gateway.properties.State), $($gateway.properties.HealthState)"
    }
}
function New-SdnExpressHostCertificate 
{
    param()

    function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
    function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}

    $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName+"."+(get-ciminstance win32_computersystem).Domain

    $cert = GetSdnCert -subjectName $NodeFQDN.ToUpper()
    if ($Cert -eq $Null) {
        write-verbose "Creating new host certificate." 
        $Cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1")
    } else {
        write-verbose "Existing certificate meets criteria. Exporting." 
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
}

Export-ModuleMember -Function New-SDNExpressVM
Export-ModuleMember -Function New-SDNExpressNetworkController
Export-ModuleMember -Function New-FCNCNetworkController
Export-ModuleMember -Function Add-SDNExpressHost
Export-ModuleMember -Function Add-SDNExpressMux
Export-ModuleMember -Function New-SDNExpressGatewayPool
Export-ModuleMember -Function New-SDNExpressGateway
Export-ModuleMember -Function Initialize-SDNExpressGateway

Export-ModuleMember -Function New-SDNExpressLoadBalancerManagerConfiguration
Export-ModuleMember -Function New-SDNExpressVirtualNetworkManagerConfiguration
Export-ModuleMember -Function New-SDNExpressiDNSConfiguration
Export-ModuleMember -Function Add-SDNExpressLoadBalancerVIPSubnet
Export-ModuleMember -Function Add-SDNExpressVirtualNetworkPASubnet

Export-ModuleMember -Function Test-SDNExpressHealth
Export-ModuleMember -Function Enable-SDNExpressVMPort

Export-ModuleMember -Function WaitForComputerToBeReady
Export-ModuleMember -Function Write-SDNExpressLog
Export-ModuleMember -Function Get-IPAddressInSubnet
Export-ModuleMember -Function Parse-RemoteOutput
Export-ModuleMember -Variable $Global:fdGetSdnCert
Export-ModuleMember -Function GetSdnCert
Export-ModuleMember -Function Write-SDNExpressLogFunction

