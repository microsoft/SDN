Param($serviceVMComputerNames, $mgmtDomainAccountUserName, $mgmtDomainAccountPassword, $mgmtSecurityGroupName, $clientSecurityGroupName, $restEndPoint, $diagnosticLogShare, $diagnosticLogShareUsername, $diagnosticLogSharePassword)

. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop"

# Exit Codes
$ErrorCode_Success = 0
$ErrorCode_Failed = 1

try 
{    
    #------------------------------------------
    # Get existing configuration
    #------------------------------------------
    $ncController = TryGetNetworkController
    
    if($ncController -eq $null)
    {
        Log "There was an error communicating with the network controller from node $($env:computername).."
        Exit $ErrorCode_Failed   
    }
    
    $ncCluster = TryGetNetworkControllerCluster
    
    if($ncCluster -eq $null)
    {
        Log "There was an error communicating with the network controller cluster from node $($env:computername).."
        Exit $ErrorCode_Success
    }
    
    #------------------------------------------
    # Find responsible node
    #------------------------------------------
    [array]$vmNames = GetVMNamesFromComputerTierString $serviceVMComputerNames
    
    Log "Finding who is responsible for servicing the network controller.."
    $isResponsible = $false
    foreach($vmName in $vmNames)
    {
        # if I'm the first on-line node, then I'm responsible
        $vmNameWithoutSuffix = $vmName.Split(".")[0]
        if($vmNameWithoutSuffix.ToLower() -eq $env:COMPUTERNAME.ToLower())
        {
            Log "This VM will be responsible for servicing."
            $isResponsible = $true
            break
        }
        
        # if there is a remote node that is on-line, then they are responsible
        $remoteNodeName = TryGetNetworkControllerNodeRemote $vmName $mgmtDomainAccountUserName $mgmtDomainAccountPassword
        if($remoteNodeName -ne $null)
        {
            Log "Remote node $remoteNodeName will be responsible for servicing the network controller."
            $isResponsible = $false
            break
        }
    }
    
    # if i'm not responsible, exit script
    if(-not $isResponsible)
    {
        Log "This VM is not responsible for servicing the network controller."
        Log "Completed execution of script."
        Exit $ErrorCode_Success
    }
    
    #------------------------------------------
    # Set Network Controller Cluster
    #------------------------------------------    
    # ignoring the following not supported by service template:
    # -CredentialEncryptionCertificate
    Log "Setting Network controller cluster parameters.."
    Log "    -ManagementSecurityGroup: $mgmtSecurityGroupName"
    Set-NetworkControllerCluster -ManagementSecurityGroup $mgmtSecurityGroupName -Verbose
    
    #------------------------------------------
    # Set Network Controller
    #------------------------------------------
    # ignoring the following not supported by service template:
    # -ServerCertificate
    if([System.String]::IsNullOrEmpty($restEndPoint))
    {
        Log "Setting Network controller parameters.."
        Log "    -ClientSecurityGroup: $clientSecurityGroupName"
        Set-NetworkController -ClientSecurityGroup $clientSecurityGroupName -Verbose
    }
    else
    {
        # In case of Rest IP, it will be provided in CIDR notation
        $restEndPointWithoutSubnet = $restEndPoint.Split("/")[0]

        Log "Setting Network controller parameters.."
        Log "    -ClientSecurityGroup: $clientSecurityGroupName"

        $restIP = $null;
        if([System.Net.IPAddress]::TryParse($restEndPointWithoutSubnet, [ref] $restIP))
        {
            Log "    -RestIPAddress: $restIP"
            Set-NetworkController -ClientSecurityGroup $clientSecurityGroupName -RestIPAddress $restIP -Verbose
        }
        else
        {
            Log "    -RestName: $restEndPoint"
            Set-NetworkController -ClientSecurityGroup $clientSecurityGroupName -RestName $restEndPoint -Verbose
        }
    }
    
    #------------------------------------------
    # Set Network Controller Diagnostics
    #------------------------------------------
    # log scope determines if whether application logs are enabled.
    # All = cluster + application logs are recorded
    # Cluster = only cluster logs are recorded
    $logScope = "All"
        
    if([System.String]::IsNullOrEmpty($diagnosticLogShare))
    {
        Log "Setting Network controller diagnostic parameters.."
        Log "    -UseLocalLogLocation"
        Log "    -LogScope: $logScope"
        Set-NetworkControllerDiagnostic -UseLocalLogLocation -LogScope $logScope
    }
    else
    {
        $logCredential = $null
        if( (-not [String]::IsNullOrEmpty($diagnosticLogShareUsername)) -and 
            (-not [String]::IsNullOrEmpty($diagnosticLogSharePassword)) )
        {
            $logCredential = CreateCredential $diagnosticLogShareUsername $diagnosticLogSharePassword
        }
                
        Log "Setting Network controller diagnostic parameters.."
        Log "    -DiagnosticLogLocation $diagnosticLogShare"
        Log "    -LogLocationCredential: $($logCredential.UserName)"
        Log "    -LogScope: $logScope"
        Set-NetworkControllerDiagnostic -DiagnosticLogLocation $diagnosticLogShare -LogLocationCredential $logCredential -LogScope $logScope
    }
}
catch 
{
    Log "Caught an exception:"
    Log "    Exception Type: $($_.Exception.GetType().FullName)"
    Log "    Exception Message: $($_.Exception.Message)"
    Log "    Exception HResult: $($_.Exception.HResult)"
    Exit $($_.Exception.HResult)
}  

Log "Completed execution of script."
Exit $ErrorCode_Success 