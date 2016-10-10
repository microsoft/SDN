Param($restEndPoint, $mgmtDomainAccountUserName, $mgmtDomainAccountPassword, $serviceVMComputerNames);

. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop";

# Exit Codes
$ErrorCode_Success = 0;
$ErrorCode_Failed = 1;

try
{
    #------------------------------------------
    # Check for standalone deployment
    #------------------------------------------
    [array]$vmNames = GetVMNamesFromComputerTierString $serviceVMComputerNames
    if($vmNames.Count -eq 1)
    {
        Log "Skipping Scale-Out for 1-node deployment.."
        Exit $ErrorCode_Success   
    }

    #------------------------------------------
    # Wait for network controller to be configured before proceeding
    #------------------------------------------
    WaitForNetworkController $restEndPoint

    #------------------------------------------
    # See if this node is already part of the network controller deployment
    #------------------------------------------
    $ncController = TryGetNetworkController
    
    if($ncController -ne $null)
    {
        Log "Network Controller already configured, exiting.."
        Log "Completed execution of script."
        Exit $ErrorCode_Success   
    }
    
    #------------------------------------------
    # Find an on-line remote node.
    #------------------------------------------
    $credential = CreateCredential $mgmtDomainAccountUserName $mgmtDomainAccountPassword
    [array]$vmNames = GetVMNamesFromComputerTierString $serviceVMComputerNames
    $remoteNodeName = TryGetNetworkControllerNodeRemote $vmNames $mgmtDomainAccountUserName $mgmtDomainAccountPassword
    
    if($remoteNodeName -eq $null)
    {
        Log "Warning: Could not establish a connection with any other node in the network controller."
        Log "    Unable to add this node to the network controller."
        Exit $ErrorCode_Failed
    }
    
    #------------------------------------------
    # Add myself as a node to the existing network controller
    #------------------------------------------
    $computerName = $env:computername
    $fqdn = $([System.Net.Dns]::GetHostByName($computerName)).HostName
    $nicName = $(Get-NetAdapter).Name
    $fd = "fd:/$computerName"
    
    Log "Adding node to existing network controller.."
    Log "    -Name: $computerName"
    Log "    -Server: $fqdn"
    Log "    -FaultDomain: $fd"
    Log "    -RestInterface: $nicName"
    Log "    -ComputerName: $remoteNodeName"
    Log "    -Credential: $($credential.UserName)"
    Add-NetworkControllerNode -Name $computerName -Server $fqdn -FaultDomain $fd -RestInterface $nicName -ComputerName $remoteNodeName -Credential $credential -Verbose
}
catch 
{
    Log "Caught an exception:";
    Log "    Exception Type: $($_.Exception.GetType().FullName)";
    Log "    Exception Message: $($_.Exception.Message)";
    Log "    Exception HResult: $($_.Exception.HResult)";
    Exit $($_.Exception.HResult);
}  

Log "Completed execution of script."
Exit $ErrorCode_Success   


