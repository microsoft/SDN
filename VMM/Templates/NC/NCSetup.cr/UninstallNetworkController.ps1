. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop";

# Exit Codes
$ErrorCode_Success = 0;
$ErrorCode_Failed = 1;

try
{    
    #------------------------------------------
    # Uninstall network controller
    #------------------------------------------
    $ncCluster = TryGetNetworkControllerCluster
    
    if($ncCluster -eq $null)
    {
        Log "No Network controller is configured for this machine. Exiting script.."
        Exit $ErrorCode_Success
    }
    else
    {
        # Removes both Network Controller and Network Controller Cluster from all nodes
        Log "Uninstalling the Network Controller and the Network Controller Cluster.."
        Uninstall-NetworkControllerCluster -Verbose -Force
    }
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


