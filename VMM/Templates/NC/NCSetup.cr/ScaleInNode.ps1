Param($mgmtDomainAccountUserName, $mgmtDomainAccountPassword, $RemainingVMInstanceCount);

. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop";

# Exit Codes
$ErrorCode_Success = 0;
$ErrorCode_Failed = 1;

try
{
    #------------------------------------------
    # Get network controller node info
    #------------------------------------------
    try
    {
        Log "Discovering existing NC nodes.."
        $ncNodes = Get-NetworkControllerNode
    }
    catch
    {
        Log "Existing Network Controller Nodes not found."
    }
    
    if($ncNodes -eq $null)
    {
        Log "No Network controller is configured for this machine. Exiting script.."
        Exit $ErrorCode_Success
    }
    else
    {
        #------------------------------------------
        # Find an on-line remote node.
        #------------------------------------------
        Log "Found existing nodes: $ncNodes"
        $node = $ncNodes | where{$_.Server.ToLower().Split(".")[0].Equals($env:COMPUTERNAME.ToLower())}
        $otherNodes = $ncNodes | where{-not $_.Equals($node)}
        $vmNames = $otherNodes.Server
        $remoteNodeName = TryGetNetworkControllerNodeRemote $vmNames $mgmtDomainAccountUserName $mgmtDomainAccountPassword
        
        if($remoteNodeName -eq $null)
        {
            Log "Warning: Could not establish a connection with any other node in the network controller."
            Log "    Unable to remove this node from the network controller."
            Exit $ErrorCode_Failed
        }
        
        #------------------------------------------
        # Remove myself from the existing Network Controller
        #------------------------------------------
        
        # credential to access the network controller
        $credential = CreateCredential $mgmtDomainAccountUserName $mgmtDomainAccountPassword
        
		#Remove the node only if we have more than 3 VMs, else it throws exception
		if($RemainingVMInstanceCount -gt 3)
		{
            # use a remote call to another node to remove this node
            Log "Removing node from network controller.."
            Log "    -Name: $($node.Name)"
            Log "    -ComputerName: $remoteNodeName"
            Log "    -Credential: $($credential.UserName)"
            Remove-NetworkControllerNode -Name $node.Name -ComputerName $remoteNodeName -Credential $credential -Force -Verbose
		}
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


