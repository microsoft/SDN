Param($serviceVMComputerNames, $mgmtSecurityGroupName, $clientSecurityGroupName, $restEndPoint, $mgmtDomainAccountUserName, $mgmtDomainAccountPassword, $diagnosticLogShare, $diagnosticLogShareUsername, $diagnosticLogSharePassword);

. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop";

# Exit Codes
$ErrorCode_Success = 0;
$ErrorCode_Failed = 1;

try
{        
    # Start the network controller cmdlet log collection
    StartNetworkControllerLogging
    
    # This machine has finished prep stages, so mark it as ready for NC
    MarkAsReadyForNetworkControllerDeployment
    
    # See if this node is already part of a NC deployment
    $ncController = TryGetNetworkController
    
    if($ncController -ne $null)
    {
        Log "Network Controller already configured, exiting.."
        Log "Completed execution of script."
        Exit $ErrorCode_Success   
    }
    
    # see if the NC already exists remotely. Should be expected during scale-out
    if(-not [String]::IsNullOrEmpty($restEndPoint))
    {
        Log "Checking if network controller exists remotely..";
		
        # In case of Rest IP, it will be provided in CIDR notation
        $restEndPointWithoutSubnet = $restEndPoint.Split("/")[0]
		
        $ncControllerRemote = Test-Connection $restEndPointWithoutSubnet -Quiet    
        if($ncControllerRemote)
        {
            Log "Network Controller already configured remotely, exiting.."
            Log "Completed execution of script."
            Exit $ErrorCode_Success   
        }
    }

    #------------------------------------------
    # Determine this VM's index in the service tier.
    # 0         : Install Network Controller on all nodes
    # 1-N       : Do nothing.
    # -1        : There was an error parsing the string
    #------------------------------------------
    [array]$vmNames = GetVMNamesFromComputerTierString $serviceVMComputerNames
    $indexInComputerTier = GetIndexFromComputerTierString $serviceVMComputerNames
    
    # Branch into different deployment steps based on the index of this VM
    if($indexInComputerTier -eq -1)
    {
        Log "There was a problem determining the deployment index of this VM."
        Exit $ErrorCode_Failed
    }
    
    if($indexInComputerTier -ge 1)
    {
        # This is the 2nd or 3rd+ VM in the tier. 
        # Do nothing, since the first VM in the tier will configure us.
        Log "This VM index is $indexInComputerTier, this VM will automatically be configured by the VM with the 0th index."
        Log "Completed execution of script."
        Exit $ErrorCode_Success
    }
    
    if($indexInComputerTier -eq 0)
    {        
        #------------------------------------------
        # Create Node Objects for each VM
        #------------------------------------------
        $nodes = @()
        Log "Constructing Node objects for all VMs.."
        foreach($vmName in $vmNames)
        {
            # wait for other nodes to catch up to this point
            WaitForReadyNode $vmName 20
            
            $fqdn = $([System.Net.Dns]::GetHostByName($vmName)).HostName
            $nicName = $(Get-NetAdapter).Name
            $fd = "fd:/$vmName"
            
            Log "Constructing node with parameters.."
            Log "    -Name: $vmName"
            Log "    -Server: $fqdn"
            Log "    -FaultDomain: $fd"
            Log "    -RestInterface: $nicName"
            $ncNode = New-NetworkControllerNodeObject -Name $vmName -Server $fqdn -FaultDomain $fd -RestInterface $nicName -Verbose
            $nodes += $ncNode
        }

        #------------------------------------------
        # Retrieve SSL certificate
        #------------------------------------------
        Log "Grabbing SSL Cert from personal store.."
        $sslThumbprint = GetSSLCertificateThumbprint
        $sslCertificate = Get-Item Cert:\LocalMachine\My | Get-ChildItem | where {$_.Thumbprint -eq $sslThumbprint}

        #------------------------------------------
        # Installation of Network Controller Cluster
        #------------------------------------------
        $ncCluster = TryGetNetworkControllerCluster
        
        if($ncCluster -eq $null)
        {
            $attempt = 1
            $maxRetry = 5
            $success = $false

            while($success -eq $false)
            {
                try
                {
                    $ncCluster = TryGetNetworkControllerCluster
                    if($ncCluster -ne $null)
                    {
                        Log "Found stale Network Controller Cluster. Removing..."
                        Uninstall-NetworkControllerCluster -Force -Verbose
                        Log "Removed existing Network Controller Cluster."
                    }

                    # SSL-enabled deployment 
                    if($diagnosticLogShare -ne $null -and $diagnosticLogShare.Length -gt 0)
                    {
                        $logCredential = $null
                        if( (-not [String]::IsNullOrEmpty($diagnosticLogShareUsername)) -and 
                            (-not [String]::IsNullOrEmpty($diagnosticLogSharePassword)) )
                        {
                            $logCredential = CreateCredential $diagnosticLogShareUsername $diagnosticLogSharePassword
                        }

                        Log "Installing NetworkControllerCluster with parameters.."
                        Log "    -ClusterAuthentication: Kerberos"
                        Log "    -ManagementSecurityGroup: $mgmtSecurityGroupName"
                        Log "    -Nodes: $($nodes.Name)"
                        Log "    -CredentialEncryptionCertificate: $($sslCertificate.Subject)"
                        Log "    -DiagnosticLogLocation: $diagnosticLogShare"
                        Log "    -LogLocationCredential: $($logCredential.UserName)"
                        Install-NetworkControllerCluster -ClusterAuthentication Kerberos -ManagementSecurityGroup $mgmtSecurityGroupName -Node $nodes -CredentialEncryptionCertificate $sslCertificate -DiagnosticLogLocation $diagnosticLogShare -LogLocationCredential $logCredential -Verbose 
                    }
                    else 
                    {
                        Log "Installing NetworkControllerCluster with parameters.."
                        Log "    -ClusterAuthentication: Kerberos"
                        Log "    -ManagementSecurityGroup: $mgmtSecurityGroupName"
                        Log "    -Nodes: $($nodes.Name)"
                        Log "    -CredentialEncryptionCertificate: $($sslCertificate.Subject)"
                        Install-NetworkControllerCluster -ClusterAuthentication Kerberos -ManagementSecurityGroup $mgmtSecurityGroupName -Node $nodes -CredentialEncryptionCertificate $sslCertificate -Verbose
                    }
                    $success = $true
                }
                catch
                {
                    Log "Attempt $attempt to Install-NetworkControllerCluster has failed."
                    if($attempt -le $maxRetry)
                    {
					    Log "Will attempt to install cluster again."
                        $attempt += 1
						Start-Sleep -Seconds (120 * $attempt)
						Log "Attempting to Install-NetworkControllerCluster."
                    }
                    else
                    {
                        throw $_.Exception
                    }
                }
            }
        }
        else
        {
            Log "NetworkControler Cluster already exists, skipping creation.."
        }
        
        Start-Sleep -Seconds 5
        
        #------------------------------------------
        # Installation of Network Controller
        #------------------------------------------
        $ncController = TryGetNetworkController

        # In case of Rest IP, it will be provided in CIDR notation
        $restEndPointWithoutSubnet = $restEndPoint.Split("/")[0]

        if($ncController -eq $null)
        {            
            if($vmNames.Length -gt 1)
            {
                # 3-node installation
				Log "Installing NetworkController with parameters.."
                Log "    -ClientAuthentication: Kerberos"
                Log "    -ClientSecurityGroup: $clientSecurityGroupName"
                Log "    -ServerCertificate: $($sslCertificate.Subject)"

                $restIP = $null;
                if([System.Net.IPAddress]::TryParse($restEndPointWithoutSubnet, [ref] $restIP))
                {
                    $restipSubnetLength = $restEndPoint.Split("/")[1]
                    if($restipSubnetLength -eq $null)
                    {
                        Log "Rest IP Subnet was not provided. Using Subnet from NC network adapter."
                        $restipSubnetLength = GetLocalHostIPv4Subnet
                        $restEndPoint = ($restEndPoint + "/" + $restipSubnetLength)
                    }

                    Log "    -RestIPAddress: $restEndPoint"
                    Install-NetworkController -Node $nodes -ClientAuthentication Kerberos -ClientSecurityGroup $clientSecurityGroupName -ServerCertificate $sslCertificate -RestIPAddress $restEndPoint -Verbose
                }
                else
                {
                    Log "    -RestName: $restEndPoint"
                    Install-NetworkController -Node $nodes -ClientAuthentication Kerberos -ClientSecurityGroup $clientSecurityGroupName -ServerCertificate $sslCertificate -RestName $restEndPoint -Verbose
                }
            }
            else 
            {
                # standalone installation
                Log "Installing NetworkController with parameters.."
                Log "    -ClientAuthentication: Kerberos"
                Log "    -ClientSecurityGroup: $clientSecurityGroupName"
                Log "    -ServerCertificate: $($sslCertificate.Subject)"
                Log "    -RestName: unused for one node deployment"
				Log "    -RestIP: unused for one node deployment"
                Install-NetworkController -Node $nodes -ClientAuthentication Kerberos -ClientSecurityGroup $clientSecurityGroupName -ServerCertificate $sslCertificate -Verbose 
            }
        }
        else
        {
            Log "NetworkControler already exists, skipping creation.."
        }
        
        # wait for NC services to come online.
        Start-Sleep -Seconds 60
        
        # turn off logging
        TryStopNetworkControllerLogging
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


