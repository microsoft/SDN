# library for common functions

# Import the module
if (-not (Get-Module Hyper-V))
{ 
    Import-Module Hyper-V -EA SilentlyContinue
}

# Writes to a log file if a path is given, else to stdout
function WriteOutput($Message, $LogPath="")
{
    $Message = Prepend-TimeStamp ($Message)
    if ($LogPath -ne "") {
        Out-File -InputObject $Message -FilePath $LogPath -Append
    } else {
        Write-Host $Message
        Write-Output $Message
    }
}

# Writes to a log file if a path is given, else to stdout
function LogAndThrow($Message, $LogPath="")
{
    Write-Output $Message $LogPath
    throw $Message
}

# Checks error code and exits if it is set
function CheckErrorAndExit([psobject]$Err, $LogPath="")
{
   if ($Err) {
       WriteOutput "$Err" $LogPath
       exit 1
   }
}

# Checks error code and throws the exception
function CheckErrorAndThrow([psobject]$Err, $LogPath="")
{
   if ($Err) {
       WriteOutput "$Err" $LogPath
       throw "Error occured: $Err"
   }
}

function Prepend-TimeStamp ($msg)
{
    $timeStamp = Get-Date -Format o
    $msg =$timeStamp + " : " + $msg
    return $msg
}

# Starts a VM if it is in stopped state
function StartVm([string]$VmName, $LogPath="")
{
    $vm = Get-VM -Name $VmName -EV Err -EA SilentlyContinue
    CheckErrorAndExit $Err $LogPath

    # If VM is not running, bring it up
    if ($vm.State -ne "Running") {
        WriteOutput "Starting vm $VmName" $LogPath
        Start-VM -Name $VmName -EV Err -EA SilentlyContinue
        CheckErrorAndExit $Err $LogPath
    }
}

# Stops a VM if it is in the running state
function StopVm([string]$VmName, $LogPath="")
{
    $vm = Get-VM -VmName $VmName -EV Err -EA SilentlyContinue
    CheckErrorAndExit $Err $LogPath
    if ($vm.State -eq "Running") {
        # VM may be booting up still and running; if so, wait for shutdown service
        $vmShutdown = Get-VmIntegrationService -VmName $VmName -Name Shutdown -EV Err -EA SilentlyContinue
        CheckErrorAndExit $Err $LogPath

        while ($vm.State -eq "Running" -and $vmShutdown.PrimaryStatusDescription -ne "OK") {
            WriteOutput ("VM current state is " + $vm.State + "; wait for 3 seconds") $LogPath
            Start-Sleep -s 3
        }

        Stop-VM -Name $VmName -Force -EV Err -EA SilentlyContinue
        CheckErrorAndExit $Err $LogPath
        
        while ($vm.State -eq "Running") {
            WriteOutput "VM current state is " + $vm.State + "; wait for 5 seconds" $LogPath
            Start-Sleep -s 5
        }
    }
}

# Waits for a vmNic's IP interfaces to come up, and optionally for a given IP address
function WaitForConnectivity([string]$VmName, [string]$NicName, [string]$IpAddr="*", $LogPath="") 
{
    StartVm $VmName $LogPath
    while ((Get-VmIntegrationService -VmName $VmName -Name Heartbeat).PrimaryStatusDescription -ne "OK") {
        WriteOutput "Waiting 3 seconds for OS" $LogPath
        Start-Sleep -s 3
    }

    $timeout = 300
    do {
        Start-Sleep -Seconds 3
        $timeout -= 3

        $ips = (Get-VMNetworkAdapter -Name $NicName -VmName $VmName).IpAddresses
        if ($ips -eq $null) { $ips = @() }
        WriteOutput "IP addresses: $ips" $LogPath

        $hasIps = $ips.Contains($IpAddr) -or ($IpAddr -eq "*" -and $ips.Count -gt 0)
    } until ($timeout -le 0 -or $hasIps)

    if (-not $hasIps) {
        WriteOutput "Timed out waiting for connectivity to $VmName" $LogPath
        exit 1
    } else {
        WriteOutput "IP address $IpAddr is up on the VM $VmName" $LogPath
    }
}

# Waits for the partition to be available
function WaitForVmPartitionToBeUp([string]$VmName, $LogPath="")
{
    [int]$TimeoutWaitingForInteractiveSession = 20
    $curTime = get-date
    $StopTime = $curTime.AddMinutes($TimeoutWaitingForInteractiveSession)

    $VmrtIsUp = $false
    $vmp = $null
    while($curTime -le $StopTime) {
        $vmp = Get-VMPartition -VMName $VmName -Timeout 1 -ErrorVariable Err -EA SilentlyContinue
        if ($? -and ![String]::IsNullOrWhiteSpace($vmp.MachineName)) {
            $VmrtIsUp = $true            
            break
        } else {
            WriteOutput "Guest vmrt service is not up yet.."
        }
        $curTime = get-date
    }

    if ($VmrtIsUp -eq $false) {
        WriteOutput "Failed to bring vm partition for $($VmName). Giving up and exiting..." 
        exit 1
    }
}

# Checks both error and process exit code
function CheckProcessErrorAndExit($Process, $Err, $LogPath="")
{
    CheckErrorAndExit $Err $LogPath
    if ($Process.ExitCode -ne 0) {
        WriteOutput ("Process failed with exit code " + $Process.ExitCode) $LogPath
        exit 1
    }
}

# Checks both error and process exit code
function CheckProcessErrorAndThrow($Process, $Err, $LogPath="")
{
    CheckErrorAndThrow $Err $LogPath
    if ($Process.ExitCode -ne 0) {
        $msg = "Process failed with exit code " + $Process.ExitCode
        WriteOutput $msg $LogPath
        throw $msg
    }
}

# Copies the result and log file from VM. Appends the log to  the local file
# Bails out if the VM result log shows failure
function CopyAndVerifyLogsFromVM([string]$VmLogFileName, [string]$VmResultFileName, [psobject]$VmName, [ref]$Result)
{
    $VmPartition = Get-VMPartition -VMName $VmName -EV Err -EA SilentlyContinue -Timeout 2
    CheckErrorAndExit $Err

    $TempResultPath = $pwd.Path + "\TempResult.txt"
    $TempLogPath = $pwd.Path + "\TempLog.txt"
    Copy-VMItem -Path ($VmPartition + $VmResultFileName) -FullDestination $TempResultPath -Force
    Copy-VMItem -Path ($VmPartition + $VmLogFileName) -FullDestination $TempLogPath -Force
    $resultText = cat $TempResultPath
    
    $logs = cat $TempLogPath
    WriteOutput "==================================================================="
    WriteOutput "Logs From script which ran on VM : $VmName" 
    WriteOutput $logs
    WriteOutput "==================================================================="

    del $TempResultPath
    del $TempLogPath

    if (-not $resultText.Contains("0")) {
        exit 1
    }
}

# Gets partition for the VM
function GetPartition($VmName, [ref]$VmParition, $LogPath="")
{
    StartVm $VmName $LogPath
    WaitForVmPartitionToBeUp $VmName $LogPath
    
    $VmParition.Value = Get-VMPartition -VMName $VmName -EV Err -EA SilentlyContinue
    CheckErrorAndExit $Err $LogPath
}

# Copies a folder from host to the VM
function CopyFolderToVm([string]$VmName, [string]$SourcePath, [string]$DestinationVmPath)
{  
    $vmp = $null
    GetPartition $VmName ([ref]$vmp)

    # Create the directory
    WriteOutput "Creating directory $DestinationVmPath in VM $VmName" 
    $proc = Start-VMProcess -Elevate -VMPartition $vmp -CommandLine "powershell.exe -executionpolicy remotesigned -command `"& {mkdir $DestinationVmPath}`"" -WaitForExit -PassThru -EV Err -Timeout 600
    CheckProcessErrorAndExit $proc $Err

    Copy-VMItem -Path $SourcePath -Destination ($vmp + $DestinationVmPath) -EV Err -EA SilentlyContinue -Force
    CheckErrorAndExit $Err
}

# Copies a file form host to the VM
function CopyFileToVm([string]$VmName, [String]$SourceFileName, [string]$DestinationVmPath)
{
    $vmp = $null
    GetPartition $VmName ([ref]$vmp)

    WriteOutput "Copying $SourceFileName to $DestinationVmPath inside VM $VmName"
    Copy-VMItem -Path $SourceFileName -Destination ($vmp + $DestinationVmPath) -EV Err -EA SilentlyContinue -Force
    CheckErrorAndExit $Err
}

# Copies a file form VM to the Host
function CopyFileFromVm([string]$VmName, [String]$SourceVmPath, [string]$LocalPath)
{
    $vmp = $null
    GetPartition $VmName ([ref]$vmp)

    WriteOutput "Copying $SourceVmPath inside VM $VmName to host local: $LocalPath"
    Copy-VMItem -Path ($vmp + $SourceVmPath) -Destination $LocalPath -EV Err -EA SilentlyContinue -Force
    CheckErrorAndExit $Err
}

# Runs a script inside the VM
# The script must already be present at the correct location inside the VM
function RunScriptInsideVM([string]$VmName, [string]$ScriptName, [string]$Arguments, [string]$WorkingDirectory)
{
    $vmp = $null
    GetPartition $VmName ([ref]$vmp)

    WriteOutput "Launching the script $ScriptName inside VM $VmName"
    Start-VMProcess -Elevate -VMPartition $vmp -CommandLine "cmd.exe /c powershell `"$ScriptName $Arguments`"" -WaitForExit  -PassThru -EV Err -EA SilentlyContinue -WorkingDirctory $WorkingDirectory  -Timeout 600
    CheckErrorAndExit $proc $Err
}

function RunCmdLetInsideVm([string]$VmName, [string]$CmdLetName, [string]$Arguments, [bool]$BailOnError)
{
    $vmp = $null
    GetPartition $VmName ([ref]$vmp)

    WriteOutput "Launching cmdlet $CmdLetName with arguments $Arguments isnide VM $VmName"
    $proc = Start-VMProcess -Elevate -Passthru -CommandLine "cmd.exe /c powershell `"$CmdLetName $Arguments`"" -WaitForExit -VMPartition $vmp  -EV Err -EA SilentlyContinue -Timeout 600
    if ($BailOnError) {
        CheckProcessErrorAndExit $proc $Err
    }
}


# Returns $null when not successful, instanceId otherwise
function GetInstanceIdForResource ([string]$ResourceTypeName, [string]$ResourceId, [string] $serverName, [bool]$UseHttps = $true)
{
    $uriVersion = '/networking/v1/'
    $uriScheme = 'https://'
    if ($UseHttps -eq $false)
    {
        $uriScheme = 'http://'
    }

    $uri = $uriScheme + $serverName + $uriVersion + $ResourceTypeName + '/' + $ResourceId
    
    try
    {
        $serverResp = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing

        if($serverResp.StatusCode -ne 200)
        {
            return $null
        }

        $resourceObj = ConvertFrom-Json $serverResp.Content
        return $resourceObj.instanceId
    }
    catch
    {
        return $null
    }  
}

# Answers whether the fabric service's primary replica
# is currently placed on this Node
function IsServicePrimaryLocal ([string]$ServiceName)
{
    $replicaName = ""
    $ignore = DeterminePrimaryServiceReplica $ServiceName ([ref]$replicaName)
    $isLocal = IsReplicaLocal $replicaName
    return $isLocal
}

# Fabric replica Names are either IP Addresses or ServerNames
# This function checks if the passed in ReplicaName is a locally
# configured Ip or Hostname, in that case returns $true, 
# $false otherwise
function IsReplicaLocal ([string]$ReplicaName)
{
    [IpAddress]$parsedIp = $null
    if ([IpAddress]::TryParse($ReplicaName, [ref]$parsedIp)) {
        $localIps = @(Get-NetIPAddress)
        
        foreach ($entry in $localIps) {
            $addr = [IpAddress]::Parse($entry.IPAddress)
            if ($addr.Equals($parsedIp)) {
                return $true
            }
        }
    } else {
        if (($ReplicaName -ieq [Net.Dns]::GetHostName()) -or ($ReplicaName -ieq "localhost")) {
            return $true
        }
    }
    
    return $false
}

# Determines current primary of the service, returns the replica name
# as output. No waiting unlike WaitForServiceToBecomePrimary
function DeterminePrimaryServiceReplica ([string]$ServiceName, [ref]$ReplicaName)
{
    $ReplicaName.Value = ""
    WriteOutput "Connecting to winfab cluster.."
    $ignore = Connect-WindowsFabricCluster -EV Err -EA SilentlyContinue -WarningAction SilentlyContinue
    CheckErrorAndExit $Err

    WriteOutput "Getting winfab partitions...."
    $fabricPartition = Get-WindowsFabricPartition -ServiceName $ServiceName -EV Err -EA SilentlyContinue
    CheckErrorAndExit $Err

    WriteOutput "Getting winfab replicas...."
    $fabricReplicas = @(Get-WindowsFabricReplica -PartitionId $fabricPartition.PartitionId -EV Err -EA SilentlyContinue)
    CheckErrorAndExit $Err

    if ($fabricReplicas.Count -eq 0) {
        WriteOutput "Failed to obtain replicas for $ServiceName"
        exit 1
    }

    foreach ($curReplica in $fabricReplicas) {
        if ($curReplica.ReplicaRole.ToString() -eq "Primary") {
            $replicaAddr = $curReplica.ReplicaAddress.Split(':')[0]
            WriteOutput "Replica for $ServiceName determined to be $replicaAddr"
            # Output current primary's ReplicaAddress
            $ReplicaName.Value = $replicaAddr
            return
        }
    }

    # No Primary replica
    WriteOutput "Failed to obtain PRIMARY replica for $ServiceName"
    exit 1
}

# Service name should be in the winfab format e.g. 
# fabric:/NetworkController/SlbManagerService
function WaitForServiceToBecomePrimary([string]$ServiceName)
{
    $waitDuration = 5
    $maxWaitTimeInMinutes = 10
    $curTime = get-date
    $stopTime = $curTime.AddMinutes($maxWaitTimeInMinutes)
    $done = $false

    do {
        $replicaName = ""
        DeterminePrimaryServiceReplica $ServiceName ([ref]$replicaName)
        
        if ([String]::IsNullOrWhiteSpace($replicaName)) {
            WriteOutput "Primary for $ServiceName is not up yet. Sleeping for $waitDuration seconds..."
            Start-Sleep -Seconds $waitDuration
        } else {
            WriteOutput "Primary for $ServiceName is $replicaName"
            return
        }

        $curTime = get-date
    } while ($curTime -le $StopTime)
    
    WriteOutput "Timeout occured while waiting for service $ServiceName to become primary."
    exit 1    
}

# Determines where Winfabric has placed code for a service
# E.g.Params -> NodeName : 'SLBM1', ServiceManifestName : 'SDNSLBM' 
# will return the path:
# 'C:\ProgramData\Windows Fabric\SLBM1\Fabric\work\Applications\NetworkController_App0\SDNSLBM.Code.10.0.0'
function DetermineServiceBinsLocation ([string]$NodeName, [string] $ServiceManifestName)
{
    $retval = "Unable To Determine"

    $ignore = Connect-WindowsFabricCluster -ErrorVariable Err -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    CheckErrorAndExit $Err

    if ( ([String]::IsNullOrWhiteSpace($NodeName)) -or
         ([String]::IsNullOrWhiteSpace($ServiceManifestName)) )
    {
        throw [System.ArgumentException]::new("Bad Node Name or Service Manifest Name.")
    }

    $fabricApplicationName = 'fabric:/NetworkController'
    $servicePackages = Get-WindowsFabricDeployedCodePackage -NodeName $NodeName -ApplicationName $fabricApplicationName -ErrorVariable Err
    CheckErrorAndExit $Err

    foreach ($servicePkg in $servicePackages)
    {
        if ($servicePkg.ServiceManifestName -eq $ServiceManifestName)
        {
            $temp = $servicePkg.EntryPoint.EntryPointLocation
            $tempArr = $temp.Split('\')
            $retVal = [String]::Join('\', $tempArr, 0, $tempArr.Length - 1)
            break;
        }
    }

    return $retval
}


# Given a BGP VM's friendly name and a peer IP
# Ensures BGP is peered with the said IP
# Throws when condition above is violated
function Verify-BgpPeering ([string] $BgpVmName,  [string] $VmUserName, [string] $VmPassword, [string] $PeerIp)
{
    [bool] $found = $false
    $bgpVmIp = Get-VmIpv4Address $BgpVmName
    $bgpServerName = Get-VMComputerName -VMName $BgpVmName -ErrorAction Stop
    $session = CreatePsRemotingSession $bgpServerName $bgpVmIp $VmUserName $VmPassword

    $peers = @(Invoke-Command -Session $session -ScriptBlock { Get-BgpPeer})

    foreach ($peer in $peers)
    {
        WriteOutput "Obtained BGP Peer with IP $($peer.PeerIPAddress). Connectivity Status $($peer.ConnectivityStatus)"
        if (($peer.PeerIPAddress -eq $PeerIp) -and ($peer.ConnectivityStatus -eq 3))
        {
            WriteOutput "Success: Found a connected peer on the BGP router for IP $PeerIp"
            $found = $true
        }
    }

    DestroyPsRemotingSession $session $LogFile
    
    if ($found -eq $false)
    {
        Throw "No BGP Peer was found in connected state for Ip: $PeerIp"
    }
}

# Given a BGP VM's friendly name and a list of routes
# Ensures every route in the list is present in BGP route information
# Throws when condition above is violated
function Verify-BgpRouteInformation ([string] $BgpVmName, [string] $VmUserName, [string] $VmPassword, $InputVips)
{
    $session = Get-PsSessionToVm $BgpVmName $VmUserName $VmPassword

    $routes = Invoke-Command -Session $session -ScriptBlock { Get-BgpRouteInformation }

    $routeVips = @()
    foreach ($route in $routes)
    {
        WriteOutput "Obtained BGP route for $($route.Network) and next hop $($route.NextHop)." | Out-Null
        $vip = ($route.Network.Split('/'))[0]
        $routeVips += $vip
    }

    DestroyPsRemotingSession $session $LogFile

    
    # Verify BGP has all the routes
    foreach ($vip in $InputVips)
    {
        if ($routeVips.Contains($vip))
        {
            WriteOutput "Success: Route Vips contain Input VIP $vip." | Out-Null
        }
        else
        {
            throw "Route Vips do not contain Input VIP $vip"
        }
    }
}

# Given a BGP VM's friendly name and a list of routes
# Ensures every route in the list is present in BGP route information
# Throws when condition above is violated
function Verify-SlbmGoalStateForAVip ([string] $NcVmName, [string] $VmUserName, [string] $VmPassword, $InputVips, $InputDips)
{
    $session = Get-PsSessionToVm $NcVmName $VmUserName $VmPassword

    Setup-SlbClientWinInRemoteSession $session

    $vips = @()
    foreach ($InputVip in $InputVips)
    {
        $vips += $InputVip.Split('-')[0]
    }

    $retDips = 
    Invoke-Command -Session $session `
        -ScriptBlock {$Using:vips | Foreach {$vip = $global:slbmConnection.GetVipConfiguration($_); ,($vip.VipEndpoints[0].DipEndpoints)}}
    
    $i = 0
    foreach ($retDipSet in $retDips)
    {
        $slbmDips = @()
        foreach ($dip in $retDipSet)
        {
            WriteOutput "Obtained DIP from SLBM : $dip"
            $slbmDips += $dip.Address
        }

        $currentInputDipSet = $InputDips[$i]
        foreach ($inputDip in $currentInputDipSet)
        {
            if ($slbmDips.Contains($inputDip))
            {
                WriteOutput "Success: Input dip $inputDip for Vip EP $($InputVips[$i]) present in SLBM goal state"
            }
            else
            {
                Throw "Input dip $inputDip for Vip EP $InputVip not present in SLBM goal state"
                DestroyPsRemotingSession $session $LogFile
            }
        }
        $i++
    }

    DestroyPsRemotingSession $session $LogFile
}

function Verify-MuxRoutesForVips ([string] $NcVmName, [string] $VmUserName, [string] $VmPassword, $inputVips)
{
    $session = Get-PsSessionToVm $NcVmName $VmUserName $VmPassword
    Setup-SlbClientWinInRemoteSession $session

    $routes = 
    Invoke-Command -Session $session `
        -ScriptBlock {(slb-GetMuxAdvertisedRoutes).MuxAdvertisedRoutes }

    WriteOutput "Found Routes: `r`n $($routes | Out-String)"

    foreach ($inputVipEp in $inputVips)
    {
        $inputVip = $inputVipEp.Split('-')[0]
        $routeFound = $false
        foreach ($route in $routes)
        {
            $vip = $route.VipPrefix.Split('/')[0]
            if ($vip -eq $inputVip)
            {
                WriteOutput "Success: Found $inputVip amongst the advertised routes"
                $routeFound = $true
                break
            }
        }
        if ($routeFound -eq $false)
        {
            DestroyPsRemotingSession $session $LogFile
            Throw "No route advertisment found for $inputVip"
        }
    }

    DestroyPsRemotingSession $session $LogFile
}

function Verify-MuxDipsForAVip ([string] $NcVmName, [string] $VmUserName, [string] $VmPassword, [string] $MuxIp, $InputVipEps, $InputDips)
{
    $session = Get-PsSessionToVm $NcVmName $VmUserName $VmPassword

    Setup-SlbClientWinInRemoteSession $session
    
    $vipEndpoints = @()
    foreach ($inpVip in $InputVipEps)
    {
        $vipEndPoints += $inpVip.Replace('-', ':')
    }

    $dipSetIndex = 0
    # Assume vipEndpoints have vips of interest
    $retDipSets = 
    Invoke-Command -Session $session `
        -ScriptBlock {$Using:vipEndPoints | Foreach {slb-GetInboundStateOnMuxs $_ $Using:MuxIp } }
    foreach ($dipSet in $retDipSets)
    {
        $muxDips = @()
        $dips = ($dipSet.Values.GetEnumerator().GetEnumerator())
        foreach ($dip in $dips)
        {
            WriteOutput "Obtained DIP from Mux : $dip"
            $muxDips += $dip.Address
        }

        $currentInputDipSet = $InputDips[$dipSetIndex]
        foreach ($inputDip in $currentInputDipSet)
        {
            if ($muxDips.Contains($inputDip))
            {
                WriteOutput "Input Dip $inputDip is present on the Mux for $($InputVipEps[$dipSetIndex])"
            }
            else
            {
                Throw "Input Dip $inputDip not present on the Mux for $($InputVipEps[$dipSetIndex])"
                DestroyPsRemotingSession $session $LogFile
            }
        }
        $dipSetIndex++
    }

    DestroyPsRemotingSession $session $LogFile
}

function Setup-SlbClientWinInRemoteSession ($NcVmSession)
{
    $ret = 
    Invoke-Command -Session $NcVmSession `
        -ScriptBlock { cd C:\Windows\NetworkController\SDNCTLR;. .\SlbClientWin.ps1; $slbclient = New-Object Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbClient; $slbmLocalEp = new-object System.Net.IPEndPoint([ipaddress]::Loopback, 8550); $global:slbmConnection = $slbclient.ConnectToSlbManager($slbmLocalEp, $null, $null)}
}

function Get-PsSessionToVm ([String] $VmFriendlyName, [String] $VmUserName, [String] $VmPassword)
{
    $vmIp = Get-VmIpv4Address $VmFriendlyName
    $vmServerName = Get-VMComputerName -VMName $VmFriendlyName -ErrorAction Stop
    $session = CreatePsRemotingSession $vmServerName $vmIp $VmUserName $VmPassword
    return $session
}

function Get-VmIpv4Address([string] $vmName)
{
    $ncServerName = Get-VMComputerName -VMName $vmName -ErrorAction Stop
    $vmIp = ([System.Net.Dns]::GetHostAddresses($ncServerName) | where-object {$_.AddressFamily -eq 'InterNetwork'}).IPAddressToString
    return $vmIp
}

# Call this function on Host only
function Execute-DumpSlbConfigState ([string] $NcVmName, [string] $ScriptDirOnHost = (pwd).Path, $OutputDirOnHost = (pwd).Path)
{
    $scriptHostLocalPath = $ScriptDirOnHost + '\' + 'DumpSlbConfigState.ps1'
    $scriptVmDir  = 'C:\tools'
    $scriptVmPath = $scriptVmDir + '\DumpSlbConfigState.ps1'
    $scriptVmOutputPath = $scriptVmDir + '\SlbConfigState.txt'

    CopyFileToVm $NcVmName $scriptHostLocalPath $scriptVmDir
    RunScriptInsideVM $NcVmName $scriptVmPath '' $scriptVmDir
    CopyFileFromVm $NcVmName $scriptVmOutputPath $OutputDirOnHost
}

# Creates a PS remoting session to the VM
function CreatePsRemotingSession([string]$VmName, [string]$MgmtIp, [string]$User, [string]$Password, $LogPath="")
{
    $securePwd = ConvertTo-SecureString $Password -AsPlainText -force
    $creds = New-Object System.Management.Automation.PSCredential("$VmName\$User", $securePwd)

    $trustedHosts = (Get-Item WSMan:\localhost\client\TrustedHosts).Value
    if (-not ($trustedHosts -match $MgmtIp) -and $trustedHosts -ne "*") {
        $trustedHosts += ",$MgmtIp"
        Set-Item -Force WSMan:\localhost\client\TrustedHosts $trustedHosts
    }
    WriteOutput "Trying to establish PS remoting session for $VmName" $LogPath | Out-Null
    $session = New-PsSession -ComputerName $MgmtIp -Credential $creds -EV Err -EA SilentlyContinue
    CheckErrorAndExit $Err $LogPath
    WriteOutput "Successfully established PS remoting session for $VmName" $LogPath | Out-Null

    return $session
}

# Destroys a PS remoting session with the VM
function DestroyPsRemotingSession($Session, $LogPath="")
{
    Remove-PsSession -Session $Session -EV Err -EA SilentlyContinue
    CheckErrorAndExit $Err $LogPath
}

# Runs a script block on the given PS remoting session
function RunScriptBlock($Session, $ScriptBlock, $ArgList="", $LogPath="")
{
    WriteOutput "Attempting to run: $ScriptBlock, with args: $ArgList" $LogPath

    if ($Session -eq $null -or (Get-PsSession -Id $Session.Id).State -eq "Broken") {
        WriteOutput "Session is no longer valid; abandoning invocation of script block" $LogPath
        exit 1
    }

    $global:lastexitcode = 0
    $output = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgList -EV Err
    if ($Err.Count -eq 0) {
        $global:lastexitcode = Invoke-Command -Session $Session -ScriptBlock { $lastExitCode } -EV Err
        if ($global:lastexitcode -eq $null) {
            $global:lastexitcode = 0 
        }
    }

    if ($Err.Count -gt 0 -or $global:lastexitcode -ne 0) {
        WriteOutput ("Unable to run $ScriptBlock; exit code: $global:lastexitcode, error count: " + $Err.Count) $LogPath
        WriteOutput "Command output: $output" $LogPath
        exit 1
    }

    return $output
}

# Adds host entry to etc file for DNS resolution
function AddHostEntryToEtcFile([string]$IpAddress, [string]$HostName)
{
    $HostsLocation = "$env:windir\System32\drivers\etc\hosts"
    $NewHostEntry = "`t$IPAddress`t$HostName"

    if((Get-Content $HostsLocation) -contains $NewHostEntry)
    {
        WriteOutput "The hosts file already contains the entry: $NewHostEntry.  File not updated."
    }
    else
    {
        WriteOutput "The hosts file does not contain the entry: $NewHostEntry.  Attempting to update..."
        Add-Content -Path $HostsLocation -Value $NewHostEntry
    }
    if((Get-Content $HostsLocation) -contains $NewHostEntry)
    {
        WriteOutput "New entry, $NewHostEntry, added to $HostsLocation."
    }
    else
    {
        WriteOutput "The new entry, $NewHostEntry, was not added to $HostsLocation."
    }
}

function WaitForHyperVJobCompletion($HyperVJob, $JobName, $LogPath="")
{
    if ($HyperVJob.ReturnValue -eq 4096) {
        $job = [WMI]$HyperVJob.job
        
        while (($job.JobState -eq 3) -or ($job.JobState -eq 4)) {
            Start-Sleep -s 1
            $job = [WMI]$HyperVJob.job
        }

        if ($job.JobState -eq 7) {
            WriteOutput "Hyper-V job $JobName completed with job state 7" $LogPath
        } else {
            WriteOutput ("Hyper-V job $JobName failed with error " + $job.GetError()) $LogPath
            return 1
        }
    } elseif ($HyperVJob.ReturnValue -eq 0) {
        WriteOutput "Hyper-V job $JobName completed with job state 0" $LogPath
    } else {
        WriteOutput ("Hyper-V job $JobName failed with return value " + $HyperVJob.ReturnValue) $LogPath
        return 1
    }

    return 0;
}

function GetWinPrismRemotePsSession([string]$ComputerName, [ref]$Session)
{
    $secPassword = ConvertTo-SecureString "Myd3ar-uncooperativeDomin0" -AsPlainText -Force -EV Err -EA SilentlyContinue 
    CheckErrorAndExit $Err $LogPath

    $creds = New-object -typename System.Management.Automation.PSCredential("ntdev\texas", $secPassword)
    CheckErrorAndExit $Err $LogPath

    WriteOutput "Creating a PsSession with $ComputerName"
    $Session.Value = New-PSSession -ComputerName $ComputerName –Credential $creds
}

function KillProcessInVm ($VmName, $ProcessName)
{
    $Vmp = $null
    GetPartition $VmName ([ref]$Vmp) $LogPath
 
    # Kill all the existing instances of given Process
    $process = Start-VMProcess -CommandLine "cmd.exe /c taskkill /F /IM $ProcessName"-ErrorVariable Err -ErrorAction SilentlyContinue -Elevate -Wait -VMPartition $vmp
    CheckErrorAndThrow $Err
}

function VerifyDataPath($Vmp, $DestIp, $Ports, $Protocol)
{
    foreach($port in $Ports)
    {
        WriteOutput "Sending data from $($Vmp.VirtualMachineName) over $DestIp, port = $port, protocol = $Protocol"
        
        $process = $null        
        if($Protocol -ieq "tcp")
        {
            $cmdLine = "c:\tools\ctsTraffic.exe -target:$DestIp -port:$port -Connections:1 -iterations:1 -Transfer:$TransferSize -pattern:pushpull"
            WriteOutput "Running command on VM $($Vmp.VirtualMachineName):  $cmdLine"
            $process = Start-VmProcess -Elevate -VMPartition $vmp -CommandLine $cmdLine -PassThru -WaitForExit -ErrorVariable Err -ErrorAction SilentlyContinue -Timeout 3000
        }
        else
        {
            $cmdline = "c:\tools\ctsTraffic.exe -target:$DestIp -port:$port -Protocol:$Protocol -BitsPerSecond:$BitsPerSecond -BufferDepth:1 -StreamLength:$StreamLength -FrameRate:$FrameRate -Iterations:1"
            WriteOutput "Running command on VM $($Vmp.VirtualMachineName): $cmdLine"
            $process = Start-VmProcess -Elevate -VMPartition $vmp -CommandLine $cmdline -PassThru -WaitForExit  -ErrorVariable Err -ErrorAction SilentlyContinue  -Timeout 3000
        }
        CheckProcessErrorAndThrow $process $Err

        WriteOutput "Data path verified for VM $($Vmp.VirtualMachineName) over $DestIp, port = $port, protocol = $Protocol"
    }
}

# Wait till the machine with specified Ip is reachable (ICMP pingable)
# Waits for the specified maximum time in minutes
function WaitTillMachineReachable([string]$IpAddress, [int]$MaxMinutesToWait)
{
    $iterations = 0
    $sleepTime = 10   # in seconds
    $maxIterations = $MaxMinutesToWait * 60 / $sleepTime
    while(-not (Test-Connection -ComputerName $IpAddress -Quiet) -and $iterations -lt $maxIterations)
    {
        WriteOutput("Machine with Ip $IpAddress is not reachable yet. Sleeping for 10 seconds")
        sleep $sleepTime
        $iterations ++
    }

    if($iterations -eq $maxIterations)
    {
        WriteOutput("Timeout occured while waiting for Machine with Ip $IpAddress to be reachable.")
        return $false
    }
    else
    {
        $totalTime = $iterations * $sleepTime
        WriteOutput("Machine with ip $IpAddress is reachable after $totalTime seconds.")
        return $true
    }
}

#
# Given the VM name it returns the computer name of the VM
#
function Get-VMComputerName
{
    [CmdletBinding()]
    Param (
      [string]
      $VMName = ''
      )

    Write-Verbose "Query for VM $VMName"

    $ComputerNames = @()

    Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem | Where-Object {$_.ElementName -ne $env:COMPUTERNAME} | ForEach-Object { 

        $existingVMName = $_.ElementName

        $_.GetRelated('Msvm_KvpExchangeComponent').GuestIntrinsicExchangeItems | ForEach-Object {  

            if($_ -as [xml])
            {    
                $GuestExchangeItemXml = ([XML]$_).SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text()='FullyQualifiedDomainName']") 

                if ($GuestExchangeItemXml -ne $null) 
                {
                    $computerName = $GuestExchangeItemXml.SelectSingleNode("/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value

                    Write-Verbose "Computer Name for VM $existingVMName is $computerName"

                    if ($VMName -eq '' -or $VMName -eq $existingVMName)
                    {
                        $ComputerNames += $computerName
                    }
                }
            }
        }
    }

    if ($ComputerNames.Length -eq 0)
    {
        throw "VM $VMName not found"
    }

    return $ComputerNames
}

function StartTranscript ($LogPath)
{
    try 
    { 
        if(Test-Path $LogPath)
        {
            del $LogPath
        }
        Stop-Transcript | out-null
    }
    catch
    {
    }

    Start-Transcript -path $LogPath -Append
}


# Define constants which are used by multiple scripts here
$TransferSize = 1024000
$BitsPerSecond = 10000
$StreamLength = 3
$FrameRate = 5


$VmNameBlue1 = "WORKLOAD1_BLUE"
$VmNameBlue2 = "WORKLOAD2_BLUE"
$VmNameBlue3 = "WORKLOAD3_BLUE"
$VmNameGreen1 = "WORKLOAD1_GREEN"
$VmNameGreen2 = "WORKLOAD2_GREEN"
$VmNameService = "WORKLOAD_SERVICE"
$VmNameService2 = "WORKLOAD2_SERVICE"
$VmNameSlbClient = "SlbClient1"