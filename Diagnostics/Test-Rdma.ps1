[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True, Position=1, HelpMessage="Interface index of the adapter for which RDMA config is to be verified")]
  [string] $IfIndex,  
  [Parameter(Mandatory=$True, Position=2, HelpMessage="True if underlying fabric type is RoCE. False for iWarp or IB")]
  [bool] $IsRoCE,
  [Parameter(Position=3, HelpMessage="IP address of the remote RDMA adapter")]
  [string] $RemoteIpAddress,
  [Parameter(Position=4, HelpMessage="Full path to the folder containing diskspd.exe")]
  [string] $PathToDiskspd 
)

if ($RemoteIpAddress -ne $null)
{
    if (($PathToDiskspd -eq $null) -Or ($PathToDiskspd -eq ''))
    {
        $PathToDiskspd = "C:\Windows\System32"
    }
    
    $FullPathToDiskspd = $PathToDiskspd + "\diskspd.exe"
    if ((Test-Path $FullPathToDiskspd) -eq $false)
    {
        Write-Host "ERROR: Diskspd.exe not found at" $FullPathToDiskspd ". Please download diskspd.exe and place it in the specified location. Exiting." -ForegroundColor Red
        return
    }
    else
    {
        Write-Host "VERBOSE: Diskspd.exe found at" $FullPathToDiskspd 
    }
}

$rdmaAdapter = Get-NetAdapter -IfIndex $IfIndex

if ($rdmaAdapter -eq $null)
{
    Write-Host "ERROR: The adapter with interface index $IfIndex not found" -ForegroundColor Red
    return
}

$rdmaAdapterName = $rdmaAdapter.Name
$virtualAdapter = Get-VMNetworkAdapter -ManagementOS | where DeviceId -eq $rdmaAdapter.DeviceID

if ($virtualAdapter -eq $null)
{
    $isRdmaAdapterVirtual = $false
    Write-Host "VERBOSE: The adapter $rdmaAdapterName is a physical adapter"
}
else
{
    $isRdmaAdapterVirtual = $true
    Write-Host "VERBOSE: The adapter $rdmaAdapterName is a virtual adapter"
}

$rdmaCapabilities = Get-NetAdapterRdma -InterfaceDescription $rdmaAdapter.InterfaceDescription

if ($rdmaCapabilities -eq $null -or $rdmaCapabilities.Enabled -eq $false) 
{
    Write-Host "ERROR: The adapter $rdmaAdapterName is not enabled for RDMA" -ForegroundColor Red
    return
}

if ($rdmaCapabilities.MaxQueuePairCount -eq 0)
{ 
    Write-Host "ERROR: RDMA capabilities for adapter $rdmaAdapterName are not valid : MaxQueuePairCount is 0" -ForegroundColor Red
    return
}

if ($rdmaCapabilities.MaxCompletionQueueCount -eq 0)
{
    Write-Host "ERROR: RDMA capabilities for adapter $rdmaAdapterName are not valid : MaxCompletionQueueCount is 0" -ForegroundColor Red
    return
}

$smbClientNetworkInterfaces = Get-SmbClientNetworkInterface

if ($smbClientNetworkInterfaces -eq $null)
{
    Write-Host "ERROR: No network interfaces detected by SMB (Get-SmbClientNetworkInterface)" -ForegroundColor Red
    return 
}

$rdmaAdapterSmbClientNetworkInterface = $null
foreach ($smbClientNetworkInterface in $smbClientNetworkInterfaces)
{
    if ($smbClientNetworkInterface.InterfaceIndex -eq $IfIndex)
    {
        $rdmaAdapterSmbClientNetworkInterface = $smbClientNetworkInterface
    }
}

if ($rdmaAdapterSmbClientNetworkInterface -eq $null)
{
    Write-Host "ERROR: No network interfaces found by SMB for adapter $rdmaAdapterName (Get-SmbClientNetworkInterface)" -ForegroundColor Red
    return
}

if ($rdmaAdapterSmbClientNetworkInterface.RdmaCapable -eq $false)
{
    Write-Host "ERROR: SMB did not detect adapter $rdmaAdapterName as RDMA capable. Make sure the adapter is bound to TCP/IP and not to other protocol like vmSwitch." -ForegroundColor Red
    return
}

$rdmaAdapters = $rdmaAdapter
if ($isRdmaAdapterVirtual -eq $true)
{
    Write-Host "VERBOSE: Retrieving vSwitch bound to the virtual adapter"
    $switchName = $virtualAdapter.SwitchName
    Write-Host "VERBOSE: Found vSwitch: $switchName"
    $vSwitch = Get-VMSwitch -Name $switchName
    $rdmaAdapters = Get-NetAdapter -InterfaceDescription $vSwitch.NetAdapterInterfaceDescriptions
    $vSwitchAdapterMessage = "VERBOSE: Found the following physical adapter(s) bound to vSwitch: "
    $index = 1
    foreach ($qosAdapter in $rdmaAdapters)
    {        
        $qosAdapterName = $qosAdapter.Name
        $vSwitchAdapterMessage = $vSwitchAdapterMessage + [string]$qosAdapterName
        if ($index -lt $rdmaAdapters.Length)
        { 
                $vSwitchAdapterMessage = $vSwitchAdapterMessage + ", " 
        }
        $index = $index + 1
    }
    Write-Host $vSwitchAdapterMessage 
}


if ($IsRoCE -eq $true)
{
    Write-Host "VERBOSE: Underlying adapter is RoCE. Checking if QoS/DCB/PFC is configured on each physical adapter(s)"
    foreach ($qosAdapter in $rdmaAdapters)
    {
        $qosAdapterName = $qosAdapter.Name
        $qos = Get-NetAdapterQos -Name $qosAdapterName 
        if ($qos.Enabled -eq $false)
        {
            Write-Host "ERROR: QoS is not enabled for adapter $qosAdapterName" -ForegroundColor Red
            return            
        }

        if ($qos.OperationalFlowControl -eq "All Priorities Disabled")
        {
            Write-Host "ERROR: Flow control is not enabled for adapter $qosAdapterName" -ForegroundColor Red
            return            
        }
    }
    Write-Host "VERBOSE: QoS/DCB/PFC configuration is correct."
}

Write-Host "VERBOSE: RDMA configuration is correct."

if ($RemoteIpAddress -ne '')
{
    Write-Host "VERBOSE: Checking if remote IP address, $RemoteIpAddress, is reachable."
    $canPing = Test-Connection $RemoteIpAddress -Quiet
    if ($canPing -eq $false)
    {
        Write-Host "ERROR: Cannot reach remote IP $RemoteIpAddress" -ForegroundColor Red
        return          
    }
    else
    {
        Write-Host "VERBOSE: Remote IP $RemoteIpAddress is reachable."
    }
}

if ($RemoteIpAddress -eq '')
{
    Write-Host "VERBOSE: Remote IP address was not provided. If RDMA does not work, make sure that remote IP address is reachable."    
   
}
else
{
    Write-Host "VERBOSE: Disabling RDMA on adapters that are not part of this test. RDMA will be enabled on them later."
    $adapters = Get-NetAdapterRdma 
    $InstanceIds = $rdmaAdapters.InstanceID;

    $adaptersToEnableRdma = @()
    foreach ($adapter in $adapters)
    {
        if ($adapter.Enabled -eq $true)
        {
            if (($adapter.InstanceID -notin $InstanceIds) -And ($adapter.InstanceID -ne $rdmaAdapter.InstanceID))
            {
                $adaptersToEnableRdma += $adapter
                Disable-NetAdapterRdma -Name $adapter.Name
            }            
        }
    }

    Write-Host "VERBOSE: Testing RDMA traffic now for. Traffic will be sent in a parallel job. Job details:"

    $ScriptBlock = {
        param($RemoteIpAddress, $PathToDiskspd) 
        cd $PathToDiskspd
        .\diskspd.exe -b4K -c10G -t4 -o16 -d100000 -L -Sr -d30 \\$RemoteIpAddress\C$\testfile.dat
      }
      
    $thisJob = Start-Job $ScriptBlock -ArgumentList $RemoteIpAddress,$PathToDiskspd

    $RdmaTrafficDetected = $false

    # Check Perfmon counters while the job is running
    While ((Get-Job -id $($thisJob).Id).state -eq "Running")
    {
        $written = Get-Counter -Counter "\SMB Direct Connection(_Total)\Bytes RDMA Written/sec" -ErrorAction Ignore
        $sent = Get-Counter -Counter "\SMB Direct Connection(_Total)\Bytes Sent/sec" -ErrorAction Ignore
        if ($written -ne $null)
        {
            $RdmaWriteBytesPerSecond = [uint64]($written.Readings.split(":")[1])
            if ($RdmaWriteBytesPerSecond -gt 0)
            {
                 $RdmaTrafficDetected = $true
                 
            }
            Write-Host "VERBOSE:" $RdmaWriteBytesPerSecond "RDMA bytes written per second"
        } 
        if ($sent -ne $null)
        {
             $RdmaWriteBytesPerSecond = [uint64]($sent.Readings.split(":")[1])
            if ($RdmaWriteBytesPerSecond -gt 0)
            {
                 $RdmaTrafficDetected = $true
            }
            Write-Host "VERBOSE:" $RdmaWriteBytesPerSecond "RDMA bytes sent per second"            
        } 
    }

    del \\$RemoteIpAddress\C$\testfile.dat

    Write-Host "VERBOSE: Enabling RDMA on adapters that are not part of this test. RDMA was disabled on them prior to sending RDMA traffic."
    foreach ($adapter in $adaptersToEnableRdma)
    {
        Enable-NetAdapterRdma -Name $adapter.Name
    }

    if ($RdmaTrafficDetected)
    {
        Write-Host "VERBOSE: RDMA traffic test SUCCESSFUL: RDMA traffic was sent to" $RemoteIpAddress -ForegroundColor Green
    }
    else
    {
        Write-Host "VERBOSE: RDMA traffic test FAILED: Please check physical switch port configuration for Priorty Flow Control." -ForegroundColor Yellow
    }

}
