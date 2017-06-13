<#
.SYNOPSIS

    Measures vmswitch path cost (cycles per packet) for performance benchmarking.

.DESCRIPTION

    Query Perfmon counters to calculate vmswitch performance benchmark
        - Query packets sent by vswitch to all of its vPorts. This represents the amount
        of useful work a vswitch can do (i.e. measured in terms of how many packets it
        can deliver to its vPorts.)
        - Query system's processor speed
        - Query processor utilization
        - Calculate path cost, based on the above information

.PARAMETER DurationInSeconds

    Required parameter that specifies how long the script should collect information.
    This time period does not include the warmup and cooldown time.

.PARAMETER SwitchName

    Required parameter that specifies the vswitch to query packet count from.

.PARAMETER BaseCpuNumber

    Optional parameter that specifies the starting CPU for including in the
    CPU utilization measurement. Default value is 0.

.PARAMETER MaxCpuNumber
    
    Optional parameter that specifies the ending CPU for including in the CPU
    utilization measurement. Default value is max processor number in the system.

.PARAMETER WarmUpDurationInSeconds

    Optional parameter that specifies warmup time that will not be included in
    the measurement. This time period will be added to DurationInSeconds for
    total runtime. Default value is 0.

.PARAMETER CoolDownDurationInSeconds

    Optional parameter that specifies cooldown time that will not be included in
    the measurement. This time period will be added to DurationInSeconds for
    total runtime. Default value is 0.

.EXAMPLE

    Get-VSwitchPathCost.ps1 -DurationInSeconds 30 -SwitchName MyVSwitch

.NOTES

   This script does not start any traffic. It is the caller's responsibility to ensure
   traffic is already running in steady state, before calling the script.
   The script only collects perfmon counters for the specified during, and computes
   path cost, based on the specified CPU range.

   Since CPU utilization and path cost are more accurately measured with HyperThreading
   disabled, this script forces HyperThreading to be disabled. You can disable HyperThreading
   in the BIOS.

   However, note that for better performance, HyperThreading should be enabled.

#>

PARAM($DurationInSeconds =$(throw "DurationInSeconds is required"),
      $SwitchName = $(throw "SwitchName is required"),
      $BaseCpuNumber=0,
      $MaxCpuNumber,
      $WarmUpDurationInSeconds=0,
      $CoolDownDurationInSeconds=0)


function Log($Message)
{
    if ($Message.StartsWith("ERROR"))
    {
        Write-Error "$Message"
        exit
    }
    elseif ($Message.StartsWith("WARNING"))
    {
        Write-Host "$Message" -foregroundcolor red -backgroundcolor yellow
    }
    else
    {
        Write-Host "$Message"
    }
}

function IsHyperThreadingEnabled()
{
    $cpuInfo = Get-WmiObject -Class win32_processor -Property "numberOfCores", "NumberOfLogicalProcessors"
    if ($cpuInfo[0].NumberOfCores -lt $cpuInfo[0].NumberOfLogicalProcessors)
    {
        return $True
    }
    else
    {
        return $False
    }
}

function GetNumCpusPerNUMA()
{
    $cpuInfo = Get-WmiObject -Class win32_processor -Property "numberOfCores"
    $numcores = $cpuInfo[0].NumberOfCores
    Log "Number of cores per NUMA: $numcores"
    return $numcores
}

function GetNumaCount()
{
    $cpuInfo = Get-WmiObject -Class win32_processor -Property "numberOfCores"
    $numaCount = $cpuInfo.Count
    Log "NUMA count: $numaCount"
    return $numaCount
}

function GetCpuClockSpeed()
{
    $cpuInfo = Get-WmiObject -Class win32_processor -Property "maxclockspeed"
    return $cpuInfo[0].MaxClockSpeed
}


#
# This function takes in a job ID of a Get-Counter job, and
# retrieve the perfmon output of the job, and computes the
# average values of the samples.
#
function GetAverageFromGetCounterJob($JobId)
{
    Stop-Job $JobId
    $statArray = Receive-Job $JobId
    Remove-Job $JobId

    $avg = 0
    $count=0
    $endIndex = $statArray.Count - 1 - $CoolDownDurationInSeconds
    $startIndex = $endIndex - $DurationInSeconds
            
    $message = ""
    for ($i=$startIndex; $i -le $endIndex; $i++)
    {
        $value = $statArray[$i].Readings.Split(":")[-1]
        $value = $value.Trim()

        $value = [int64]$value
        $avg += $value

        $message = $message + [string]$value + ", "
        $count++
    }

    $avg = $avg / $count

    return $avg
}


###############################################################
### Start program #############################################################
###############################################################


#######################################
# Sanity check the parameters & host setup
#######################################

$switch = Get-Vmswitch $SwitchName
if ($switch -eq $null)
{
   Log "ERROR: Switch $SwitchName does not exist"
}

if ($switch.Count -gt 1)
{
    Log "ERROR: There are more than one vswitch with the name $SwitchName"
}

if ($MaxCpuNumber -eq $null)
{
    $cpuPerNuma = GetNumCpusPerNUMA
    $numaCount = GetNumaCount
    $MaxCpuNumber = $cpuPerNuma * $numaCount - 1
    Log "Set MaxCpuNumber to $MaxCpuNumber"
}

if ($MaxCpuNumber -lt $BaseCpuNumber)
{
   Log "ERROR: Max CPU number is less than base CPU number"
}

#
# Verify HyperThreading is disabled
#
if (IsHyperThreadingEnabled)
{
    Log "ERROR: HyperThreading is enabled. Please disable HyperThreading before starting the test."
}

Log "Collecting performance stats"
Log "DurationInSeconds:               $DurationInSeconds"
Log "BaseCpuNumber:                   $BaseCpuNumber"
Log "MaxCpuNumber:                    $MaxCpuNumber"


#############################################
# Start perfmon monitoring
#############################################
Log ""

$hostCounterName = (get-counter -listset "Hyper-V Virtual Switch").PathsWithInstances | where {$_ -like "*$SwitchName*\Bytes Sent/sec*"}
$hostCounterRxBytesPerSecJob = Start-Job -ScriptBlock {param($counter) Get-Counter -Counter $counter -SampleInterval 1 -Continuous} -ArgumentList $hostCounterName

$hostCounterName = (get-counter -listset "Hyper-V Virtual Switch").PathsWithInstances | where {$_ -like "*$SwitchName*\Packets Sent/sec*"}
$hostCounterRxPktsPerSecJob = Start-Job -ScriptBlock {param($counter) Get-Counter -Counter $counter -SampleInterval 1 -Continuous} -ArgumentList $hostCounterName


#
# Collect host VP utilization
#
Log "Start collecing host VP utilization ..."
$hostVPPerProcRuntimeJobs = @()
for ($i=$BaseCpuNumber; $i -le $MaxCpuNumber; $i++)
{
    Log "`tStart collecting VP utilization for VP $i ..."
    $jobObj = Start-Job -ScriptBlock {param($procId) Get-Counter -Counter "\Hyper-V Hypervisor Root Virtual Processor(Root VP $procId)\% Total Run Time" -SampleInterval 1 -Continuous} -ArgumentList $i
    $hostVPPerProcRuntimeJobs = $hostVPPerProcRuntimeJobs + $jobObj
}

#
# Wait for all jobs to start
#
Log "Waiting for all jobs to start..."
for ($i=$BaseCpuNumber; $i -le $MaxCpuNumber; $i++)
{
    $jobId = $hostVPPerProcRuntimeJobs[$i-$BaseCpuNumber].Id
    Log "Waiting for VP[$i] counters to start..."
    $value = Receive-Job -Id $jobId -Keep
    while ($value.Count -lt 1)
    {
        $jobId = $hostVPPerProcRuntimeJobs[$i-$BaseCpuNumber].Id
        $value = Receive-Job -Id $jobId -Keep
        Sleep 1
    }
}

$waitTime = $WarmUpDurationInSeconds + $DurationInSeconds + $CoolDownDurationInSeconds
Log "Wait for $waitTime seconds ($WarmUpDurationInSeconds seconds of warmup + $DurationInSeconds seconds of active measurement + $CoolDownDurationInSeconds seconds of cool down."
Sleep $waitTime 


#############################################
# Retrieve statistics
#############################################
Log ""

Log "Calculating bytes/s in vswitch counters, $CoolDownDurationInSeconds seconds from end of run."
$hostCounterRxBytesPerSecAvg = GetAverageFromGetCounterJob($hostCounterRxBytesPerSecJob.Id)
$hostCounterRxBytesPerSecAvg = $hostCounterRxBytesPerSecAvg * 8;

Log "Calculating pkts/s in host switch port counters, $CoolDownDurationInSeconds seconds from end of run."
$hostCounterRxPktsPerSecAvg = GetAverageFromGetCounterJob($hostCounterRxPktsPerSecJob.Id)

#
# Per proc host VP runtime
#
$hostVPRuntime = 0
for ($i=$BaseCpuNumber; $i -le $MaxCpuNumber; $i++)
{
    Log "Calculating VP utilization for VP $i, $CoolDownDurationInSeconds seconds from end of run ..."
    $value = GetAverageFromGetCounterJob($hostVPPerProcRuntimeJobs[$i-$BaseCpuNumber].Id)
    Log "`tHost utilization VP[$i]=$([math]::Round($value,2))"

    $hostVPRuntime += $value
}
$hostVPRuntime = $hostVPRuntime / ($MaxCpuNumber - $BaseCpuNumber + 1)


#
# Calculate path costs
#
$cpuCyclesPerSec = GetCpuClockSpeed
$cpuCyclesPerSec = $cpuCyclesPerSec * 1000000
$totalCyclesPerSec = ($MaxCpuNumber - $BaseCpuNumber + 1)  * $cpuCyclesPerSec
$totalCyclesPerSec = $totalCyclesPerSec * $hostVPRuntime / 100
$bytePathCost = 0
if ($hostCounterRxBytesPerSecAve -ne 0)
{
    $bytePathCost = $totalCyclesPerSec / $hostCounterRxBytesPerSecAvg
}
$pktPathCost = 0
if ($hostCounterRxPktsPerSecAvg -ne 0)
{
    $pktPathCost = $totalCyclesPerSec / $hostCounterRxPktsPerSecAvg
}


Log "===============Results============================================"
Log ""
Log "CPU speed (cycles per second):                    $cpuCyclesPerSec"
Log "VP Utilization:                                   $([math]::Round($hostVPRuntime,2))"
Log "Total CPU cycles used per second:                 $([math]::Round($totalCyclesPerSec,2))"
Log ""
Log "Bytes/s received through vswitch:                 $([math]::Round($hostCounterRxBytesPerSecAvg,2))"
Log "Packets/s received through vswitch:               $([math]::Round($hostCounterRxPktsPerSecAvg,2))"
Log "Byte path cost (cycles/byte):                     $([math]::Round($bytePathCost,2))"
Log "Packet path cost (cycles/packet):                 $([math]::Round($pktPathCost,2))"