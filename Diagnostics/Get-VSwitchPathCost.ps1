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

   However, note that for better performance, HyperThreading should be enabled.
#>

Param(
    [Parameter(Mandatory=$true)] $DurationInSeconds,
    [Parameter(Mandatory=$true)] $SwitchName,
    $BaseCpuNumber = 0,
    [Parameter(Mandatory=$false)] $MaxCpuNumber,
    $WarmUpDurationInSeconds = 0,
    $CoolDownDurationInSeconds = 0
)


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

$cpuInfo = @(Get-WmiObject -Class win32_processor -Property NumberOfCores, MaxClockSpeed, NumberOfLogicalProcessors)

function IsHyperThreadingEnabled()
{
    return $cpuInfo[0].NumberOfCores -lt $cpuInfo[0].NumberOfLogicalProcessors
}

function GetNumCpusPerNUMA()
{
    $numcores = $cpuInfo[0].NumberOfCores
    Log "Number of cores per NUMA: $numcores"
    return $numcores
}

function GetNumaCount()
{
    $numaCount = $cpuInfo.Count
    Log "NUMA count: $numaCount"
    return $numaCount
}

function GetCpuClockSpeed()
{
    return $cpuInfo[0].MaxClockSpeed
}


#
# This function takes a specially processed array of counter results Strings
# formatted like "<path> : <value>" and computes the average values of the samples.
#
function Get-CounterAverage([String[]] $statArray)
{
    $sum = 0
    $count = 0
    $endIndex = $statArray.Count - 1 - $CoolDownDurationInSeconds
    $startIndex = $endIndex - $DurationInSeconds

    for ($i = $startIndex; $i -le $endIndex; $i++)
    {
        $value = $statArray[$i].Split(":")[1]
        $value = [Int64] $value.Trim()

        $sum += $value
        $count++
    }

    return $sum / $count
}


#
# Start program
#

#
# Sanity check the parameters & host setup
#

if (IsHyperThreadingEnabled)
{
    Log "ERROR: Hyper-Threading is enabled. Please disable Hyper-Threading before starting the test."
}

$switch = Get-VMSwitch $SwitchName
if ($switch -eq $null)
{
    Log "ERROR: Switch $SwitchName does not exist"
}

if ($switch.Count -gt 1)
{
    Log "ERROR: There are more than one vswitch with the name $SwitchName"
}

if (-not $PSBoundParameters.ContainsKey("MaxCpuNumber"))
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


Log "Collecting performance stats"
Log "DurationInSeconds:               $DurationInSeconds"
Log "BaseCpuNumber:                   $BaseCpuNumber"
Log "MaxCpuNumber:                    $MaxCpuNumber"


#
# Start perfmon monitoring
#
Log ""

$vSwitchCounters = (Get-Counter -ListSet "Hyper-V Virtual Switch").PathsWithInstances | where {$_ -like "*($SwitchName)\Bytes Sent/sec*" -or $_ -like "*($SwitchName)\Packets Sent/sec*"}
$rootVPCounters = (Get-Counter -ListSet "Hyper-V Hypervisor Root Virtual Processor").PathsWithInstances | where {$_ -like "*(Root VP *)\% Total Run Time*"}
$rootVPCounters = $rootVPCounters[(-$BaseCpuNumber-1)..(-$MaxCpuNumber-1)] # rootVPCounters is in reverse order of VP#

$allCounters = $vSwitchCounters + $rootVPCounters

Log "Starting counter collection"
$counterJob = Start-Job -ScriptBlock {param($counters) Get-Counter -Counter $counters -Continuous -SampleInterval 1} -ArgumentList (,$allCounters)

Log "Waiting for counter collection to start..."
$value = Receive-Job $counterJob -Keep
while ($value.Count -lt 1)
{
    $value = Receive-Job $counterJob -Keep
    Start-Sleep 1
} 

$waitTime = $WarmUpDurationInSeconds + $DurationInSeconds + $CoolDownDurationInSeconds
Log "Counter collection started. Waiting for $waitTime seconds ($WarmUpDurationInSeconds seconds of warmup + $DurationInSeconds seconds of active measurement + $CoolDownDurationInSeconds seconds of cool down."
Start-Sleep $waitTime


#
# Retrieve statistics
#
Log ""

Stop-Job $counterJob
$output = (((Receive-Job $counterJob).Readings | Out-String) -replace ":`n",": ") -split "`n|`r`n" | where {$_} # make -like work on output
Remove-Job $counterJob

Log "Calculating bytes/s in vswitch counters, $CoolDownDurationInSeconds seconds from end of run."
$hostCounterRxBytesPerSecAvg = Get-CounterAverage ($output -like "*($SwitchName)\Bytes Sent/sec*")
$hostCounterRxBytesPerSecAvg *= 8

Log "Calculating pkts/s in host switch port counters, $CoolDownDurationInSeconds seconds from end of run."
$hostCounterRxPktsPerSecAvg = Get-CounterAverage ($output -like "*($SwitchName)\Packets Sent/sec*")

# Per proc host VP runtime
$hostVPRuntime = 0
for ($i=$BaseCpuNumber; $i -le $MaxCpuNumber; $i++)
{
    Log "Calculating VP utilization for VP $i, $CoolDownDurationInSeconds seconds from end of run ..."
    $value = Get-CounterAverage ($output -like "*(Root VP $i)\% Total Run Time*")
    Log "`tHost utilization VP[$i]=$([math]::Round($value, 2))"

    $hostVPRuntime += $value
}
$hostVPRuntime = $hostVPRuntime / ($MaxCpuNumber - $BaseCpuNumber + 1)


# Calculate path costs
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

Log ""
Log "==============================Results=============================="
Log ""
Log "CPU speed (cycles per second):                    $cpuCyclesPerSec"
Log "VP Utilization:                                   $([math]::Round($hostVPRuntime,2))"
Log "Total CPU cycles used per second:                 $([math]::Round($totalCyclesPerSec,2))"
Log ""
Log "Bytes/s received through vswitch:                 $([math]::Round($hostCounterRxBytesPerSecAvg,2))"
Log "Packets/s received through vswitch:               $([math]::Round($hostCounterRxPktsPerSecAvg,2))"
Log "Byte path cost (cycles/byte):                     $([math]::Round($bytePathCost,2))"
Log "Packet path cost (cycles/packet):                 $([math]::Round($pktPathCost,2))"
