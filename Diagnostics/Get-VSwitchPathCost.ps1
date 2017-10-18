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
.PARAMETER SwitchName
    Required parameter that specifies the vswitch to query packet count from.
.PARAMETER BaseCpuNumber
    Optional parameter that specifies the starting CPU for including in the
    CPU utilization measurement. Default value is 0.
.PARAMETER MaxCpuNumber
    Optional parameter that specifies the ending CPU for including in the CPU
    utilization measurement. Default value is max processor number in the system.
.PARAMETER Warmup
    Optional parameter that specifies warmup time that will not be included in
    the measurement. This time period will be added to Duration for total runtime.
    Default value is 1 second.
.PARAMETER Duration
    Optional parameter that specifies how long the script should collect information.
    This time period does not include the warmup and cooldown time. Minimum 1 second.
    Default value is 90 seconds
.PARAMETER Cooldown
    Optional parameter that specifies cooldown time that will not be included in
    the measurement. This time period will be added to Duration for total runtime.
    Default value is 1 second.
.PARAMETER Force
    Switch parameter that suppresses continue prompts, and will default to 'yes'.
    Without this switch, the user be prompted to continue if a power saving profile 
    or Hyper-Threading is enabled. If none of these features are enabled, then this
    Switch will do nothing.
.EXAMPLE
    Get-VSwitchPathCost.ps1 -Duration 30 -SwitchName MyVSwitch
.NOTES
    This script does not start any traffic. It is the caller's responsibility to ensure
    traffic is already running in steady state, before calling the script.
    The script only collects perfmon counters for the specified during, and computes
    path cost, based on the specified CPU range.

    Note that CPU utilization and path cost can only be accurately measured with Hyper-Threading
    disabled. You can disable Hyper-Threading in the BIOS. However, note that for better
    performance, it should be enabled.
#>

Param(
    [Parameter(Mandatory=$true)]
    [String] $SwitchName,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0, [Int]::MaxValue)]
    [Int] $BaseCpuNumber = 0,

    [Parameter(Mandatory=$false)]
    [ValidateScript({$_ -ge $BaseCpuNumber})] [ValidateRange(0, [Int]::MaxValue)]
    [Int] $MaxCpuNumber,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0, [Int]::MaxValue)]
    [Int] $Warmup = 1,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, [Int]::MaxValue)]
    [Int] $Duration = 90,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0, [Int]::MaxValue)]
    [Int] $Cooldown = 1,

    [Parameter(Mandatory=$false)]
    [Switch] $Force
)

# query processor info
$cpuInfo = @(Get-WmiObject -Class Win32_Processor -Property NumberOfCores, NumberOfLogicalProcessors, CurrentClockSpeed, MaxClockSpeed)
$hyperThreading = $cpuInfo[0].NumberOfCores -lt $cpuInfo[0].NumberOfLogicalProcessors
$systemMaxCpuNumber = ($cpuInfo.Count * $cpuInfo[0].NumberOfLogicalProcessors) - 1
$cpuClockSpeed = $cpuInfo[0].MaxClockSpeed
$isPowerSavingProfile = $cpuInfo[0].CurrentClockSpeed -lt (0.50 * $cpuInfo[0].MaxClockSpeed)

function PromptToContinue()
{
    if (-not $Force)
    {
        $options = @(
            (New-Object Management.Automation.Host.ChoiceDescription "&Yes","Continue"),
            (New-Object Management.Automation.Host.ChoiceDescription "&No","Exit")
        )

        $result = $Host.UI.PromptForChoice("", "Do you want to continue?", $options, 1)
        if ($result -eq 1)
        {
            exit 1
        }
    }
}

#
# This function takes a specially processed array of counter results Strings
# formatted like "<path> : <value>" and computes the average values of the samples.
#
function Get-CounterAverage([String[]] $statArray)
{
    $sum = 0
    $count = 0
    $endIndex = $statArray.Count - 1 - $Cooldown
    $startIndex = $endIndex - $Duration

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

if ($isPowerSavingProfile)
{
    Write-Warning "The system is using a power saving profile. This will adversly affect performance."
    PromptToContinue
}

if ($hyperThreading)
{
    Write-Warning "Hyper-Threading is enabled. Hyper-Threading should be disabled for accurate path cost calculation."
    PromptToContinue
}

if ($BaseCpuNumber -gt $systemMaxCpuNumber)
{
    throw "Get-VSwitchPathCost : BaseCpuNumber is greater than system's maximum CPU number of $systemMaxCpuNumber."
}

if (-not $PSBoundParameters.ContainsKey("MaxCpuNumber"))
{
    $MaxCpuNumber = $systemMaxCpuNumber
}
elseif ($MaxCpuNumber -gt $systemMaxCpuNumber)
{
    throw "Get-VSwitchPathCost : MaxCpuNumber is greater than system's maximum CPU number of $systemMaxCpuNumber."
}

if ($hyperThreading)
{
    if ($BaseCpuNumber % 2 -eq 1)
    {
        Write-Host "Setting BaseCpuNumber to an even value so that both logical cores in an execution unit are measured."
        $BaseCpuNumber -= 1
    }

    if ($MaxCpuNumber % 2 -eq 0)
    {
        Write-Host "Setting MaxCpuNumber to an odd value so that both logical cores in an execution unit are measured."
        $MaxCpuNumber += 1
    }
}

Write-Verbose "BaseCpuNumber: $BaseCpuNumber"
Write-Verbose "MaxCpuNumber:  $MaxCpuNumber"

#
# Start perfmon monitoring
#
$vSwitchCounters = (Get-Counter -ListSet "Hyper-V Virtual Switch").PathsWithInstances | where {$_ -like "*($SwitchName)\Bytes Sent/sec*" -or $_ -like "*($SwitchName)\Packets Sent/sec*"}
if (-not $vSwitchCounters)
{
    throw "Get-VSwitchPathCost : Switch $SwitchName does not exist"
}

$rootVPCounters = (Get-Counter -ListSet "Hyper-V Hypervisor Root Virtual Processor").PathsWithInstances | where {$_ -like "*(Root VP *)\% Total Run Time*"}
$rootVPCounters = $rootVPCounters[(-$BaseCpuNumber-1)..(-$MaxCpuNumber-1)] # rootVPCounters is in reverse order of VP#

$allCounters = $vSwitchCounters + $rootVPCounters
$counterJob = Start-Job -ScriptBlock {param($counters) Get-Counter -Counter $counters -Continuous -SampleInterval 1} -ArgumentList (,$allCounters)

Write-Host "Waiting for counter collection to start..."
$value = Receive-Job $counterJob -Keep
while ($value.Count -lt 1)
{
    $value = Receive-Job $counterJob -Keep
    Start-Sleep 1
}

$waitTime = $Warmup + $Duration + $Cooldown
Write-Host "Counter collection started. Waiting $waitTime seconds ($Warmup`s warmup + $Duration`s active measurement + $Cooldown`s cooldown)"
Start-Sleep $waitTime


#
# Calculate statistics
#
Write-Host "Calculating statistics..."

Stop-Job $counterJob
$output = (((Receive-Job $counterJob).Readings | Out-String) -replace ":`n",": ") -split "`n|`r`n" | where {$_} # make -like work on output
Remove-Job $counterJob

$hostCounterRxBytesPerSecAvg = Get-CounterAverage ($output -like "*($SwitchName)\Bytes Sent/sec*")
$hostCounterRxPktsPerSecAvg = Get-CounterAverage ($output -like "*($SwitchName)\Packets Sent/sec*")

# Per proc host VP runtime
Write-Verbose "Root VP % Usage:"
$hostVPRuntime = 0
for ($i=$BaseCpuNumber; $i -le $MaxCpuNumber; $i++)
{
    $value = Get-CounterAverage ($output -like "*(Root VP $i)\% Total Run Time*")
    Write-Verbose "  VP[$i]=$([Math]::Round($value, 2))"

    $hostVPRuntime += $value
}
$hostVPRuntime = $hostVPRuntime / ($MaxCpuNumber - $BaseCpuNumber + 1)


# Calculate path costs
$cpuCyclesPerSec = $cpuClockSpeed * 1000000
$totalCyclesPerSec = ($MaxCpuNumber - $BaseCpuNumber + 1)  * $cpuCyclesPerSec
$totalCyclesPerSec = $totalCyclesPerSec * $hostVPRuntime / 100
$bytePathCost = 0
if ($hostCounterRxBytesPerSecAvg -ne 0)
{
    $bytePathCost = $totalCyclesPerSec / $hostCounterRxBytesPerSecAvg
}
$pktPathCost = 0
if ($hostCounterRxPktsPerSecAvg -ne 0)
{
    $pktPathCost = $totalCyclesPerSec / $hostCounterRxPktsPerSecAvg
}

#
# Output results
#
$results = New-Object Data.Datatable
"Statistic", "Value" | foreach {$null = $results.Columns.Add($_)}

$statistics = @(
    @("CPU speed (cycles per second)", $cpuCyclesPerSec),
    @("VP Utilization", [Math]::Round($hostVPRuntime, 2)),
    @("Total CPU cycles used per second", [Math]::Round($totalCyclesPerSec, 2)),
    @("Mbps received through vswitch", [Math]::Round((8 * $hostCounterRxBytesPerSecAvg) / 1MB, 2)),
    @("Packets/s received through vswitch", [Math]::Round($hostCounterRxPktsPerSecAvg, 2)),
    @("Byte path cost (cycles/byte)", [Math]::Round($bytePathCost, 2)),
    @("Packet path cost (cycles/packet)", [Math]::Round($pktPathCost, 2))
)

$statistics | foreach {$null = $results.Rows.Add($_)}

return $results
