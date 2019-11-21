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
    [ValidateScript({Get-VMSwitch -Name $_})] # requires admin
    [Parameter(Mandatory=$true)]
    [String] $SwitchName,

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

# Determine which NetAdapters are bound to the vSwitch. RS1 compatible.
$vmSwitch = Get-VMSwitch $SwitchName
switch ($vmSwitch.SwitchType) {
    "External" {
        $nicListKey = "Registry::HKLM\SYSTEM\CurrentControlSet\Services\vmsmp\parameters\NicList\/Device/{0}"
        $boundNetAdapters = Get-NetAdapter | where {$vmSwitch.Id -ieq (Get-ItemProperty -Path ($nicListKey -f $_.DeviceID) -ErrorAction SilentlyContinue).SwitchName}
    }
    "Internal" {
        $boundNetAdapters = Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName | foreach {Get-NetAdapter "vEthernet ($($_.Name))"}
    }
    "Private" {
        throw "Get-VSwitchPathCost : Measurement of private switches is not supported."
    }
}

$rss = Get-NetAdapterRss -Name $boundNetAdapters.Name
$baseCpuNum = ($rss.BaseProcessorNumber | Measure -Minimum).Minimum
$maxCpuNum = ($rss.MaxProcessorNumber | Measure -Maximum).Maximum
Write-Verbose "vSwitch CPUs: $baseCpuNum to $maxCpuNum"

# Query processor info
$cpuInfo = @(Get-CimInstance -ClassName "Win32_Processor" -Property "NumberOfCores", "NumberOfLogicalProcessors", "CurrentClockSpeed", "MaxClockSpeed")
$isHyperThreading = $cpuInfo[0].NumberOfCores -lt $cpuInfo[0].NumberOfLogicalProcessors
$isPowerSavingProfile = $cpuInfo[0].CurrentClockSpeed -lt (0.50 * $cpuInfo[0].MaxClockSpeed)

function PromptToContinue() {
    if (-not $Force) {
        $options = @(
            (New-Object Management.Automation.Host.ChoiceDescription "&Yes","Continue"),
            (New-Object Management.Automation.Host.ChoiceDescription "&No","Exit")
        )

        $result = $Host.UI.PromptForChoice("", "Do you want to continue?", $options, 1)
        if ($result -eq 1) {
            exit 1
        }
    }
}

function Get-Average($Object) {
    return ($Object | Measure-Object -Average).Average
}

#
# Sanity check the parameters & host setup
#

if ($isPowerSavingProfile) {
    Write-Warning "The system is using a power saving profile. This will adversly affect performance."
    PromptToContinue
}

if ($isHyperThreading) {
    Write-Warning "Hyper-Threading is enabled. Hyper-Threading should be disabled for accurate path cost calculation."
    PromptToContinue

    if ($baseCpuNum % 2 -eq 1) {
        Write-Verbose "Setting baseCpuNum to an even value so that both logical cores in an execution unit are measured."
        $baseCpuNum -= 1
    }

    if ($maxCpuNum % 2 -eq 0) {
        Write-Verbose "Setting maxCpuNum to an odd value so that both logical cores in an execution unit are measured."
        $maxCpuNum += 1
    }
}

# Enumerate counter paths. Full path is required to access results.
$cpuUsage          = "\\$env:COMPUTERNAME\Processor Information(_Total)\% Processor Time"
$rootVPUsage       = "\\$env:COMPUTERNAME\Hyper-V Hypervisor Root Virtual Processor(_Total)\% Total Run Time"
$vSwitchThroughput = "\\$env:COMPUTERNAME\Hyper-V Virtual Switch($SwitchName)\Bytes Sent/sec"
$vSwitchPacketRate = "\\$env:COMPUTERNAME\Hyper-V Virtual Switch($SwitchName)\Packets Sent/sec"
$vSwitchVPUsage    = $($baseCpuNum..$maxCpuNum | foreach {"\\$env:COMPUTERNAME\Hyper-V Hypervisor Root Virtual Processor(Root VP $_)\% Total Run Time"})

$countersPaths = $(@($cpuUsage, $rootVPUsage, $vSwitchThroughput, $vSwitchPacketRate) + $vSwitchVPUsage) | foreach {"`"$_`""}

Write-Host "Counter collection started..."
# Restarting typeperf helps avoid an issue where somes counters are always -1.
$null = typeperf $countersPaths -si 1 -sc $Warmup
$output = typeperf $countersPaths -si 1 -sc $($Duration + $Cooldown)

Write-Host "Validating output..."
# Parse as CSV and remove cooldown counters
$countersCSV = $output | select -Skip 1 | select -SkipLast 4 | ConvertFrom-Csv | select -SkipLast $Cooldown

# Check for cells for -1, which indicates the counter query failed.
($countersCSV | Get-Member -MemberType "NoteProperty").Name | foreach {
    if ($countersCSV.$_ -eq -1) {
        Write-Error "Invalid value -1 for counter $_."
        continue
    }
}

Write-Host "Calculating statistics..."
# Average counter values
$avgCPUUsage      = Get-Average $countersCSV.$cpuUsage
$avgRootVPUsage   = Get-Average $countersCSV.$rootVPUsage
$avgThroughput    = Get-Average $countersCSV.$vSwitchThroughput
$avgPacketRate    = Get-Average $countersCSV.$vSwitchPacketRate
$avgSwitchVPUsage = Get-Average $($vSwitchVPUsage | foreach {Get-Average $countersCSV.$_})

# Calculate path costs
$cpuCyclesPerSec = $cpuInfo[0].MaxClockSpeed * 1000000
$totalCyclesPerSec = ($maxCpuNum - $baseCpuNum + 1) * $cpuCyclesPerSec * ($avgSwitchVPUsage / 100)
$bytePathCost = if ($avgThroughput -ne 0) {$totalCyclesPerSec / $avgThroughput} else {0}
$pktPathCost = if ($avgPacketRate -ne 0) {$totalCyclesPerSec / $avgPacketRate} else {0}

#
# Output results
#

$statistics = @(
    @("CPU Utilization", [Math]::Round($avgCPUUsage, 5)),
    @("Total Root VP Utilization", [Math]::Round($avgRootVPUsage, 5)),
    @("vSwitch Root VP Utilization", [Math]::Round($avgSwitchVPUsage, 5)),
    @("Total CPU cycles used per second", [Math]::Round($totalCyclesPerSec, 2)),
    @("Mbps received through vSwitch", [Math]::Round((8 * $avgThroughput) / 1MB, 2)),
    @("Packets/s received through vSwitch", [Math]::Round($avgPacketRate, 2)),
    @("Byte path cost (cycles/byte)", [Math]::Round($bytePathCost, 5)),
    @("Packet path cost (cycles/packet)", [Math]::Round($pktPathCost, 5))
)

$results = New-Object Data.Datatable # makes output pretty
"Statistic", "Value" | foreach {$null = $results.Columns.Add($_)}
$statistics | foreach {$null = $results.Rows.Add($_)}

return $results
