<#
.SYNOPSIS
    Collects data on system and network configuration for diagnosing Microsoft Networking.
.DESCRIPTION
    Collects comprehensive configuration data to aid in troubleshooting Microsoft Network issues.
    Data is collected from the following sources:
        - Get-NetView metadata (path, args, etc.)
        - Environment (OS, hardware, etc.)
        - Physical, virtual, Container, NICs
        - Virtual Machine configuration
        - Virtual Switches, Bridges, NATs
        - Device Drivers
        - Performance Counters
        - Logs, Traces, etc.

    The data is collected in a folder on the Desktop (by default), which is zipped
    on completion. Send only the .zip file to Microsoft.

    The output is most easily viewed with Visual Studio Code or similar editor with a navigation panel.

    If you receive the error "Get-NetView.ps1 cannot be loaded because running scripts is disabled on this system."
    then enable execution of scripts for the current PowerShell window with the following:
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.PARAMETER OutputDirectory
    Optional path to the directory where the output should be saved. Can be either a relative or an absolute path.
    If unspecified, the current user's Desktop will be used by default.
.PARAMETER ExtraCommands
    Optional list of additional commands, given as ScriptBlocks. Their output is saved to the CustomModule directory,
    which can be accessed by using "$CustomModule" as a placeholder. For example, {Copy-Item .\MyFile.txt $CustomModule}
    copies "MyFile.txt" to "CustomModule\MyFile.txt".
.PARAMETER MaxThreads
    Maximum number of simultaneous background tasks, from 1 to 10. Defaults to 5.
.PARAMETER SkipAdminCheck
    If this switch is present, then the check for administrator privileges will be skipped.
    Note that less data may be collected and the results may be of limited use.
.EXAMPLE
    .\Get-NetView.ps1 -OutputDirectory ".\"
    Runs Get-NetView and outputs to the current working directory.
.EXAMPLE
    .\Get-NetView.ps1 -SkipAdminCheck
    Runs Get-NetView without verifying administrator privileges and outputs to the Desktop.
.NOTES
    Feature Request List
        - Get-WinEvent and system logs: https://technet.microsoft.com/en-us/library/dd367894.aspx?f=255&MSPPError=-2147217396
        - Convert NetSH to NetEvent PS calls.
        - Perf Profile acqusition
        - Remote powershell support
        - Cluster member execution support via remote powershell
        - See this command to get VFs on vSwitch (see text in below functions)
            > Get-NetAdapterSriovVf -SwitchId 2
.LINK
    https://github.com/Microsoft/SDN
#>
Param(
    [parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [String] $OutputDirectory = "",

    [parameter(Mandatory=$false)]
    [ScriptBlock[]] $ExtraCommands = @(),

    [parameter(Mandatory=$false)]
    [ValidateRange(1, 16)]
    [Int] $MaxThreads = 5,

    [parameter(Mandatory=$false)]
    [Switch] $SkipAdminCheck = $false
)

#
# Common Functions
#

$ExecFunctions = {
    $columns   = 4096
    $Global:ThreadPool = $null

    function ExecCommandText {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
        )

        # Mirror command execution context
        $context = "$env:USERNAME @ ${env:COMPUTERNAME}:"
        Write-Output $context | Out-File -Encoding Ascii -Append $Output

        # Mirror command to execute
        $cmdMirror = "$(prompt)$Command"
        Write-Output $cmdMirror | Out-File -Encoding Ascii -Append $Output
    } # ExecCommandText()

    function ExecCommandPrivate {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
        )

        ExecCommandText -Command ($Command) -Output $Output

        # Execute Command and redirect to file. Useful so users know what to run!!!
        Invoke-Expression $Command | Out-File -Encoding Ascii -Append $Output
    } # ExecCommandPrivate()

    enum CommandStatus {
        NotTested    # Indicates problem with TestCommand
        Unavailable  # [Part of] the command doesn't exist
        Failed       # An error prevented successful execution
        Succeeded    # No errors or exceptions
    }

    function TestCommand {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command
        )

        $status = [CommandStatus]::NotTested
        $commandOut = ""

        try {
            $error.Clear()

            # Redirect all command output (expect errors) to stdout.
            # Any errors will still be output to $error variable.
            $silentCmd = '$({0}) 2>$null 3>&1 4>&1 5>&1 6>&1' -f $Command

            # ErrorAction MUST be Stop for try catch to work.
            $commandOut = (Invoke-Expression $silentCmd -ErrorAction Stop)

            # Sometimes commands output errors even on successful execution.
            # We only should fail commands if an error was their *only* output.
            if (($error -ne $null) -and [String]::IsNullOrWhiteSpace($commandOut)) {
                # Some PS commands are incorrectly implemented in return
                # code and require detecting SilentlyContinue
                if ($Command -notlike "*SilentlyContinue*") {
                    throw $error[0]
                }
            }

            $status = [CommandStatus]::Succeeded
        } catch [Management.Automation.CommandNotFoundException] {
            $status = [CommandStatus]::Unavailable
        } catch {
            $status  = [CommandStatus]::Failed
            $commandOut = ($error[0] | Out-String)
        } finally {
            # Post-execution cleanup to avoid false positives
            $error.Clear()
        }

        return $status, $commandOut
    } # TestCommand()

    # Powershell cmdlets have inconsistent implementations in command error handling. This function
    # performs a validation of the command prior to formal execution and will log any failures.
    function ExecCommand {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output,
            [parameter(Mandatory=$false)] [Switch] $Trusted
        )

        $cmdLog = $Command

        if ($Trusted) {
            # Skip command validation
            ExecCommandPrivate -Command $Command -Output $Output
        } else {
            $result, $commandOut = TestCommand -Command $Command

            if ($result -eq [CommandStatus]::Succeeded) {
                ExecCommandText -Command $Command -Output $Output
                $commandOut | Out-File -Encoding Ascii -Append $Output
            } else {
                $cmdLog = "[Command $result] $Command"

                Write-Output "[Command $result]" | Out-File -Encoding ascii -Append $Output
                Write-Output "$Command" | Out-File -Encoding ascii -Append $Output
                Write-Output "$commandOut" | Out-File -Encoding ascii -Append $Output
                Write-Output "`n`n" | Out-File -Encoding ascii -Append $Output
            }
        }

        Write-Host "$cmdLog"
    } # ExecCommand()

    function ExecCommands {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$false)] [Switch] $Trusted,
            [parameter(Mandatory=$true)] [String] $File,
            [parameter(Mandatory=$true)] [String] $OutDir,
            [parameter(Mandatory=$true)] [String[]] $Commands
        )

        $out = (Join-Path -Path $OutDir -ChildPath $File)
        foreach ($cmd in $Commands) {
            ExecCommand -Trusted:$Trusted -Command ($cmd) -Output $out
        }
    } # ExecCommands()
} # $ExecFunctions

. $ExecFunctions # import into script context

function TryCmd {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock
    )

    try {
        $out = &$ScriptBlock
    } catch {
        $out = $null
    }

    # Returning $null will cause foreach to iterate once
    # unless TryCmd call is in parentheses.
    if ($out -eq $null) {
        $out = @()
    }

    return $out
} # TryCmd()

function Open-GlobalThreadPool {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Int] $MaxThreads
    )

    if ($Global:ThreadPool -eq $null)
    {
        $Global:ThreadPool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
        $Global:ThreadPool.Open()
    }
}

function Close-GlobalThreadPool {
    [CmdletBinding()]
    Param()

    if ($Global:ThreadPool -ne $null)
    {
        Write-Host "Cleanup background threads..."
        $Global:ThreadPool.Close()
        $Global:ThreadPool.Dispose()
        $Global:ThreadPool = $null
    }
}

function Start-Thread {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock,
        [parameter(Mandatory=$false)] [ValidateScript({Test-Path $_ -PathType Container})] [String] $StartPath = ".",
        [parameter(Mandatory=$false)] [Hashtable] $Params = @{}
    )

    $ps = [PowerShell]::Create()

    $ps.RunspacePool = $Global:ThreadPool
    $null = $ps.AddScript("Set-Location ""$(Resolve-Path $StartPath)""")
    $null = $ps.AddScript($ExecFunctions) # import into thread context
    $null = $ps.AddScript($ScriptBlock, $true).AddParameters($Params)

    $async = $ps.BeginInvoke()

    return @{Name=$ScriptBlock.Ast.Name; AsyncResult=$async; PowerShell=$ps}
} # Start-Thread()

function Show-Threads {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Hashtable[]] $Threads,
        [parameter(Mandatory=$false)] [Switch] $Sequential
    )

    if ($Sequential) {
        $Threads | foreach {
            $_.Powershell.Streams.Error | Out-Host # blocks until thread completion
            $_.Powershell.Streams.Warning | Out-Host
            $_.Powershell.Streams.Information | Out-Host
            $_.PowerShell.Streams.ClearStreams()
            $_.PowerShell.EndInvoke($_.AsyncResult)   
        }
    } else {
        $mThreads = [Collections.ArrayList]$Threads

        while ($mThreads.Count -gt 0) {
            for ($i = 0; $i -lt $mThreads.Count; $i++) {
                $thread = $mThreads[$i]

                $thread.Powershell.Streams.Warning | Out-Host
                $thread.Powershell.Streams.Warning.Clear()
                $thread.Powershell.Streams.Information | Out-Host
                $thread.Powershell.Streams.Information.Clear()

                if ($thread.AsyncResult.IsCompleted)
                {
                    # Accessing Streams.Error blocks until thread is completed
                    $thread.Powershell.Streams.Error | Out-Host
                    $thread.Powershell.Streams.Error.Clear()

                    $thread.PowerShell.EndInvoke($thread.AsyncResult)
                    $mThreads.RemoveAt($i)
                    $i--
                }
            }
            Start-Sleep -Milliseconds 15
        }
    }
} # Show-Threads()

function ExecCommandsAsync {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [Switch] $Trusted,
        [parameter(Mandatory=$true)] [String] $File,
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [String[]] $Commands
    )

    # uncomment to make script run linearly
    #return ExecCommands @PSBoundParameters
    return Start-Thread -ScriptBlock ${function:ExecCommands} -Params $PSBoundParameters
} # ExecCommandsAsync()

#
# Data Collection Functions
#

function NetIpNic{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = (Join-Path -Path $OutDir -ChildPath "NetIp")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPInterface.txt"
    [String []] $cmds = "Get-NetIPInterface -InterfaceAlias ""$name"" | Out-String -Width $columns",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNeighbor.txt"
    [String []] $cmds = "Get-NetNeighbor -InterfaceAlias ""$name"" | Out-String -Width $columns",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetRoute.txt"
    [String []] $cmds = "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetIpNic()

function NetIp {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetIp")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-List",
                        "Get-NetIpAddress | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPInterface.txt"
    [String []] $cmds = "Get-NetIPInterface | Out-String -Width $columns",
                        "Get-NetIPInterface | Format-Table -AutoSize  | Out-String -Width $columns",
                        "Get-NetIPInterface | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNeighbor.txt"
    [String []] $cmds = "Get-NetNeighbor | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPv4Protocol.txt"
    [String []] $cmds = "Get-NetIPv4Protocol | Out-String -Width $columns",
                        "Get-NetIPv4Protocol | Format-List  -Property *",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPv6Protocol.txt"
    [String []] $cmds = "Get-NetIPv6Protocol | Out-String -Width $columns",
                        "Get-NetIPv6Protocol | Format-List  -Property *",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetOffloadGlobalSetting.txt"
    [String []] $cmds = "Get-NetOffloadGlobalSetting | Out-String -Width $columns",
                        "Get-NetOffloadGlobalSetting | Format-List  -Property *",
                        "Get-NetOffloadGlobalSetting | Format-Table -AutoSize",
                        "Get-NetOffloadGlobalSetting | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetPrefixPolicy.txt"
    [String []] $cmds = "Get-NetPrefixPolicy | Format-Table -AutoSize",
                        "Get-NetPrefixPolicy | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetRoute.txt"
    [String []] $cmds = "Get-NetRoute | Format-Table -AutoSize",
                        "Get-NetRoute | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTCPConnection.txt"
    [String []] $cmds = "Get-NetTCPConnection | Format-Table -AutoSize",
                        "Get-NetTCPConnection | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTcpSetting.txt"
    [String []] $cmds = "Get-NetTcpSetting  | Format-Table -AutoSize",
                        "Get-NetTcpSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTransportFilter.txt"
    [String []] $cmds = "Get-NetTransportFilter  | Format-Table -AutoSize",
                        "Get-NetTransportFilter  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetUDPEndpoint.txt"
    [String []] $cmds = "Get-NetUDPEndpoint  | Format-Table -AutoSize",
                        "Get-NetUDPEndpoint  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetUDPSetting.txt"
    [String []] $cmds = "Get-NetUDPSetting  | Format-Table -AutoSize",
                        "Get-NetUDPSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetIp()

function NetNat {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetNat")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetNat.txt"
    [String []] $cmds = "Get-NetNat | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNat | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNat | Format-List",
                        "Get-NetNat | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatExternalAddress.txt"
    [String []] $cmds = "Get-NetNatExternalAddress | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatExternalAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatExternalAddress | Format-List",
                        "Get-NetNatExternalAddress | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatGlobal.txt"
    [String []] $cmds = "Get-NetNatGlobal | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatGlobal | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatGlobal | Format-List",
                        "Get-NetNatGlobal | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatSession.txt"
    [String []] $cmds = "Get-NetNatSession | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatSession | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatSession | Format-List",
                        "Get-NetNatSession | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatStaticMapping.txt"
    [String []] $cmds = "Get-NetNatStaticMapping | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatStaticMapping | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatStaticMapping | Format-List",
                        "Get-NetNatStaticMapping | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

} # NetNat()

function NetAdapterWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = $OutDir

    $file = "Get-NetAdapter.txt"
    [String []] $cmds = "Get-NetAdapter -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapter -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterAdvancedProperty.txt"
    [String []] $cmds = "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties | Sort-Object RegistryKeyword | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Sort-Object RegistryKeyword | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-Table  -Property * | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterBinding.txt"
    [String []] $cmds = "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Sort-Object ComponentID | Out-String -Width $columns",
                        "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterChecksumOffload.txt"
    [String []] $cmds = "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterLso.txt"
    [String []] $cmds = "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRss.txt"
    [String []] $cmds = "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterStatistics.txt"
    [String []] $cmds = "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterEncapsulatedPacketTaskOffload.txt"
    [String []] $cmds = "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterHardwareInfo.txt"
    [String []] $cmds = "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterIPsecOffload.txt"
    [String []] $cmds = "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterPowerManagement.txt"
    [String []] $cmds = "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterQos.txt"
    [String []] $cmds = "Get-NetAdapterQos -Name ""$name"" -IncludeHidden -ErrorAction SilentlyContinue | Out-String -Width $columns",
                        "Get-NetAdapterQos -Name ""$name"" -IncludeHidden -ErrorAction SilentlyContinue | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRdma.txt"
    [String []] $cmds = "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterPacketDirect.txt"
    [String []] $cmds = "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRsc.txt"
    [String []] $cmds = "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterSriov.txt"
    [String []] $cmds = "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterSriovVf.txt"
    [String []] $cmds = "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVmq.txt"
    [String []] $cmds = "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVmqQueue.txt"
    [String []] $cmds = "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVPort.txt"
    [String []] $cmds = "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetAdapterWorker()

function NetAdapterWorkerPrepare {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicDesc,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $desc = $NicDesc

    # Create dir for each NIC
    $nic     = Get-NetAdapter -InterfaceDescription $desc
    $idx     = $nic.IfIndex
    $name    = $nic.Name
    $title   = "pNic.$idx.$name.$desc"
    $dir     = (Join-Path -Path $OutDir -ChildPath "$title")
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host "Processing: $title"
    NetIpNic         -NicName $name -OutDir $dir
    NetAdapterWorker -NicName $name -OutDir $dir
    NicVendor        -NicName $name -OutDir $dir
} # NetAdapterWorkerPrepare()

function LbfoWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $LbfoName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name  = $LbfoName
    $title = "LBFO.$name"
    $dir   = (Join-Path -Path $OutDir -ChildPath "$title")
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host "Processing: $title"
    $file = "Get-NetLbfoTeam.txt"
    [String []] $cmds = "Get-NetLbfoTeam -Name ""$name""",
                        "Get-NetLbfoTeam -Name ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeamNic.txt"
    [String []] $cmds = "Get-NetLbfoTeamNic -Team ""$name""",
                        "Get-NetLbfoTeamNic -Team ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeamMember.txt"
    [String []] $cmds = "Get-NetLbfoTeamMember -Team ""$name""",
                        "Get-NetLbfoTeamMember -Team ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # Report the TNIC(S)
    foreach ($tnic in TryCmd {Get-NetLbfoTeamNic -Team $name}) {
        NetAdapterWorkerPrepare -NicDesc $tnic.InterfaceDescription -OutDir $OutDir
    }

    # Report the NIC Members
    foreach ($mnic in TryCmd {Get-NetLbfoTeamMember -Team $name}) {
        NetAdapterWorkerPrepare -NicDesc $mnic.InterfaceDescription -OutDir $OutDir
    }
} # LbfoWorker()

function LbfoDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Cache output
    $externalVMSwitches = TryCmd {Get-VMSwitch | where {$_.SwitchType -eq "External"}}

    foreach ($lbfo in TryCmd {Get-NetLbfoTeam}) {
        # Skip all vSwitch Protocol NICs since the LBFO and member reporting will occur as part of
        # vSwitch reporting.
        $match = $false

        $netAdapter = Get-NetAdapter -Name $lbfo.Name

        foreach ($vmSwitch in $externalVMSwitches) {
            if ($vmSwitch.NetAdapterInterfaceDescriptions -contains $netAdapter.InterfaceDescription) {
                $match = $true
                break
            }
        }

        if (-not $match) {
            LbfoWorker -LbfoName $lbfo.Name -OutDir $dir
        }
    }
} # LbfoDetail()

function ProtocolNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMSwitchId
    $dir = $OutDir

    # Distinguish between LBFO from standard PTNICs and create the hierarchies accordingly
    foreach ($desc in TryCmd {(Get-VMSwitch -Id $id).NetAdapterInterfaceDescriptions}) {
        $nic = Get-NetAdapter -InterfaceDescription $desc
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            LbfoWorker -LbfoName $nic.Name -OutDir $dir
        } else {
            NetAdapterWorkerPrepare -NicDesc $desc -OutDir $dir
        }
    }
} # ProtocolNicDetail()

function NativeNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Cache output
    $externalVMSwitches = TryCmd {Get-VMSwitch | where {$_.SwitchType -eq "External"}}
    $lbfoNics = TryCmd {Get-NetLbfoTeamMember}

    foreach ($nic in Get-NetAdapter) {
        $native = $true

        # Skip vSwitch Host vNICs by checking the driver
        if (@("vmswitch.sys", "VmsProxyHNic.sys") -contains $nic.DriverFileName) {
            continue
        }

        # Skip LBFO TNICs by checking the driver
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            continue
        }

        # Skip all vSwitch Protocol NICs
        foreach ($vmSwitch in $externalVMSwitches) {
            if ($vmSwitch.NetAdapterInterfaceDescriptions -contains $nic.InterfaceDescription) {
                $native = $false
                break
            }
        }

        # Skip LBFO Team Member Adapters
        foreach ($lbfonic in $lbfoNics) {
            if ($nic.InterfaceDescription -eq $lbfonic.InterfaceDescription) {
                $native = $false
                break
            }
        }

        if ($native) {
            NetAdapterWorkerPrepare -NicDesc $nic.InterfaceDescription -OutDir $dir
        }
    }
} # NativeNicDetail()

function ChelsioDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "ChelsioDetail")
    New-Item -ItemType Directory -Path $dir | Out-Null

    # Collect Chelsio related event logs and miscellaneous details
    $file = "ChelsioDetail-Eventlog-BusDevice.txt"
    [String []] $cmds = "Get-EventLog -LogName System -Source ""*chvbd*"" -ErrorAction SilentlyContinue | Format-List",
                        "Get-EventLog -LogName System -Source ""*cht4vbd*"" -ErrorAction SilentlyContinue | Format-List"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "ChelsioDetail-Eventlog-NetDevice.txt"
    [String []] $cmds = "Get-EventLog -LogName System -Source ""*chndis*"" -ErrorAction SilentlyContinue | Format-List",
                        "Get-EventLog -LogName System -Source ""*chnet*"" -ErrorAction SilentlyContinue | Format-List",
                        "Get-EventLog -LogName System -Source ""*cht4ndis*"" -ErrorAction SilentlyContinue | Format-List"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "ChelsioDetail-Misc.txt"
    [String []] $cmds = "verifier /query",
                        "Get-PnpDevice -FriendlyName ""*Chelsio*Enumerator*"" | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_DriverVersion | Format-Table -Autosize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # Basic sanity check. Most of Chelsio related logs are collected using cxgbtool.exe.
    # So if cxgbtool.exe is not there in System32 forlder, then exit from the function.
    $cxgbtool = Get-Item "$env:windir\System32\cxgbtool.exe" -ErrorAction SilentlyContinue
    if ($cxgbtool.Exists -eq $null) {
        Write-Warning "Unable to collect Chelsio debug logs as cxgbtool is not present in $env:windir\system32"
        return
    }

    $ifName = $NicName
    $ifIndex = (Get-NetAdapter $NicName).ifIndex
    $ifHwInfo = Get-NetAdapterHardwareInfo -Name "$ifName"
    $dirBusName = "BusDev_$($ifHwInfo.Bus)_$($ifHwInfo.Device)_$($ifHwInfo.Function)"
    $dirBus = (Join-Path -Path $dir -ChildPath $dirBusName)

    if ($Script:ChelsioOncePerASIC -notcontains $dirBusName) {
        $Script:ChelsioOncePerASIC += @($dirBusName) # expensive, avoid duplicate effort
        New-Item -ItemType Directory -Path $dirBus | Out-Null

        # Enumerate VBD
        [String] $ifNameVbd = $null
        [Array] $PnPDevices = Get-PnpDevice -FriendlyName "*Chelsio*Enumerator*" | where {$_.Status -eq "OK"}
        for ($i = 0; $i -lt $PnPDevices.Count; $i++) {
            $instanceId = $PnPDevices[$i].InstanceId
            $locationInfo = (Get-PnpDeviceProperty -InstanceId "$instanceId" -KeyName "DEVPKEY_Device_LocationInfo").Data
            if ($ifHwInfo.LocationInformationString -eq $locationInfo) {
                $ifNameVbd = "vbd$i"
                break
            }
        }

        if ([String]::IsNullOrEmpty($ifNameVbd)) {
            Write-Warning "Couldn't resolve interface name for bus device"
            return
        }

        $file = "ChelsioDetail-Cudbg.txt"
        $CollectFile = "Cudbg-Collect.dmp"
        $ReadFlashFile = "Cudbg-Readflash.dmp"
        $OutCollect = (Join-Path -Path $dirBus -ChildPath $CollectFile)
        $OutReadFlash = (Join-Path -Path $dirBus -ChildPath $ReadFlashFile)
        [String []] $cmds = "cxgbtool.exe $ifNameVbd cudbg collect all ""$OutCollect""",
                            "cxgbtool.exe $ifNameVbd cudbg readflash ""$OutReadFlash"""
        ExecCommandsAsync -Trusted -OutDir $dirBus -File $file -Commands $cmds

        $file = "ChelsioDetail-Firmware-BusDevice$i.txt"
        [String []] $cmds = "cxgbtool.exe $ifNameVbd firmware mbox 1",
                            "cxgbtool.exe $ifNameVbd firmware mbox 2",
                            "cxgbtool.exe $ifNameVbd firmware mbox 3",
                            "cxgbtool.exe $ifNameVbd firmware mbox 4",
                            "cxgbtool.exe $ifNameVbd firmware mbox 5",
                            "cxgbtool.exe $ifNameVbd firmware mbox 6",
                            "cxgbtool.exe $ifNameVbd firmware mbox 7"
        ExecCommandsAsync -OutDir $dirBus -File $file -Commands $cmds

        $file = "ChelsioDetail-Hardware-BusDevice$i.txt"
        $flashFile = "Hardware-BusDevice$i-flash.dmp"
        $OutFlash = (Join-Path -Path $dirBus -ChildPath $flashFile)
        [String []] $cmds = "cxgbtool.exe $ifNameVbd hardware sgedbg",
                            "cxgbtool.exe $ifNameVbd hardware flash ""$OutFlash"""
        ExecCommandsAsync -OutDir $dirBus -File $file -Commands $cmds
    } # $Script:ChelsioOncePerASIC

    $dirNetName = "NetDev_$ifIndex"
    $dirNet = (Join-Path -Path $dir -ChildPath $dirNetName)
    New-Item -ItemType Directory -Path $dirNet | Out-Null

    # Enumerate NIC
    [Array] $NetDevices = Get-NetAdapter -InterfaceDescription "*Chelsio*" | where {$_.Status -eq "Up"} | Sort-Object -Property MacAddress
    $ifNameNic = $null
    for ($i = 0; $i -lt $NetDevices.Count; $i++) {
        if ($ifName -eq $NetDevices[$i].Name) {
            $ifNameNic = "nic$i"
            break
        }
    }

    if ([String]::IsNullOrEmpty($ifNameNic)) {
        Write-Warning "Couldn't resolve interface name for Network device(ifIndex:$ifIndex)"
        return
    }

    $file = "ChelsioDetail-Debug.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameNic debug filter",
                        "cxgbtool.exe $ifNameNic debug qsets",
                        "cxgbtool.exe $ifNameNic debug qstats txeth rxeth txvirt rxvirt txrdma rxrdma txnvgre rxnvgre",
                        "cxgbtool.exe $ifNameNic debug dumpctx",
                        "cxgbtool.exe $ifNameNic debug version",
                        "cxgbtool.exe $ifNameNic debug eps",
                        "cxgbtool.exe $ifNameNic debug qps",
                        "cxgbtool.exe $ifNameNic debug rdma_stats",
                        "cxgbtool.exe $ifNameNic debug stags",
                        "cxgbtool.exe $ifNameNic debug l2t"
    ExecCommandsAsync -OutDir $dirNet -File $file -Commands $cmds

    $file = "ChelsioDetail-Hardware.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameNic hardware tid_info",
                        "cxgbtool.exe $ifNameNic hardware fec",
                        "cxgbtool.exe $ifNameNic hardware link_cfg",
                        "cxgbtool.exe $ifNameNic hardware pktfilter",
                        "cxgbtool.exe $ifNameNic hardware sensor"
    ExecCommandsAsync -OutDir $dirNet -File $file -Commands $cmds
} # ChelsioDetail()

# ========================================================================
# function stub for extension by IHV
# Copy and rename it, add your commands, and call it in NicVendor() below
# ========================================================================
function MyVendorDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = Join-Path -Path $OutDir -ChildPath "MyVendorDetail"

    # Try to keep the layout of this block of code
    # Feel free to copy it or wrap it in other control structures
    # See other functions in this file for examples
    $file = "$NicName.MyVendor.txt"
    [String []] $cmds = "Command 1",
                        "Command 2",
                        "Command 3",
                        "etc."
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # MyVendorDetail()

function NicVendor {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName, # Get-NetAdapter output
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Call appropriate vendor specific function
    $pciId = (Get-NetAdapterAdvancedProperty -Name $NicName -AllProperties -RegistryKeyword "ComponentID").RegistryValue
    switch -Wildcard($pciId) {
        "CHT*BUS\chnet*" {
            ChelsioDetail $NicName $dir
        }
        # Not implemented.  See MyVendorDetail() for examples.
        #
        #"PCI\VEN_15B3*" {
        #    MellanoxDetail $Nic $dir
        #
        #}
        #"PCI\VEN_8086*" {
        #    IntelDetail $Nic $dir
        #}
        default {
            # Not implemented, not native, or N/A
        }
    }
} # NicVendor()

function HostVNicWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $HostVNicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $HostVNicName
    $dir  = $OutDir

    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterIsolation.txt"
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterVlan.txt"
    [String []] $cmds = "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # HostVNicWorker()

function HostVNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Cache output
    $allNetAdapters = Get-NetAdapter -IncludeHidden

    foreach ($nic in TryCmd {Get-VMNetworkAdapter -ManagementOS} | where {$_.SwitchId -eq $VMSwitchId}) {
        <#
            Correlate to VMNic instance to NetAdapter instance view
            Physical to Virtual Mapping.
            -----------------------------
            Get-NetAdapter uses:
               Name                    : vEthernet (VMS-Ext-Public) 2
            Get-VMNetworkAdapter uses:
               Name                    : VMS-Ext-Public

            Thus we need to match the corresponding devices via DeviceID such that
            we can execute VMNetworkAdapter and NetAdapter information for this hNIC
        #>
        $idx = 0
        foreach($pnic in $allNetAdapters) {
            if ($pnic.DeviceID -eq $nic.DeviceId) {
                $pnicname = $pnic.Name
                $idx      = $pnic.IfIndex
            }
        }

        # Create dir for each NIC
        $name    = $nic.Name
        $title   = "hNic.$idx.$name"
        $dir     = (Join-Path -Path $OutDir -ChildPath "$title")
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Host "Processing: $title"
        NetIpNic         -NicName      $pnicname -OutDir $dir
        HostVNicWorker   -HostVNicName $name     -OutDir $dir
        NetAdapterWorker -NicName      $pnicname -OutDir $dir
    }
} # HostVNicDetail()

function VMNetworkAdapterDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMName,
        [parameter(Mandatory=$true)] [String] $VMNicName,
        [parameter(Mandatory=$true)] [String] $VMNicId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name  = $VMNicName
    $id    = $VMNicId
    $title = "VMNic.$name.$id"
    $dir   = (Join-Path -Path $OutDir -ChildPath "$title")
    New-Item -ItemType directory -Path $dir | Out-Null

    # We must use Id to identity VMNics, because different VMNics
    # can have the same MAC (if VM is off), Name, VMName, and SwitchName.
    [String] $vmNicObject = "`$(Get-VMNetworkAdapter -VMName ""$VMName"" | where {(`$_.Id -split ""\\"")[1] -eq ""$id""})"

    Write-Host "Processing: $title"
    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "$vmNicObject | Out-String -Width $columns",
                        "$vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterAcl -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterIsolation.txt"
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterVlan.txt"
    [String []] $cmds = "Get-VMNetworkAdapterVlan -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionPortFeature.txt"
    [String []] $cmds = "Get-VMSwitchExtensionPortFeature -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionPortData.txt"
    [String []] $cmds = "Get-VMSwitchExtensionPortData -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
    #>
} # VMNetworkAdapterDetail()

function VMWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMId
    $dir = $OutDir

    # Different VMs can have the same name
    [String] $vmObject = "`$(Get-VM -Id $id)"

    $file = "Get-VM.txt"
    [String []] $cmds = "$vmObject | Out-String -Width $columns",
                        "$vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMBios.txt"
    [String []] $cmds = "Get-VMBios -VM $vmObject | Out-String -Width $columns",
                        "Get-VMBios -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMFirmware.txt"
    [String []] $cmds = "Get-VMFirmware -VM $vmObject | Out-String -Width $columns",
                        "Get-VMFirmware -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMProcessor.txt"
    [String []] $cmds = "Get-VMProcessor -VM $vmObject | Out-String -Width $columns",
                        "Get-VMProcessor -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMMemory.txt"
    [String []] $cmds = "Get-VMMemory -VM $vmObject | Out-String -Width $columns",
                        "Get-VMMemory -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMVideo.txt"
    [String []] $cmds = "Get-VMVideo -VM $vmObject | Out-String -Width $columns",
                        "Get-VMVideo -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHardDiskDrive.txt"
    [String []] $cmds = "Get-VMHardDiskDrive -VM $vmObject | Out-String -Width $columns",
                        "Get-VMHardDiskDrive -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMComPort.txt"
    [String []] $cmds = "Get-VMComPort -VM $vmObject | Out-String -Width $columns",
                        "Get-VMComPort -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSecurity.txt"
    [String []] $cmds = "Get-VMSecurity -VM $vmObject | Out-String -Width $columns",
                        "Get-VMSecurity -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMWorker()

function VMNetworkAdapterPerVM {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    [Int] $index = 1
    foreach ($vm in TryCmd {Get-VM}) {
        $vmName = $vm.Name
        $vmId   = $vm.VMId
        $title  = "VM.$index.$vmName"

        $dir    = (Join-Path -Path $OutDir -ChildPath "$title")

        $vmQuery = $false
        foreach ($vmNic in TryCmd {Get-VMNetworkAdapter -VM $vm} | where {$_.SwitchId -eq $VMSwitchId}) {
            $vmNicId = ($vmNic.Id -split "\\")[1] # Same as AdapterId, but works if VM is off

            if (-not $vmQuery)
            {
                Write-Host "Processing: $title"
                New-Item -ItemType "Directory" -Path $dir | Out-Null
                VMWorker -VMId $vmId -OutDir $dir
                $vmQuery = $true
            }

            VMNetworkAdapterDetail -VMName $vmName -VMNicName $vmNic.Name -VMNicId $vmNicId -OutDir $dir
        }

        $index++
    }
} # VMNetworkAdapterPerVM()

function VMSwitchWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMSwitchId
    $dir = $OutDir

    $vmSwitchObject = "`$(Get-VMSwitch -Id $id)"

    $file = "Get-VMSwitch.txt"
    [String []] $cmds = "$vmSwitchObject",
                        "$vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtension.txt"
    [String []] $cmds = "Get-VMSwitchExtension -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionSwitchData.txt"
    [String []] $cmds = "Get-VMSwitchExtensionSwitchData -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionSwitchFeature.txt"
    [String []] $cmds = "Get-VMSwitchExtensionSwitchFeature -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchTeam.txt"
    [String []] $cmds = "Get-VMSwitchTeam -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMSwitchWorker()

function VfpExtensionDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id = $VMSwitchId
    $vfpExtension = TryCmd {Get-VMSwitch -Id $id | Get-VMSwitchExtension} | where {$_.Name -like "Microsoft Azure VFP Switch Extension"}

    if ($vfpExtension.Enabled -ne "True") {
        return
    }

    $dir  = (Join-Path -Path $OutDir -ChildPath "VFP")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "VfpCtrl.help.txt"
    [String []] $cmds = "vfpctrl.exe /h"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $switches = Get-WmiObject -Namespace "root\virtualization\v2" -Class "Msvm_VirtualEthernetSwitch"
    foreach ($vmSwitch in $switches) {
        if ($vmSwitch.Name -eq $id) {
            $currswitch = $vmSwitch
            break
        }
    }

    $ports = $currswitch.GetRelated("Msvm_EthernetSwitchPort", "Msvm_SystemDevice", $null, $null, $null, $null, $false, $null)
    foreach ($port in $ports) {
        $file     = "VfpCtrl.PortGuid.$portGuid.txt"
        $portGuid = $port.Name
        [String []] $cmds = "vfpctrl.exe /list-space /port $portGuid",
                            "vfpctrl.exe /list-mapping /port $portGuid",
                            "vfpctrl.exe /list-rule /port $portGuid",
                            "vfpctrl.exe /port $portGuid /get-port-state"
        ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
    }
} # VfpExtensionDetail()

function VMSwitchDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # FIXME!!!
    # See this command to get VFs on vSwitch
    # Get-NetAdapterSriovVf -SwitchId 2

    [Int] $index = 1
    foreach ($vmSwitch in TryCmd {Get-VMSwitch}) {
        $name  = $vmSwitch.Name
        $type  = $vmSwitch.SwitchType
        $id    = $vmSwitch.Id
        $title = "VMSwitch.$index.$type.$name"

        $dir  = (Join-Path -Path $OutDir -ChildPath "$title")
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Host "Processing: $title"
        VfpExtensionDetail    -VMSwitchId $id -OutDir $dir
        VMSwitchWorker        -VMSwitchId $id -OutDir $dir
        ProtocolNicDetail     -VMSwitchId $id -OutDir $dir
        HostVNicDetail        -VMSwitchId $id -OutDir $dir
        VMNetworkAdapterPerVM -VMSwitchId $id -OutDir $dir

        $index++
    }
} # VMSwitchDetail()

function NetworkSummary {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "Get-VMSwitch.txt"
    [String []] $cmds = "Get-VMSwitch | Sort-Object Name",
                        "Get-VMSwitch | Sort-Object Name | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "Get-VMNetworkAdapter -All | Sort-Object Name | Format-Table -AutoSize",
                        "Get-VMNetworkAdapter -All | Sort-Object Name | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSystemSwitchExtension.txt"
    [String []] $cmds = "Get-VMSystemSwitchExtension | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSystemSwitchExtensionSwitchFeature.txt"
    [String []] $cmds = "Get-VMSystemSwitchExtensionSwitchFeature",
                        "Get-VMSystemSwitchExtensionSwitchFeature | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapter.txt"
    [String []] $cmds = "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -AutoSize",
                        "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterStatistics.txt"
    [String []] $cmds = "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Autosize  | Out-String -Width $columns",
                        "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -Autosize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeam.txt"
    [String []] $cmds = "Get-NetLbfoTeam | Sort-Object InterfaceDescription",
                        "Get-NetLbfoTeam | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize  | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress | Format-Table -Autosize",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "ipconfig.txt"
    [String []] $cmds = "ipconfig",
                        "ipconfig /allcompartments /all"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetworkSummary()

function SMBDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "SMB")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-SmbClientNetworkInterface.txt"
    [String []] $cmds = "Get-SmbClientNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbClientNetworkInterface | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbServerNetworkInterface.txt"
    [String []] $cmds = "Get-SmbServerNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbServerNetworkInterface | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbClientConfiguration.txt"
    [String []] $cmds = "Get-SmbClientConfiguration"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbMultichannelConnection.txt"
    [String []] $cmds = "Get-SmbMultichannelConnection | Sort-Object Name | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbMultichannelConnection -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection -SmbInstance CSV -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection -SmbInstance SBL -IncludeNotSelected | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbMultichannelConstraint.txt"
    [String []] $cmds = "Get-SmbMultichannelConstraint"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Smb-WindowsEvents.txt"
    [String []] $cmds = "Get-WinEvent -ListLog ""*SMB*"" | Format-List -Property *",
                        "Get-WinEvent -ListLog ""*SMB*"" | Get-WinEvent | ? Message -like ""*RDMA*"" | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # SMBDetail()

function NetSetupDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetSetup")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "NetSetup.txt"
    [String []] $cmds = "Test-Path $env:SystemRoot\System32\NetSetupMig.log",
                        "Test-Path $env:SystemRoot\Panther\setupact.log",
                        "Test-Path $env:SystemRoot\INF\setupapi.*",
                        "Test-Path $env:SystemRoot\logs\NetSetup"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # Copy over the logs
    [String []] $cmds = "$env:SystemRoot\System32\NetSetupMig.log",
                        "$env:SystemRoot\Panther\setupact.log",
                        "$env:SystemRoot\INF\setupapi.*",
                        "$env:SystemRoot\logs\NetSetup"
    $cmds = $cmds | foreach {"Copy-Item $_ $dir -Recurse -Verbose 4>&1"}
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds
} # NetSetupDetail()

function HNSDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    try {
        $null = Get-Service "hns" -ErrorAction Stop
    } catch {
        Write-Host "HNSDetail: hns service not found, skipping."
        return
    }

    $dir = (Join-Path -Path $OutDir -ChildPath "HNS")
    New-Item -ItemType Directory -Path $dir | Out-Null

    # Data collected before stop -> start must be collected synchronously

    $file = "HNSRegistry-1.txt"
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\hns -Recurse",
                        "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSNetwork-1.txt"
    [String []] $cmds = "Get-HNSNetwork | ConvertTo-Json -Depth 10"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSEndpoint-1.txt"
    [String []] $cmds = "Get-HNSEndpoint | ConvertTo-Json -Depth 10"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    # HNS service stop -> start occurs after capturing the current HNS state info.
    $hnsRunning = (Get-Service hns).Status -eq "Running"
    try {
        if ($hnsRunning) {
            # Force stop to avoid command line prompt
            $null = net stop hns /y
        }

        $file = "HNSData.txt"
        [String []] $cmds = "Copy-Item ""$env:ProgramData\Microsoft\Windows\HNS\HNS.data"" $dir 4>&1"
        ExecCommands -OutDir $dir -File $file -Commands $cmds
    } finally {
        if ($hnsRunning) {
            $null = net start hns
        }
    }

    # Acquire all settings again after stop -> start services
    # From now on we can collect data asynchronously.
    $file = "HNSRegistry-2.txt"
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\hns -Recurse",
                        "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSNetwork-2.txt"
    [String []] $cmds = "Get-HNSNetwork | ConvertTo-Json -Depth 10"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSEndpoint-2.txt"
    [String []] $cmds = "Get-HNSEndpoint | ConvertTo-Json -Depth 10"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    #netsh trace start scenario=Virtualization provider=Microsoft-Windows-tcpip provider=Microsoft-Windows-winnat capture=yes captureMultilayer=yes capturetype=both report=disabled tracefile=$dir\server.etl overwrite=yes
    #Start-Sleep 120
    #netsh trace stop
} # HNSDetail()

function QosDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetQoS")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetAdapterQos.txt"
    [String []] $cmds = "Get-NetAdapterQos",
                        "Get-NetAdapterQos -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterQos -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosDcbxSetting.txt"
    [String []] $cmds = "Get-NetQosDcbxSetting",
                        "Get-NetQosDcbxSetting | Format-List  -Property *",
                        "Get-NetQosDcbxSetting | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosFlowControl.txt"
    [String []] $cmds = "Get-NetQosFlowControl",
                        "Get-NetQosFlowControl | Format-List  -Property *",
                        "Get-NetQosFlowControl | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosPolicy.txt"
    [String []] $cmds = "Get-NetQosPolicy",
                        "Get-NetQosPolicy | Format-List  -Property *",
                        "Get-NetQosPolicy | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosTrafficClass.txt"
    [String []] $cmds = "Get-NetQosTrafficClass",
                        "Get-NetQosTrafficClass | Format-List  -Property *",
                        "Get-NetQosTrafficClass | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # QosDetail()

function ServicesDrivers {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "ServicesDrivers")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "sc.txt"
    [String []] $cmds = "sc.exe queryex vmsp",
                        "sc.exe queryex vmsproxy"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-Service.txt"
    [String []] $cmds = "Get-Service ""*"" | Sort-Object Name | Format-Table -AutoSize",
                        "Get-Service ""*"" | Sort-Object Name | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WindowsDriver.txt"
    [String []] $cmds = "Get-WindowsDriver -Online -All" # very slow, -Trusted to skip validation
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WindowsEdition.txt"
    [String []] $cmds = "Get-WindowsEdition -Online"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WmiObject.Win32_PnPSignedDriver.txt"
    [String []] $cmds = "Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # ServicesDrivers()

function NetshTrace {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "Netsh")
    New-Item -ItemType directory -Path $dir | Out-Null

    <# Deprecated / DELETEME
        #Figure out how to get this netsh rundown command executing under Powershell with logging...
        $ndiswpp = "{DD7A21E6-A651-46D4-B7C2-66543067B869}"
        $vmswpp  = "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"
        netsh trace start provider=$vmswpp level=1 keywords=0x00010000 provider=$ndiswpp level=1 keywords=0x02 correlation=disabled report=disabled overwrite=yes tracefile=$dir\NetRundown.etl
        netsh trace stop
    #>

    #$wpp_vswitch  = "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"
    #$wpp_ndis     = "{DD7A21E6-A651-46D4-B7C2-66543067B869}"

    # The sequence below triggers the ETW providers to dump their internal traces when the session starts.  Thus allowing for capturing a
    # snapshot of their logs/traces.
    #
    # NOTE: This does not cover IFR (in-memory) traces.  More work needed to address said traces.
    $file = "NetRundown.txt"
    [String []] $cmds = "New-NetEventSession    NetRundown -CaptureMode SaveToFile -LocalFilePath $dir\NetRundown.etl",
                        "Add-NetEventProvider   ""{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x10000",
                        "Add-NetEventProvider   ""{DD7A21E6-A651-46D4-B7C2-66543067B869}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x2",
                        "Start-NetEventSession  NetRundown",
                        "Stop-NetEventSession   NetRundown",
                        "Remove-NetEventSession NetRundown"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds

    #
    # The ETL file can be converted to text using the following command:
    #    netsh trace convert NetRundown.etl tmfpath=\\winbuilds\release\RS_ONECORE_STACK_SDN_DEV1\15014.1001.170117-1700\amd64fre\symbols.pri\TraceFormat
    #    Specifying a path to the TMF symbols. Output is attached.

    $file = "NetshDump.txt"
    [String []] $cmds = "netsh dump"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "NetshStatistics.txt"
    [String []] $cmds = "netsh interface ipv4 show icmpstats",
                        "netsh interface ipv4 show ipstats",
                        "netsh interface ipv4 show tcpstats",
                        "netsh interface ipv4 show udpstats",
                        "netsh interface ipv6 show ipstats",
                        "netsh interface ipv6 show tcpstats",
                        "netsh interface ipv6 show udpstats"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds

    Write-Host "`n"
    Write-Host "Processing..."
    $file = "NetshTrace.txt"
    [String []] $cmds = "netsh -?",
                        "netsh trace show scenarios",
                        "netsh trace show providers",
                        "netsh trace diagnose scenario=NetworkSnapshot mode=Telemetry saveSessionTrace=yes report=yes ReportFile=$dir\Snapshot.cab"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds
} # NetshTrace()

function OneX {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "OneX")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "OneX.txt"
    [String []] $cmds = "netsh lan show interface",
                        "netsh lan show profile"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
}

function Counters {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "Counters")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "CounterSetName.txt"
    [String []] $cmds = "Get-Counter -ListSet * | Sort-Object CounterSetName | Select-Object CounterSetName | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "CounterSetName.Paths.txt"
    [String []] $cmds = "(Get-Counter -ListSet * | Sort-Object CounterSetName).Paths | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "CounterSetName.PathsWithInstances.txt"
    [String []] $cmds = "(Get-Counter -ListSet * | Sort-Object CounterSetName).PathsWithInstances | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "CounterSet.Property.txt"
    [String []] $cmds = "(Get-Counter -ListSet * | Sort-Object CounterSetName) | Format-List -Property * | Out-String -Width $columns",
                        "(Get-Counter -ListSet * | Sort-Object CounterSetName) | Format-Table -Property * | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "CounterDetail" # used with 2 different extensions
    $out  = (Join-Path -Path $dir -ChildPath $file)
    # Get paths for counters of interest
    # Be careful what you add to this, Get-Counter runtime scales
    # exponetially with respect to the number of counter instances.
    $listSet = @("Hyper-V*", "ICMP*", "*Intel*", "IP*", "*Mellanox*", "Network*", "Physical Network*", "RDMA*", "SMB*", "TCP*", "UDP*","VFP*", "WFP*", "*WinNAT*")
    $counterPaths = (Get-Counter -ListSet $listSet -ErrorAction SilentlyContinue | Sort-Object -Unique -Property "CounterSetName").PathsWithInstances

    # Filter counter instances
    $counterPaths = $counterPaths | where {
        ($_ -notlike "\Hyper-V Virtual Network Adapter VRSS(*)*") -and `
        ($_ -notmatch "\\Hyper-V Hypervisor.*Processor\(.*\d+\)")
    }

    Write-Host "Querying perf counters..."
    $readings = Get-Counter -Counter $counterPaths -MaxSamples 10 -SampleInterval 5 -ErrorAction SilentlyContinue

    Write-Host "Exporting perf counters..."
    $readings | Export-Counter -Path "$out.blg" -FileFormat BLG
    $readings | Export-Counter -Path "$out.csv" -FileFormat CSV
} # Counters()

function HwErrorReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "WER.txt"
    [String []] $cmds = "copy-item $env:ProgramData\Microsoft\Windows\WER $outdir -recurse -verbose 4>&1"
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds
} # HwErrorReport()

function LogsReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "WinEVT.txt"
    [String []] $cmds = "Copy-Item $env:SystemRoot\System32\winevt $outdir -Recurse -Verbose 4>&1"
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds
} # LogsReport()

function Metadata {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [Hashtable] $Params
    )

    $dir  = $OutDir

    $file = "Metadata.txt"
    $out = Join-Path $dir $file
    $paramString = if ($Params.Count -eq 0) {"None`n`n"} else {"`n$($Params | Out-String)"}
    Write-Output "Version: $version" | Out-File -Encoding ascii -Append $out
    Write-Output "Parameters: $paramString" | Out-File -Encoding ascii -Append $out

    [String []] $cmds = "Get-FileHash -Path $PSCommandPath -Algorithm ""SHA256"" | Format-List -Property * | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds
} # Metadata()

function Environment {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "Environment.txt"
    [String []] $cmds = "Get-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion""",
                        "date",
                        #"Get-WinEvent -ProviderName eventlog | Where-Object {$_.Id -eq 6005 -or $_.Id -eq 6006}",
                        "wmic os get lastbootuptime",
                        "wmic cpu get name",
                        "systeminfo"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Verifier.txt"
    [String []] $cmds = "verifier /querysettings"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # Environment()

function HostInfo {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "Get-HotFix.txt"
    [String []] $cmds = "get-hotfix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width $columns",
                        "get-hotfix | Sort-Object InstalledOn | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHostSupportedVersion.txt"
    [String []] $cmds = "Get-VMHostSupportedVersion | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-VMHostSupportedVersion | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHostNumaNode.txt"
    [String []] $cmds = "Get-VMHostNumaNode"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    <#
    $file = "Get-VMHostNumaNodeStatus.txt"
    [String []] $cmds = "Get-VMHostNumaNodeStatus"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
    #>
} # HostInfo()

function CustomModule {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String[]] $Commands, # Passed in as [ScriptBlock[]]
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    if ($Commands.Count -eq 0) {
        return
    }

    $CustomModule  = (Join-Path $OutDir "CustomModule")
    New-Item -ItemType Directory -Path $CustomModule | Out-Null

    $file = "ExtraCommands.txt"
    ExecCommands -OutDir $CustomModule -File $file -Commands $Commands
} # CustomModule()

#
# Setup & Validation Functions
#

function CheckAdminPrivileges {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Bool] $SkipAdminCheck
    )

    if (-not $SkipAdminCheck) {
        # Yep, this is the easiest way to do this.
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if (-not $isAdmin) {
            throw "Get-NetView : You do not have the required permission to complete this task. Please run this command in an Administrator PowerShell window or specify the -SkipAdminCheck option."
        }
    }
} # CheckAdminPrivileges()

function NormalizeWorkDir {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $OutputDirectory
    )

    # Output dir priority - $OutputDirectory, Desktop, Temp
    $baseDir = if (-not [String]::IsNullOrWhiteSpace($OutputDirectory)) {
                   if (Test-Path $OutputDirectory) {
                       (Resolve-Path $OutputDirectory).Path # full path
                   } else {
                       throw "Get-NetView : The directory ""$OutputDirectory"" does not exist."
                   }
               } elseif (($desktop = [Environment]::GetFolderPath("Desktop"))) {
                   $desktop
               } else {
                   $env:TEMP
               }
    $workDirName = "msdbg.$env:COMPUTERNAME"

    return (Join-Path $baseDir $workDirName).TrimEnd("\")
} # NormalizeWorkDir()

function EnvDestroy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    If (Test-Path $OutDir) {
        Remove-Item $OutDir -Recurse # Careful - Deletes $OurDir and all its contents
    }
} # EnvDestroy()

function EnvCreate {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Attempt to create working directory, fail gracefully otherwise
    try {
        New-Item -ItemType directory -Path $OutDir -ErrorAction Stop | Out-Null
    } catch {
        throw "Get-NetView : Failed to create directory ""$OutDir"" because " + $error[0]
    }
} # EnvCreate()

function EnvSetup {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    EnvDestroy $OutDir
    EnvCreate $OutDir
} # EnvSetup()

function CreateZip {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Src,
        [parameter(Mandatory=$true)] [String] $Out
    )

    if (Test-path $Out) {
        Remove-item $Out
    }

    Add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($Src, $Out)
} # CreateZip()


function Sanity {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir  = (Join-Path -Path $OutDir -ChildPath "Sanity")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-ChildItem.txt"
    [String []] $cmds = "Get-ChildItem -Path $OutDir -Exclude $file -Recurse | Get-FileHash | Format-Table -AutoSize | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds
} # Sanity()

function Completion {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Src
    )

    $timestamp = $start | Get-Date -f yyyy.MM.dd_hh.mm.ss

    # Zip output folder
    $outzip = "$Src-$timestamp.zip"
    CreateZip -Src $Src -Out $outzip

    $dirs = (Get-ChildItem $Src -Recurse | Measure-Object -Property length -Sum) # out folder size
    $hash = (Get-FileHash -Path $MyInvocation.PSCommandPath -Algorithm "SHA256").Hash # script hash

    # Display version and file save location
    Write-Host "`n"
    Write-Host "Diagnostics Data:"
    Write-Host "-----------------"
    Write-Host "Get-NetView"
    Write-Host "Version: $version"
    Write-Host "SHA256:  $(if ($hash) {$hash} else {"N/A"})"
    Write-Host ""
    Write-Host $outzip
    Write-Host "Size:    $("{0:N2} MB" -f ((Get-Item $outzip).Length / 1MB))"
    Write-Host ""
    Write-Host $Src
    Write-Host "Size:    $("{0:N2} MB" -f ($dirs.sum / 1MB))"
    Write-Host "Dirs:    $((Get-ChildItem $Src -Directory -Recurse | Measure-Object).Count)"
    Write-Host "Files:   $((Get-ChildItem $Src -File -Recurse | Measure-Object).Count)"
    Write-Host ""
    Write-Host "Execution Time:"
    Write-Host "---------------"
    $delta = (Get-Date) - $Start
    Write-Host "$($delta.Minutes) Min $($delta.Seconds) Sec"
    Write-Host "`n"
} # Completion()

#===============================================
# Main Program
#===============================================
function Get-NetView {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [String] $OutputDirectory = "",

        [parameter(Mandatory=$false)]
        [ScriptBlock[]] $ExtraCommands = @(),

        [ValidateRange(1, 16)]
        [Int] $MaxThreads = 5,

        [parameter(Mandatory=$false)]
        [Switch] $SkipAdminCheck = $false
    )

    $start = Get-Date
    $version = "2018.09.14.0" # Version within date context

    # Input Validation
    CheckAdminPrivileges $SkipAdminCheck
    $workDir = NormalizeWorkDir -OutputDirectory $OutputDirectory

    EnvSetup $workDir
    Clear-Host

    # Start Run
    try {
        CustomModule -OutDir $workDir -Commands $ExtraCommands

        Open-GlobalThreadPool -MaxThreads $MaxThreads

        $threads = if ($true) {
            Start-Thread ${function:NetshTrace} -Params @{OutDir=$workDir}
            Start-Thread ${function:Counters}   -Params @{OutDir=$workDir}

            Metadata          -OutDir $workDir  -Params $PSBoundParameters
            Environment       -OutDir $workDir
            ServicesDrivers   -OutDir $workDir

            NetworkSummary    -OutDir $workDir
            HwErrorReport     -OutDir $workDir
            LogsReport        -OutDir $workDir

            NetSetupDetail    -OutDir $workDir
            VMSwitchDetail    -OutDir $workDir
            LbfoDetail        -OutDir $workDir
            NativeNicDetail   -OutDir $workDir
            OneX              -OutDir $workDir

            QosDetail         -OutDir $workDir
            SMBDetail         -OutDir $workDir
            NetIp             -OutDir $workDir
            NetNat            -OutDir $workDir
            HNSDetail         -OutDir $workDir
        }

        # Show thread output, and wait for them all to complete
        Show-Threads -Threads $threads

        # Tamper Detection
        Sanity            -OutDir $workDir
    } catch {
        throw $error[0] # try finally obfuscates error
    } finally {
        Close-GlobalThreadPool
    }

    Completion -Src $workDir
} Get-NetView @PSBoundParameters # Entry Point
