<#
.SYNOPSIS
    Collects data on system and network configuration for diagnosting Microsoft Networking.
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
    List of additional commands to run, formatted as Strings. Output is saved to the CustomModule directory. You can
    use {0} as a placeholder for the CustomModule directory location, and it will be formatted in. This allows you to
    copy or save additional files to the final output.
    For example, 'echo "Hello, World!" > {0}\MyFile.txt' will save to <root>\CustomModule\MyFile.txt
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
    [String] $OutputDirectory,

    [parameter(Mandatory=$false)]
    [String[]] $ExtraCommands,

    [parameter(Mandatory=$false)]
    [Switch] $SkipAdminCheck
)

#
# Common Functions
#

$ExecFunctions = {
    # Global vars
    $columns   = 4096

    function ExecCommandText {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
        )

        # Mirror command execution context
        $context = "$env:USERNAME @ ${env:COMPUTERNAME}:"
        Write-Output $context | Out-File -Encoding ascii -Append $Output

        # Mirror command to execute
        $cmdMirror = "$(prompt)$Command"
        Write-Output $cmdMirror | Out-File -Encoding ascii -Append $Output
    } # ExecCommandText()

    function ExecCommandPrivate {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
        )

        ExecCommandText -Command ($Command) -Output $Output

        # Execute Command and redirect to file.  Useful so users know what to run!!!
        Invoke-Expression $Command | Out-File -Encoding ascii -Append $Output
    } #ExecCommandPrivate()

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

        $result  = [CommandStatus]::NotTested
        $failure = $null

        Try {
            # pre-execution cleanup
            $error.clear()

            # Instrument the validate command for silent output
            #$tmp = "$Command -erroraction 'silentlycontinue' | Out-Null"
            $tmp = "$Command | Out-Null"

            # Redirect all error output to $null to encompass all possible errors
            #Write-Host $tmp -ForegroundColor Yellow
            Invoke-Expression $tmp 2> $null
            if ($error -ne $null) {
                # Some PS commands are incorrectly implemented in return code
                # and require detecting SilentContinue
                if (-not ($tmp -like '*SilentlyContinue*')) {
                    throw $error[0]
                }
            }

            # This is only reachable in success case
            $result = [CommandStatus]::Succeeded
        } Catch [Management.Automation.CommandNotFoundException] {
            $result = [CommandStatus]::Unavailable
        } Catch {
            $result  = [CommandStatus]::Failed
            $failure = $error[0] | Out-String
        } Finally {
            # post-execution cleanup to avoid false positives
            $error.clear()
        }

        return $result, $failure
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

        if ($Trusted) {
            # Skip command validation
            Write-Host -ForegroundColor Cyan "$Command"
            ExecCommandPrivate -Command $Command -Output $Output
        } else {
            $result, $failure = TestCommand -Command $Command

            if ($result -eq [CommandStatus]::Succeeded) {
                Write-Host -ForegroundColor Green "$Command"
                ExecCommandPrivate -Command $Command -Output $Output
            } else {
                Write-Warning "[Command $result] $Command"

                Write-Output "[Command $result]" | Out-File -Encoding ascii -Append $Output
                Write-Output "$Command" | Out-File -Encoding ascii -Append $Output
                Write-Output "$failure" | Out-File -Encoding ascii -Append $Output
                Write-Output "`n`n" | Out-File -Encoding ascii -Append $Output
            }
        }
    } # ExecCommand()

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
    }
} # $ExecFunctions

. $ExecFunctions # import into script context

function Start-Thread {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock,
        [parameter(Mandatory=$false)] [ValidateScript({Test-Path $_ -PathType Container})] [String] $StartPath = ".",
        [parameter(Mandatory=$false)] [Hashtable] $Params = @{}
    )

    $ps = [PowerShell]::Create()

    $ps.Runspace = [RunspaceFactory]::CreateRunspace()
    $ps.Runspace.Open()
    $null = $ps.AddScript("Set-Location ""$(Resolve-Path $StartPath)""")
    $null = $ps.AddScript($ExecFunctions) # import into thread context
    $null = $ps.AddScript($ScriptBlock).AddParameters($Params)

    $async = $ps.BeginInvoke()

    return @{Name=$ScriptBlock.Ast.Name; AsyncResult=$async; PowerShell=$ps}
} # Start-Thread()

function Remove-Thread {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Hashtable] $Thread
    )
    Write-Host "Stopping thread $($Thread.Name)..."
    $Thread.PowerShell.Stop()
    $Thread.PowerShell.Dispose()
    $Thread.PowerShell.Runspace.Close()
} # Remove-Thread

function StreamThread {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Hashtable] $Thread
    )

    Write-Host "`nOn thread: $($Thread.Name)"
    Write-Host "----------------------------------------------"

    do {
        Start-Sleep -Milliseconds 50
        # TODO output errors/other streams
        $Thread.PowerShell.Streams.Information | Out-Host
        $Thread.PowerShell.Streams.Information.Clear()
    } until ($Thread.AsyncResult.IsCompleted)

    $Thread.PowerShell.EndInvoke($Thread.AsyncResult)
} # StreamThread()

#
# Data Collection Functions
#

function NetIpNicWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = $OutDir

    $file = "Get-NetIpAddress.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List -Property *",
                        "Get-NetIpAddress | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetIPInterface.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetIPInterface -InterfaceAlias ""$name"" | Out-String -Width $columns",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIPInterface | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetNeighbor.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNeighbor -InterfaceAlias ""$name"" | Out-String -Width $columns",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -AutoSiz | Out-String -Width $columns",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetRoute.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetRoute | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # NetIpNicWorker()

function NetIpNic {
    [CmdletBinding()]
    Param(
         [parameter(Mandatory=$true)] [String] $NicName,
         [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetIp"))
    New-Item -ItemType directory -Path $dir | Out-Null
    NetIpNicWorker  -NicName $name -OutDir $dir
} # NetIpNic()

function NetIpWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir  = $OutDir

    $file = "Get-NetIpAddress.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetIpAddress | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-List",
                        "Get-NetIpAddress | Format-List -Property *",
                        "Get-NetIpAddress | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetIPInterface.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetIPInterface | Out-String -Width $columns",
                        "Get-NetIPInterface | Format-Table -AutoSize  | Out-String -Width $columns",
                        "Get-NetIPInterface | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIPInterface | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetNeighbor.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNeighbor | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetIPv4Protocol.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetIPv4Protocol | Out-String -Width $columns",
                        "Get-NetIPv4Protocol | Format-List  -Property *",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIPv4Protocol | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetIPv6Protocol.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetIPv6Protocol | Out-String -Width $columns",
                        "Get-NetIPv6Protocol | Format-List  -Property *",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIPv6Protocol | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetOffloadGlobalSetting.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetOffloadGlobalSetting | Out-String -Width $columns",
                        "Get-NetOffloadGlobalSetting | Format-List  -Property *",
                        "Get-NetOffloadGlobalSetting | Format-Table -AutoSize",
                        "Get-NetOffloadGlobalSetting | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetOffloadGlobalSetting | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetPrefixPolicy.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetPrefixPolicy | Format-Table -AutoSize",
                        "Get-NetPrefixPolicy | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetPrefixPolicy | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetRoute.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetRoute | Format-Table -AutoSize",
                        "Get-NetRoute | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetRoute | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetTCPConnection.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetTCPConnection | Format-Table -AutoSize",
                        "Get-NetTCPConnection | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetTCPConnection | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command ($cmd) -Output $out
    }

    $file = "Get-NetTcpSetting.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetTcpSetting  | Format-Table -AutoSize",
                        "Get-NetTcpSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetTcpSetting  | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command ($cmd) -Output $out
    }

    $file = "Get-NetTransportFilter.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetTransportFilter  | Format-Table -AutoSize",
                        "Get-NetTransportFilter  | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetTransportFilter  | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetUDPEndpoint.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetUDPEndpoint  | Format-Table -AutoSize",
                        "Get-NetUDPEndpoint  | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetUDPEndpoint  | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetUDPSetting.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetUDPSetting  | Format-Table -AutoSize",
                        "Get-NetUDPSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetUDPSetting  | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # NetIpWorker()

function NetIp {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetIp"))
    New-Item -ItemType directory -Path $dir | Out-Null
    NetIpWorker -OutDir $dir
} # NetIp()

function NetNatWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir  = $OutDir

    $file = "Get-NetNat.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNat | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNat | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNat | Format-List",
                        "Get-NetNat | Format-List -Property *",
                        "Get-NetNat | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetNatExternalAddress.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNatExternalAddress | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatExternalAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatExternalAddress | Format-List",
                        "Get-NetNatExternalAddress | Format-List -Property *",
                        "Get-NetNatExternalAddress | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetNatGlobal.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNatGlobal | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatGlobal | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatGlobal | Format-List",
                        "Get-NetNatGlobal | Format-List -Property *",
                        "Get-NetNatGlobal | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetNatSession.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNatSession | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatSession | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatSession | Format-List",
                        "Get-NetNatSession | Format-List -Property *",
                        "Get-NetNatSession | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetNatStaticMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetNatStaticMapping | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatStaticMapping | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatStaticMapping | Format-List",
                        "Get-NetNatStaticMapping | Format-List -Property *",
                        "Get-NetNatStaticMapping | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

} # NetNatWorker

function NetNat {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetNat"))
    New-Item -ItemType directory -Path $dir | Out-Null
    NetNatWorker -OutDir $dir
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
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapter -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapter -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapter | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterAdvancedProperty.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties | Sort-Object RegistryKeyword | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Sort-Object RegistryKeyword | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-Table  -Property * | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterBinding.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Sort-Object ComponentID | Out-String -Width $columns",
                        "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterBinding | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterChecksumOffload.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterChecksumOffload | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterLso.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterLso | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterRss.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterRss | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterStatistics.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterStatistics | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterEncapsulatedPacketTaskOffload.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterEncapsulatedPacketTaskOffload | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterHardwareInfo.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterHardwareInfo | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterIPsecOffload.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterIPsecOffload | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterPowerManagement.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterPowerManagement | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterQos.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterQos -Name ""$name"" -IncludeHidden -ErrorAction SilentlyContinue | Out-String -Width $columns",
                        "Get-NetAdapterQos -Name ""$name"" -IncludeHidden -ErrorAction SilentlyContinue | Format-List  -Property *",
                        "Get-NetAdapterQos | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterRdma.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterRdma | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterPacketDirect.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterPacketDirect | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterRsc.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterRsc | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterSriov.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterSriov | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterSriovVf.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterSriovVf | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterVmq.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterVmq | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterVmqQueue.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterVmqQueue | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetAdapterVPort.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterVPort | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # NetAdapterWorker()

function NetAdapterWorkerPrepare {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicDesc,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Variables
    $out  = $OutDir
    $desc = $NicDesc

    # Create dir for each NIC
    $nic     = Get-NetAdapter -InterfaceDescription $desc
    $idx     = $nic.IfIndex
    $name    = $nic.Name
    $desc    = $NicDesc
    $nictype = "pNic"
    $title   = "$nictype.$idx.$name.$desc"
    $dir     = (Join-Path -Path $out -ChildPath ("$title"))
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host ""
    Write-Host "Processing: $title"
    Write-Host "----------------------------------------------"
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

    # Normalize Names
    $name = $LbfoName
    $out  = $OutDir

    $file = "Get-NetLbfoTeam.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetLbfoTeam -Name ""$name""",
                        "Get-NetLbfoTeam -Name ""$name"" | Format-List  -Property *",
                        "Get-NetLbfoTeam | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetLbfoTeamNic.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetLbfoTeamNic -Team ""$name""",
                        "Get-NetLbfoTeamNic -Team ""$name"" | Format-List  -Property *",
                        "Get-NetLbfoTeamNic | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-NetLbfoTeamMember.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetLbfoTeamMember -Team ""$name""",
                        "Get-NetLbfoTeamMember -Team ""$name"" | Format-List  -Property *",
                        "Get-NetLbfoTeamMember | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    # Report the TNIC(S)
    foreach ($tnic in TryCmd {Get-NetLbfoTeamNic -Team $name}) {
        NetAdapterWorkerPrepare -NicDesc $tnic.InterfaceDescription -OutDir $OutDir
    }

    # Report the NIC Members
    foreach ($mnic in TryCmd {Get-NetLbfoTeamMember -Team $name}) {
        NetAdapterWorkerPrepare -NicDesc $mnic.InterfaceDescription -OutDir $OutDir
    }
} # LbfoWorker()

function LbfoWorkerPrepare {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $LbfoName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Variable
    $name = $LbfoName

    $dir  = (Join-Path -Path $OutDir -ChildPath ("LBFO.$name"))
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host "Processing: $name"
    Write-Host "----------------------------------------------"
    LbfoWorker -LbfoName $name -OutDir $dir
} # LbfoWorkerPrepare()

function LbfoDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize variables
    $out = $OutDir

    foreach ($lbfo in TryCmd {Get-NetLbfoTeam}) {
        $name = $lbfo.Name

        # Skip all vSwitch Protocol NICs since the LBFO and member reporting will occur as part of
        # vSwitch reporting.
        $match = $false

        foreach ($vms in TryCmd {Get-VMSwitch | where {$_.SwitchType -ne "Internal"}}) {
            if ($vms.NetAdapterInterfaceDescriptions -contains (Get-NetAdapter -Name $name).InterfaceDescription) {
                $match = $true
                break
            }
        }

        if (-not $match) {
            LbfoWorkerPrepare -LbfoName $name -OutDir $out
        }
    }
} # LbfoDetail()

function ProtocolNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Variables
    $out = $OutDir

    # Distinguish between LBFO from standard PTNICs and create the hierarchies accordingly
    foreach ($desc in TryCmd {(Get-VMSwitch -Name "$VMSwitchName").NetAdapterInterfaceDescriptions}) {
        $nic = Get-NetAdapter -InterfaceDescription $desc
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            LbfoWorkerPrepare -LbfoName $nic.Name -OutDir $out
        } else {
            NetAdapterWorkerPrepare -NicDesc $desc -OutDir $out
        }
    }
} # ProtocolNicDetail()

function NativeNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Variables
    $out = $OutDir

    foreach ($nic in Get-NetAdapter) {
        $native = $true

        # Skip vSwitch Host vNICs by checking the driver
        if ($nic.DriverFileName -like "vmswitch.sys") {
            continue
        }

        # Skip LBFO TNICs by checking the driver
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            continue
        }

        # Skip all vSwitch Protocol NICs
        foreach ($vms in TryCmd {Get-VMSwitch | where {$_.SwitchType -ne "Internal"}}) {
            if ($vms.NetAdapterInterfaceDescriptions -contains $nic.InterfaceDescription) {
                $native = $false
                break
            }
        }

        # Skip LBFO Team Member Adapters
        foreach ($lbfonic in TryCmd {Get-NetLbfoTeamMember}) {
            if ($nic.InterfaceDescription -eq $lbfonic.InterfaceDescription) {
                $native = $false
                break
            }
        }

        if ($native) {
            NetAdapterWorkerPrepare -NicDesc $nic.InterfaceDescription -OutDir $out
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
    $out = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-EventLog -LogName System -Source ""*chvbd*"" -ErrorAction SilentlyContinue | Format-List",
                        "Get-EventLog -LogName System -Source ""*cht4vbd*"" -ErrorAction SilentlyContinue | Format-List"
    foreach ($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "ChelsioDetail-Eventlog-NetDevice.txt"
    $out = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-EventLog -LogName System -Source ""*chndis*"" -ErrorAction SilentlyContinue | Format-List",
                        "Get-EventLog -LogName System -Source ""*chnet*"" -ErrorAction SilentlyContinue | Format-List",
                        "Get-EventLog -LogName System -Source ""*cht4ndis*"" -ErrorAction SilentlyContinue | Format-List"
    foreach ($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "ChelsioDetail-Misc.txt"
    $out = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "verifier /query",
                        "Get-PnpDevice -FriendlyName ""*Chelsio*Enumerator*"" | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_DriverVersion | Format-Table -Autosize"
    foreach ($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    # Basic sanity check. Most of Chelsio related logs are collected using cxgbtool.exe.
    # So if cxgbtool.exe is not there in System32 forlder, then exit from the function.
    $cxgbtool = Get-Item "$env:windir\System32\cxgbtool.exe" -ErrorAction SilentlyContinue
    if ($cxgbtool.Exists -eq $null) {
        Write-Warning "Unable to collect Chelsio debug logs as cxgbtool is not present in $env:windir\system32"
        return $null
    }

    $ifName = $NicName
    $ifIndex = (Get-NetAdapter $NicName).ifIndex
    $ifHwInfo = Get-NetAdapterHardwareInfo -Name "$ifName"
    $dirBusName = "BusDev_$($ifHwInfo.Bus)_$($ifHwInfo.Device)_$($ifHwInfo.Function)"
    $dirBus = (Join-Path -Path $dir -ChildPath $dirBusName)

    if ($Global:ChelsioOncePerASIC -notcontains $dirBusName) {
        $Global:ChelsioOncePerASIC += @($dirBusName) # expensive, avoid duplicate effort
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
            return $null
        }

        $file = "ChelsioDetail-Cudbg.txt"
        $CollectFile = "Cudbg-Collect.dmp"
        $ReadFlashFile = "Cudbg-Readflash.dmp"
        $out  = (Join-Path -Path $dirBus -ChildPath $file)
        $OutCollect = (Join-Path -Path $dirBus -ChildPath $CollectFile)
        $OutReadFlash = (Join-Path -Path $dirBus -ChildPath $ReadFlashFile)
        [String []] $cmds = "cxgbtool.exe $ifNameVbd cudbg collect all ""$OutCollect""",
                            "cxgbtool.exe $ifNameVbd cudbg readflash ""$OutReadFlash"""
        foreach ($cmd in $cmds) {
            ExecCommand -Trusted -Command $cmd -Output $out
        }

        $file = "ChelsioDetail-Firmware-BusDevice$i.txt"
        $out  = (Join-Path -Path $dirBus -ChildPath $file)
        [String []] $cmds = "cxgbtool.exe $ifNameVbd firmware mbox 1",
                            "cxgbtool.exe $ifNameVbd firmware mbox 2",
                            "cxgbtool.exe $ifNameVbd firmware mbox 3",
                            "cxgbtool.exe $ifNameVbd firmware mbox 4",
                            "cxgbtool.exe $ifNameVbd firmware mbox 5",
                            "cxgbtool.exe $ifNameVbd firmware mbox 6",
                            "cxgbtool.exe $ifNameVbd firmware mbox 7"
        foreach ($cmd in $cmds) {
            ExecCommand -Command $cmd -Output $out
        }

        $file = "ChelsioDetail-Hardware-BusDevice$i.txt"
        $flashFile = "Hardware-BusDevice$i-flash.dmp"
        $out = (Join-Path -Path $dirBus -ChildPath $file)
        $OutFlash = (Join-Path -Path $dirBus -ChildPath $flashFile)
        [String []] $cmds = "cxgbtool.exe $ifNameVbd hardware sgedbg",
                            "cxgbtool.exe $ifNameVbd hardware flash ""$OutFlash"""
        foreach ($cmd in $cmds) {
            ExecCommand -Command $cmd -Output $out
        }
    } # $Global:ChelsioOncePerASIC

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
        return $null
    }

    $file = "ChelsioDetail-Debug.txt"
    $out  = (Join-Path -Path $dirNet -ChildPath $file)
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
    foreach ($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "ChelsioDetail-Hardware.txt"
    $out  = (Join-Path -Path $dirNet -ChildPath $file)
    [String []] $cmds = "cxgbtool.exe $ifNameNic hardware tid_info",
                        "cxgbtool.exe $ifNameNic hardware fec",
                        "cxgbtool.exe $ifNameNic hardware link_cfg",
                        "cxgbtool.exe $ifNameNic hardware pktfilter",
                        "cxgbtool.exe $ifNameNic hardware sensor"
    foreach ($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }
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
    $out = Join-Path $dir $file
    [String []] $cmds = "Command 1",
                        "Command 2",
                        "Command 3",
                        "etc."
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
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

    # Normalize Names
    $name = $HostVNicName
    $dir  = $OutDir

    $file = "Get-VMNetworkAdapter.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapter -ManagementOS| Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterAcl -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterIsolation.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterIsolation -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List -Property *",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterVlan.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterVlan -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # HostVNicWorker()

function HostVNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    foreach ($nic in TryCmd {Get-VMNetworkAdapter -ManagementOS -SwitchName $VMSwitchName}) {
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
        foreach($pnic in (Get-NetAdapter -IncludeHidden)) {
            if ($pnic.DeviceID -eq $nic.DeviceId) {
                $pnicname = $pnic.Name
                $idx      = $pnic.IfIndex
            }
        }

        # Create dir for each NIC
        $name    = $nic.Name
        $nictype = "hNic"
        $title   = "$nictype." + $idx + ".$name"
        $dir     = (Join-Path -Path $OutDir -ChildPath ("$title"))
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Host "Processing: $title"
        Write-Host "----------------------------------------------"
        HostVNicWorker   -HostVNicName $name     -OutDir $dir
        NetAdapterWorker -NicName      $pnicname -OutDir $dir
    }
} # HostVNicDetail()


function VMNetworkAdapterWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMName,
        [parameter(Mandatory=$true)] [String] $VMNicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Names
    $name = $VMNicName
    $dir  = $OutDir

    $file = "Get-VMNetworkAdapter.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapter -Name ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -Name ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapter * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterAcl -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterAcl | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterExtendedAcl | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMName * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterIsolation.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterIsolation | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterRoutingDomainMapping | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterTeamMapping -VMName * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterVlan.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterVlan -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -VMNetworkAdapterName ""$name"" -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VMNetworkAdapterVlan | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # VMNetworkAdapterWorker()

function VmNetworkAdapterDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMName,
        [parameter(Mandatory=$true)] [String] $VmNicName,
        [parameter(Mandatory=$true)] [String] $VmNicMac,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir     = (Join-Path -Path $OutDir -ChildPath ("VMNic.$VmNicName.$VmNicMac"))
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host "Processing: VMNic.$VmNicName.$VmNicMac"
    Write-Host "--------------------------------------"
    VMNetworkAdapterWorker -VMName $VMName -VMNicName $VmNicName -OutDir $dir
} # VmNetworkAdapterDetail()

function VmWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Names
    $dir  = $OutDir

    $file = "Get-VM.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VM -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VM -VMName ""$VMName"" | Format-List  -Property *",
                        "Get-VM | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMBios.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMBios -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMBios -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMFirmware.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMFirmware -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMFirmware -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMProcessor.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMProcessor -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMProcessor -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMMemory.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMMemory -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMMemory -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMVideo.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMVideo -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMVideo -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMHardDiskDrive.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMHardDiskDrive -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMHardDiskDrive -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMComPort.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMComPort -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMComPort -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSecurity.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSecurity -VMName ""$VMName"" | Out-String -Width $columns",
                        "Get-VMSecurity -VMName ""$VMName"" | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

} # VmWorker()

function VMNetworkAdapterPerVM {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    foreach ($vm in TryCmd {Get-VM}) {
        $vmname = $vm.Name
        $vmid   = $vm.VMId

        Write-Host "Processing: VM.$vmname.$vmid"
        Write-Host "--------------------------------------"
        foreach ($nic in TryCmd {Get-VMNetworkAdapter -VMName $vmname}) {
            if ($nic.SwitchName -eq $VMSwitchName) {
                $vmquery = 0
                $dir     = (Join-Path -Path $OutDir -ChildPath ("VM.$vmname"))
                if (-not (Test-Path $dir)) {
                    New-Item -ItemType directory -Path $dir | Out-Null
                    $vmquery = 1
                }

                if ($vmquery) {
                    VmWorker -VMName $vmname -OutDir $dir
                }
                VmNetworkAdapterDetail -VMName $vmname -VmNicName $nic.Name -VmNicMac $nic.MacAddress -OutDir $dir
            }
        }
    }
} # VMNetworkAdapterPerVM()

function VMSwitchWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Names
    $name = $VMSwitchName
    $dir  = $OutDir

    $file = "Get-VMSwitch.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitch -Name ""$name""",
                        "Get-VMSwitch -Name ""$name"" | Format-List  -Property *",
                        "Get-VMSwitch -Name ""$name"" | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchExtension.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitch -Name ""$name"" | Get-VMSwitchExtension | Format-List  -Property *",
                        "Get-VMSwitch -Name ""$name"" | Get-VMSwitchExtension | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchExtensionSwitchData.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchExtensionSwitchData -SwitchName ""$name"" | Format-List  -Property *",
                        "Get-VMSwitchExtensionSwitchData -SwitchName ""$name"" | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchExtensionSwitchFeature.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchExtensionSwitchFeature -SwitchName ""$name"" | Format-List -Property *"
                        #"Get-VMSwitchExtensionSwitchFeature -SwitchName ""$name"" | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchTeam.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchTeam -SwitchName ""$name"" | Format-List -Property *",
                        "Get-VMSwitchTeam -SwitchName ""$name"" | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSystemSwitchExtension.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSystemSwitchExtension | Format-List -Property *",
                        "Get-VMSystemSwitchExtension | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchExtensionPortFeature.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchExtensionPortFeature * | Format-List -Property *",
                        "Get-VMSwitchExtensionPortFeature * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSystemSwitchExtensionSwitchFeature.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSystemSwitchExtensionSwitchFeature",
                        "Get-VMSystemSwitchExtensionSwitchFeature | Format-List  -Property *",
                        "Get-VMSystemSwitchExtensionSwitchFeature | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    <#
    #Get-VMSwitchExtensionPortData -ComputerName $env:computername *
    # Execute command list
    $file = "Get-VMSwitchExtensionPortData.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchExtensionPortData -SwitchName ""$name"" | Format-List  -Property *",
                        "Get-VMSwitchExtensionPortData -SwitchName ""$name"" | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
    #>
} # VMSwitchWorker()

function VfpExtensionWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $VMSwitchName
    $out  = $OutDir

    $dir  = (Join-Path -Path $out -ChildPath ("VFP"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "VfpCtrl.help.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "vfpctrl.exe /h"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }


    $switches = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualEthernetSwitch
    foreach ($switch in $switches) {
        if ($switch.ElementName -eq $name) {
            $currswitch = $switch
            break
        }
    }
    $ports = $currswitch.GetRelated("Msvm_EthernetSwitchPort", "Msvm_SystemDevice", $null, $null, $null, $null, $false, $null)
    foreach ($port in $ports) {
        $portGuid = $port.Name
        $file     = "VfpCtrl.PortGuid.$portGuid.txt"
        $out      = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "vfpctrl.exe /list-space /port $portGuid",
                            "vfpctrl.exe /list-mapping /port $portGuid",
                            "vfpctrl.exe /list-rule /port $portGuid",
                            "vfpctrl.exe /port $portGuid /get-port-state"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }
    }

} # VfpExtensionWorker()

function VfpExtensionDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $VMSwitchName
    $out  = $OutDir

    foreach ($ext in TryCmd {Get-VMSwitch -Name $name | Get-VMSwitchExtension}) {
        if (($ext.Name -like "Microsoft Azure VFP Switch Extension") -and ($ext.Enabled -like "True")) {
            VfpExtensionWorker -VMSwitchName $name -OutDir $out
        }
    }

} # VfpExtensionDetail()

function VMSwitchDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # FIXME!!!
    ##See this command to get VFs on vSwitch
    #Get-NetAdapterSriovVf -SwitchId 2

    foreach ($switch in TryCmd {Get-VMSwitch}) {
        $name = $switch.Name
        $type = $switch.SwitchType

        $dir  = (Join-Path -Path $OutDir -ChildPath ("VMSwitch.$type.$name"))
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Host "Processing: $name"
        Write-Host "----------------------------------------------"
        VfpExtensionDetail    -VMSwitchName $name -OutDir $dir
        VMSwitchWorker        -VMSwitchName $name -OutDir $dir
        ProtocolNicDetail     -VMSwitchName $name -OutDir $dir
        HostVNicDetail        -VMSwitchName $name -OutDir $dir
        VMNetworkAdapterPerVM -VMSwitchName $name -OutDir $dir
    }
} # VMSwitchDetail()

function NetworkSummary {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "Get-VMSwitch.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-VMSwitch | Sort-Object Name",
                            "Get-VMSwitch | Sort-Object Name | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-VMNetworkAdapter.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-VMNetworkAdapter -All | Sort-Object Name | Format-Table -AutoSize",
                            "Get-VMNetworkAdapter -All | Sort-Object Name | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetAdapter.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -AutoSize",
                            "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetAdapterStatistics.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Autosize  | Out-String -Width $columns",
                            "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -Autosize  | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetLbfoTeam.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetLbfoTeam | Sort-Object InterfaceDescription",
                            "Get-NetLbfoTeam | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize  | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetIpAddress.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetIpAddress | Format-Table -Autosize",
                            "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "ipconfig.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "ipconfig",
                            "ipconfig /allcompartments /all"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }
} # NetworkSummary()

function SMBDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("SMB"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-SmbClientNetworkInterface.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-SmbClientNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbClientNetworkInterface | Format-List  -Property *",
                        "Get-SmbClientNetworkInterface | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-SmbServerNetworkInterface.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-SmbServerNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbServerNetworkInterface | Format-List  -Property *",
                        "Get-SmbServerNetworkInterface | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-SmbClientConfiguration.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-SmbClientConfiguration",
                        "Get-SmbClientConfiguration | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-SmbMultichannelConnection.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-SmbMultichannelConnection | Sort-Object Name | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbMultichannelConnection -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection -SmbInstance CSV -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection -SmbInstance SBL -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-SmbMultichannelConstraint.txt"
    $out = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-SmbMultichannelConstraint",
                        "Get-SmbMultichannelConstraint | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Smb-WindowsEvents.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WinEvent -ListLog ""*SMB*"" | Format-List -Property *",
                        "Get-WinEvent -ListLog ""*SMB*"" | Get-WinEvent | ? Message -like ""*RDMA*"" | Format-List -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # SMBDetail()

function NetSetupDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetSetup"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "NetSetup.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Test-Path $env:SystemRoot\System32\NetSetupMig.log",
                        "Test-Path $env:SystemRoot\Panther\setupact.log",
                        "Test-Path $env:SystemRoot\INF\setupapi.*",
                        "Test-Path $env:SystemRoot\logs\NetSetup"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    # Copy over the logs
    [String []] $cmds = "$env:SystemRoot\System32\NetSetupMig.log",
                        "$env:SystemRoot\Panther\setupact.log",
                        "$env:SystemRoot\INF\setupapi.*",
                        "$env:SystemRoot\logs\NetSetup"
    ForEach($cmd in $cmds) {
        if (Test-Path $cmd) {
            $tcmd = "Copy-Item $cmd $dir -recurse -verbose 4>&1"
            ExecCommand -Trusted -Command ($tcmd) -Output $out
        }
    }
} # NetSetupDetail()

function HNSDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath "HNS")
    New-Item -ItemType Directory -Path $dir | Out-Null

    $file = "HNSRegistry-1.txt"
    $out  = (Join-Path $dir $file)
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\hns -Recurse",
                        "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-HNSNetwork-1.txt"
    $out  = (Join-Path $dir $file)
    [String []] $cmds = "Get-HNSNetwork | ConvertTo-Json -Depth 10",
                        "Get-HNSNetwork | Get-Member"
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-HNSEndpoint-1.txt"
    $out = (Join-Path $dir $file)
    [String []] $cmds = "Get-HNSEndpoint | ConvertTo-Json -Depth 10",
                        "Get-HNSEndpoint | Get-Member"
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    # HNS service stop -> start occurs after capturing the current HNS state info.
    $hnsRunning = (Get-Service hns).Status -eq "Running"
    try {
        if ($hnsRunning) {
            # Force stop to avoid command line prompt
            net stop hns /y
        }

        $file = "HNSData.txt"
        $out  = (Join-Path $dir $file)
        [String []] $cmds = "Copy-Item ""$env:ProgramData\Microsoft\Windows\HNS\HNS.data"" $dir 4>&1"
        foreach ($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }
    } finally {
        if ($hnsRunning) {
            net start hns
        }
    }


    # Acquire all settings again after stop -> start services
    $file = "HNSRegistry-2.txt"
    $out  = (Join-Path $dir $file)
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\hns -Recurse",
                        "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-HNSNetwork-2.txt"
    $out  = (Join-Path $dir $file)
    [String []] $cmds = "Get-HNSNetwork | ConvertTo-Json -Depth 10",
                        "Get-HNSNetwork | Get-Member"
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-HNSEndpoint-2.txt"
    $out = (Join-Path $dir $file)
    [String []] $cmds = "Get-HNSEndpoint | ConvertTo-Json -Depth 10",
                        "Get-HNSEndpoint | Get-Member"
    foreach ($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }


    #netsh trace start scenario=Virtualization provider=Microsoft-Windows-tcpip provider=Microsoft-Windows-winnat capture=yes captureMultilayer=yes capturetype=both report=disabled tracefile=$dir\server.etl overwrite=yes
    #Start-Sleep 120
    #netsh trace stop
} # HNSDetail()

function QosDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetQoS"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetQosDcbxSetting.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetQosDcbxSetting",
                        "Get-NetQosDcbxSetting | Format-List  -Property *",
                        "Get-NetQosDcbxSetting | Format-Table -Property *  -AutoSize | Out-String -Width $columns",
                        "Get-NetQosDcbxSetting | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetQosFlowControl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetQosFlowControl",
                        "Get-NetQosFlowControl | Format-List  -Property *",
                        "Get-NetQosFlowControl | Format-Table -Property *  -AutoSize | Out-String -Width $columns",
                        "Get-NetQosFlowControl | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetQosPolicy.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetQosPolicy",
                        "Get-NetQosPolicy | Format-List  -Property *",
                        "Get-NetQosPolicy | Format-Table -Property *  -AutoSize | Out-String -Width $columns",
                        "Get-NetQosPolicy | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetQosTrafficClass.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetQosTrafficClass",
                        "Get-NetQosTrafficClass | Format-List  -Property *",
                        "Get-NetQosTrafficClass | Format-Table -Property *  -AutoSize | Out-String -Width $columns",
                        "Get-NetQosTrafficClass | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }
} # QosDetail()

function ServicesDrivers {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("ServicesDrivers"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "sc.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "sc.exe queryex vmsp",
                        "sc.exe queryex vmsproxy"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-Service.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-Service ""*"" | Sort-Object Name | Format-Table -AutoSize",
                        "Get-Service ""*"" | Sort-Object Name | Format-Table -Property * -AutoSize"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-WindowsDriver.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WindowsDriver -Online -All" # very slow, -Trusted to skip validation
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command $cmd -Output $out
    }

    $file = "Get-WindowsEdition.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WindowsEdition -Online"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-WmiObject.Win32_PnPSignedDriver.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }
} # ServicesDrivers()

function NetshTrace {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("Netsh"))
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
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "New-NetEventSession    NetRundown -CaptureMode SaveToFile -LocalFilePath $dir\NetRundown.etl",
                        "Add-NetEventProvider   ""{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x10000",
                        "Add-NetEventProvider   ""{DD7A21E6-A651-46D4-B7C2-66543067B869}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x2",
                        "Start-NetEventSession  NetRundown",
                        "Stop-NetEventSession   NetRundown",
                        "Remove-NetEventSession NetRundown"
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command $cmd -Output $out
    }

    #
    # The ETL file can be converted to text using the following command:
    #    netsh trace convert NetRundown.etl tmfpath=\\winbuilds\release\RS_ONECORE_STACK_SDN_DEV1\15014.1001.170117-1700\amd64fre\symbols.pri\TraceFormat
    #    Specifying a path to the TMF symbols. Output is attached.

    $file = "NetshDump.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "netsh dump"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "NetshStatistics.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "netsh interface ipv4 show icmpstats",
                        "netsh interface ipv4 show ipstats",
                        "netsh interface ipv4 show tcpstats",
                        "netsh interface ipv4 show udpstats",
                        "netsh interface ipv6 show ipstats",
                        "netsh interface ipv6 show tcpstats",
                        "netsh interface ipv6 show udpstats"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    #NetSetup, binding map, setupact logs amongst other things needed by NDIS folks.
    Write-Host "`n"
    Write-Host "Processing..."
    $file = "NetshTrace.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "netsh -?",
                        "netsh trace show scenarios",
                        "netsh trace show providers",
                        "netsh trace  diagnose scenario=NetworkSnapshot mode=Telemetry saveSessionTrace=yes report=yes ReportFile=$dir\Snapshot.cab"
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command $cmd -Output $out
    }
} # NetshTrace()

function Counters {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("Counters"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "CounterSetName.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-Counter -ListSet * | Sort-Object CounterSetName | Select-Object CounterSetName | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "CounterSetName.Paths.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "(Get-Counter -ListSet * | Sort-Object CounterSetName).Paths | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "CounterSetName.PathsWithInstances.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "(Get-Counter -ListSet * | Sort-Object CounterSetName).PathsWithInstances | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "CounterSet.Property.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "(Get-Counter -ListSet * | Sort-Object CounterSetName) | Format-List -Property * | Out-String -Width $columns",
                        "(Get-Counter -ListSet * | Sort-Object CounterSetName) | Format-Table -Property * | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "CounterDetail" # used with 2 different extensions
    $out  = (Join-Path -Path $dir -ChildPath $file)
    # Get paths for counters of interest
    $cntrList = @("*Hyper*", "*vfp*", "*ip*", "*udp*", "*tcp*", "*icmp*", "*nat*", "*network*", "*rdma*", "*smb*", "*wfp*", "*Mellanox*", "*intel*")
    $cntrPaths = Get-Counter -ListSet $cntrList -ErrorAction SilentlyContinue | Sort-Object CounterSetName | ForEach-Object { $_.Paths }

    Write-Host "Querying Perf Counters..."
    # TODO should keep taking samples until all other jobs complete
    $cntrReadings = Get-Counter -Counter $cntrPaths -MaxSamples 5 -SampleInterval 10 -ErrorAction SilentlyContinue
    Write-Host "Exporting Results..."
    $cntrReadings | Export-Counter -Path "$out.blg" -FileFormat BLG
    $cntrReadings | Export-Counter -Path "$out.csv" -FileFormat CSV
} # Counters()

function HwErrorReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "WER.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "copy-item $env:ProgramData\Microsoft\Windows\WER $outdir -recurse -verbose 4>&1"
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command ($cmd) -Output $out
    }
} # HwErrorReport()

function LogsReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "WinEVT.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Copy-Item $env:SystemRoot\System32\winevt $outdir -Recurse -Verbose 4>&1"
    ForEach($cmd in $cmds) {
        ExecCommand -Trusted -Command ($cmd) -Output $out
    }
} # LogsReport()

function Metadata {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [Hashtable] $Params
    )

    $paramStr = if ($Params.Count -eq 0) {"None"} else {Write-Output @Params}

    $file = "Metadata.txt"
    $out = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Write-Output ""Version: $version"", ""Parameters: $paramStr"" | Out-String -Width $columns",
                        "Get-FileHash -Path $PSCommandPath -Algorithm ""SHA256"" | Format-List -Property * | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # Metadata()

function Environment {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "Environment.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Get-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion""",
                        "date",
                        #"Get-WinEvent -ProviderName eventlog | Where-Object {$_.Id -eq 6005 -or $_.Id -eq 6006}",
                        "wmic os get lastbootuptime",
                        "wmic cpu get name",
                        "systeminfo"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Verifier.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "verifier /querysettings"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
} # Environment()

function HostInfo {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "Get-HotFix.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "get-hotfix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width $columns",
                        "get-hotfix | Sort-Object InstalledOn | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMHostSupportedVersion.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Get-VMHostSupportedVersion | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-VMHostSupportedVersion | Format-List -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMHostNumaNode.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Get-VMHostNumaNode"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    <#
    $file = "Get-VMHostNumaNodeStatus.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Get-VMHostNumaNodeStatus"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
    #>
} # HostInfo()

function CustomModule {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String[]] $Commands,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    if ($Commands.Count -eq 0) {
        return
    }

    $dir  = (Join-Path $OutDir "CustomModule")
    New-Item -ItemType Directory -Path $dir | Out-Null

    $file = "ExtraCommands.txt"
    $out  = (Join-Path $dir $file)
    foreach ($cmd in $Commands) {
        ExecCommand -Command ($cmd -f $dir) -Output $out
    }
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
    $baseDir = if ($OutputDirectory) {
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

    If(Test-path $Out) {
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

    $dir  = (Join-Path -Path $OutDir -ChildPath ("Sanity"))
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-ChildItem.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-ChildItem -Path $OutDir -Exclude $file -Recurse | Get-FileHash | Format-Table -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

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
        [String] $OutputDirectory,

        [parameter(Mandatory=$false)]
        [String[]] $ExtraCommands,

        [parameter(Mandatory=$false)]
        [Switch] $SkipAdminCheck
    )

    $start = Get-Date
    $version = "2017.12.08.0" # Version within date context

    # Input Validation
    CheckAdminPrivileges $SkipAdminCheck
    $workDir = NormalizeWorkDir -OutputDirectory $OutputDirectory

    EnvSetup $workDir
    Clear-Host

    # Start Run
    try {
        CustomModule      -OutDir $workDir -Commands $ExtraCommands

        # concurrent execution of slow commands
        $threads = if ($true) {
            Start-Thread ${function:ServicesDrivers} -Params @{OutDir=$workDir}
            Start-Thread ${function:NetshTrace}      -Params @{OutDir=$workDir}
            Start-Thread ${function:Counters}        -Params @{OutDir=$workDir}
        }

        Metadata          -OutDir $workDir -Params $PSBoundParameters
        Environment       -OutDir $workDir

        NetworkSummary    -OutDir $workDir
        HwErrorReport     -OutDir $workDir
        LogsReport        -OutDir $workDir

        NetSetupDetail    -OutDir $workDir
        VMSwitchDetail    -OutDir $workDir
        LbfoDetail        -OutDir $workDir
        NativeNicDetail   -OutDir $workDir

        QosDetail         -OutDir $workDir
        SMBDetail         -OutDir $workDir
        NetIp             -OutDir $workDir
        NetNat            -OutDir $workDir
        HNSDetail         -OutDir $workDir

        # show thread output
        $threads | foreach {StreamThread $_}

        # Tamper Detection
        Sanity            -OutDir $workDir
    } catch {
        throw $error[0] # try finally obfuscates error
    } finally {
        Write-Host "Removing background threads..."
        $threads | foreach {Remove-Thread $_}
    }

    Completion -Src $workDir
} Get-NetView @PSBoundParameters # Entry Point
