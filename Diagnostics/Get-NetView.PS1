<#
.SYNOPSIS
    Collects data on system and network configuration for diagnosting Microsoft SDN.
.DESCRIPTION
    Collects comprehensive configuration data to aid in troubleshooting Microsoft SDN issues.
    Data is currently collected from the following sources:
        - Get-NetView metadata (path, args, etc.)
        - Environment (OS, hardware, etc.)
        - Physical NICs
        - Virtual Machine configuration
        - Virtual Switchs
        - Device Drivers
        - Performance Counters
    The data is collected in a folder on the Desktop (by default), which is zipped
    on completion. Send only the .zip file to Microsoft.

    The output is most easily viewed with Visual Studio Code or similar editor with a navigation panel.

    If you receive the error "Get-NetView.ps1 cannot be loaded because running scripts is disabled on this system."
    then enable execution of scripts for the current PowerShell window with the following:
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.PARAMETER OutputDirectory
    Optional path to the directory where the output should be saved. Can be either a relative or an absolute path.
    If unspecified, the current user's Desktop will be used by default.
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
    [parameter(Mandatory=$false,HelpMessage="Path to the output directory")] [String] $OutputDirectory,
    [parameter(Mandatory=$false,HelpMessage="Skip check for Administrator privileges")] [Switch] $SkipAdminCheck
)

function ExecCommandText {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
    )

    # Mirror Prompt info
    $prompt = $env:username + " @ " + $env:computername + ":"
    Write-Output $prompt | out-file -Encoding ascii -Append $Output

    # Mirror Command to execute
    $cmdMirror = "PS " + (Convert-Path .) + "> " + $Command
    Write-Output $cmdMirror | out-file -Encoding ascii -Append $Output
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

function ExecCommandTrusted {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
    )

    Write-Host -ForegroundColor Cyan "$Command"
    ExecCommandPrivate -Command ($Command) -Output $Output
} # ExecCommandTrusted()

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

    $result = [CommandStatus]::NotTested

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
                throw "Error: $error[0]"
            }
        }

        # This is only reachable in success case
        $result = [CommandStatus]::Succeeded
    } Catch [Management.Automation.CommandNotFoundException] {
        $result = [CommandStatus]::Unavailable
    } Catch {
        $result = [CommandStatus]::Failed
    } Finally {
        # post-execution cleanup to avoid false positives
        $error.clear()
    }

    return $result
} # TestCommand()

# Powershell cmdlets have inconsistent implementations in command error handling. This function
# performs a validation of the command prior to formal execution and will log any failures.
function ExecCommand {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
    )

    # Use temp output to reflect the failed command, otherwise execute the command.
    $out = $Output

    $result = TestCommand -Command ($cmd)
    if ($result -eq [CommandStatus]::Succeeded) {
        Write-Host -ForegroundColor Green "$Command"
        ExecCommandPrivate -Command ($Command) -Output $out
    } else {
        Write-Warning "[Command $result] $Command"

        Write-Output "$Command" | Out-File -Encoding ascii -Append $out
        Write-Output "[Command $result]" | Out-File -Encoding ascii -Append $out
        Write-Output "`n`n" | Out-File -Encoding ascii -Append $out
    }
} # ExecCommand()

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
        ExecCommandTrusted -Command ($cmd) -Output $out
    }

    $file = "Get-NetTcpSetting.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetTcpSetting  | Format-Table -AutoSize",
                        "Get-NetTcpSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetTcpSetting  | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommandTrusted -Command ($cmd) -Output $out
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

function NetAdapterWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = $OutDir

    # Capture IP information
    NetIpNic -NicName $name -OutDir $OutDir

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

    $file = "Get-NetAdapterPowerManagment.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-NetAdapterPowerManagment -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPowerManagment -Name ""$name"" -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterPowerManagment | Get-Member"
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
    NetAdapterWorker -NicName $name -OutDir $dir
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
    ForEach($tnic in (Get-NetLbfoTeamNic -Team $name)) {
        NetAdapterWorkerPrepare -NicDesc $tnic.InterfaceDescription -OutDir $OutDir
    }

    # Report the NIC Members
    ForEach($mnic in Get-NetLbfoTeamMember -Team $name) {
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

    ForEach($lbfo in Get-NetLbfoTeam) {
        $name = $lbfo.Name

        # Skip all vSwitch Protocol NICs since the LBFO and member reporting will occur as part of
        # vSwitch reporting.
        $match = 0

        ForEach($vms in Get-VMSwitch) {
            if (-not ($vms.SwitchType -like "Internal")) {
                ForEach($desc in (Get-VMSwitch -Name $vms.Name).NetAdapterInterfaceDescriptions) {
                    if ((Get-NetAdapter -Name $name).InterfaceDescription -eq $desc) {
                        $match = 1
                        break
                    }
                }
                if ($match) {
                    break
                }
            }
        }

        if ($match -eq 0) {
            LbfoWorkerPrepare  -LbfoName $name -OutDir $out
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

    # Distinguish between LBFO from standard PTNICs and create the heriarchies accordingly
    ForEach($desc in (Get-VMSwitch -Name "$VMSwitchName").NetAdapterInterfaceDescriptions) {
        $nic = Get-NetAdapter -InterfaceDescription $desc
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            LbfoWorkerPrepare -LbfoName $nic.Name -OutDir $out
        }else {
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

    ForEach($nic in Get-NetAdapter) {
        # This must be pre-nitialized to 1 for
        $native = 1

        # Skip vSwitch Host vNICs by checking the driver
        if ($nic.DriverFileName -like "vmswitch.sys") {
            continue
        }

        # Skip LBFO TNICs by checking the driver
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            continue
        }

        # Skip all vSwitch Protocol NICs
        ForEach($vms in Get-VMSwitch) {
            if (-not ($vms.SwitchType -like "Internal")) {
                ForEach($desc in (Get-VMSwitch -Name $vms.Name).NetAdapterInterfaceDescriptions) {
                    if ($nic.InterfaceDescription -eq $desc) {
                        $native = 0
                        break
                    }
                }
                if ($native -eq 0) {
                    break
                }
            }
        }

        # Skip LBFO Team Member Adapters
        forEach($lbfonic in Get-NetLbfoTeamMember) {
            if ($nic.InterfaceDescription -eq $lbfonic.InterfaceDescription) {
                $native = 0
                break
            }
        }

        if ($native) {
            NetAdapterWorkerPrepare -NicDesc $nic.InterfaceDescription -OutDir $out
        }
    }
} # NativeNicDetail()

# function stub for extension by IHV
# Copy and rename it, add your commands, and call it in NicVendor() below
function MyVendorDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $IfIndex,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Try to keep the layout of this block of code
    # Feel free to copy it or wrap it in other control structures
    # See other functions in this file for examples
    $file = "$IfIndex.MyVendor.txt"
    $out = Join-Path $OutDir $file
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
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = Join-Path $OutDir "NicVendor"
    New-Item -Path $dir -ItemType Directory | Out-Null

    foreach ($nic in Get-NetAdapter) {
        $pciId = (Get-NetAdapterAdvancedProperty -Name $nic.Name -AllProperties -RegistryKeyword "ComponentID").RegistryValue
        switch -Wildcard($pciId) {
            # Not implemented
            #"PCI\VEN_1425*" {
            #    ChelsioDetail $nic.ifIndex $dir
            #}
            #"PCI\VEN_15B3*" {
            #    MellanoxDetail $nic.ifIndex $dir
            #}
            #"PCI\VEN_8086*" {
            #    IntelDetail $nic.ifIndex $dir
            #}
            default {
                # Not implemented, not native, or N/A
            }
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
    $out  = $OutDir

    $file = "Get-VMNetworkAdapter.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapter -ManagementOS| Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapterAcl -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterIsolation.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapterIsolation -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterVlan.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName $name | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName $name | Format-List  -Property *",
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

    ForEach($nic in (Get-VMNetworkAdapter -ManagementOS -SwitchName $VMSwitchName)) {

        # Correlate to VMNic instance to NetAdapter instance view
        # Physical to Virtual Mapping.
        # -----------------------------
        # Get-NetAdapter uses:
        #    Name                    : vEthernet (VMS-Ext-Public) 2
        # Get-VMNetworkAdapter uses:
        #    Name                    : VMS-Ext-Public
        #
        # Thus we need to match the corresponding devices via DeviceID such that
        # we can execute VMNetworkAdapter and NetAdapter information for this hNIC
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
    $dir  = $OutDir
    $name = $VMNicName

    $file = "Get-VMNetworkAdapter.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapter -Name ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -Name ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapter * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterAcl -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapterAcl | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapterExtendedAcl | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMName * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterIsolation.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapterIsolation | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapterRoutingDomainMapping | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
                        "Get-VMNetworkAdapterTeamMapping -VMName * | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMNetworkAdapterVlan.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMNetworkAdapterVlan -VMNetworkAdapterName ""$name"" -VMName $vmname | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -VMNetworkAdapterName ""$name"" -VMName $vmname | Format-List  -Property *",
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
    [String []] $cmds = "Get-VM -VMName $VMName | Out-String -Width $columns",
                        "Get-VM -VMName $VMName | Format-List  -Property *",
                        "Get-VM | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMBios.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMBios -VMName $VMName | Out-String -Width $columns",
                        "Get-VMBios -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMFirmware.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMFirmware -VMName $VMName | Out-String -Width $columns",
                        "Get-VMFirmware -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMProcessor.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMProcessor -VMName $VMName | Out-String -Width $columns",
                        "Get-VMProcessor -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMMemory.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMMemory -VMName $VMName | Out-String -Width $columns",
                        "Get-VMMemory -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMVideo.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMVideo -VMName $VMName | Out-String -Width $columns",
                        "Get-VMVideo -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
    
    $file = "Get-VMHardDiskDrive.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMHardDiskDrive -VMName $VMName | Out-String -Width $columns",
                        "Get-VMHardDiskDrive -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMComPort.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMComPort -VMName $VMName | Out-String -Width $columns",
                        "Get-VMComPort -VMName $VMName | Format-List  -Property *"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSecurity.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSecurity -VMName $VMName | Out-String -Width $columns",
                        "Get-VMSecurity -VMName $VMName | Format-List  -Property *"
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

    ForEach($vm in Get-VM) {
        $vmname = $vm.Name
        $vmid   = $vm.VMId

        Write-Host "Processing: VM.$vmname.$vmid"
        Write-Host "--------------------------------------"
        ForEach($nic in (Get-VMNetworkAdapter -VMName $vmname)) {
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
    $out  = $OutDir

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
    [String []] $cmds = "Get-VMSwitchExtensionSwitchData -SwitchName $name | Format-List  -Property *",
                        "Get-VMSwitchExtensionSwitchData -SwitchName $name | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchExtensionSwitchFeature.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchExtensionSwitchFeature -SwitchName $name | Format-List -Property *"
                        #"Get-VMSwitchExtensionSwitchFeature -SwitchName $name | Get-Member"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    $file = "Get-VMSwitchTeam.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-VMSwitchTeam -SwitchName $name | Format-List -Property *",
                        "Get-VMSwitchTeam -SwitchName $name | Get-Member"
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
    [String []] $cmds = "Get-VMSwitchExtensionPortData -SwitchName $name | Format-List  -Property *",
                        "Get-VMSwitchExtensionPortData -SwitchName $name | Get-Member"
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

    ForEach($ext in (Get-VMSwitch -Name $name | Get-VMSwitchExtension)) {
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

    ForEach($switch in Get-VMSwitch) {
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
        [String []] $cmds = "Get-NetAdapter -includeHidden | Sort-Object InterfaceDescription | Format-Table -AutoSize",
                            "Get-NetAdapter -includeHidden | Format-Table -Property * -AutoSize | Sort-Object InterfaceDescription | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetAdapterStatistics.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterStatistics -includeHidden | Format-Table -Autosize | Sort-Object InterfaceDescription | Out-String -Width $columns",
                            "Get-NetAdapterStatistics -includeHidden | Format-Table * -Autosize | Sort-Object InterfaceDescription | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetLbfoTeam.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetLbfoTeam | Sort-Object InterfaceDescription",
                            "Get-NetLbfoTeam | Format-Table -Property * -AutoSize | Sort-Object InterfaceDescription | Out-String -Width $columns"
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
    [String []] $cmds = "Test-Path C:\Windows\System32\NetSetupMig.log",
                        "Test-Path C:\Windows\Panther\setupact.log",
                        "Test-Path C:\Windows\INF\setupapi.*",
                        "Test-Path C:\Windows\logs\NetSetup"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }

    # Copy over the logs      
    [String []] $cmds = "C:\Windows\System32\NetSetupMig.log",
                        "C:\Windows\Panther\setupact.log",
                        "C:\Windows\INF\setupapi.*",
                        "C:\Windows\logs\NetSetup"
    ForEach($cmd in $cmds) {
        if (Test-Path $cmd) {
            $tcmd = "Copy-Item $cmd $dir -recurse -verbose 4>&1"
            ExecCommandTrusted -Command ($tcmd) -Output $out
        }
    }   
} # NetSetupDetail()

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
    [String []] $cmds = "Get-Service ""*"" | Sort-Object name",
                        "Get-Service ""*"" | Sort-Object status"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }
    
    $file = "Get-WindowsDriver.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WindowsDriver -Online -All"
    ForEach($cmd in $cmds) {
        ExecCommandTrusted -Command $cmd -Output $out
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
    $file = "NetRundown.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "New-NetEventSession    NetRundown -CaptureMode SaveToFile -LocalFilePath $dir\NetRundown.etl",
                        "Add-NetEventProvider   ""{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x10000",
                        "Add-NetEventProvider   ""{DD7A21E6-A651-46D4-B7C2-66543067B869}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x2",
                        "Start-NetEventSession  NetRundown",
                        "Stop-NetEventSession   NetRundown",
                        "Remove-NetEventSession NetRundown"
    ForEach($cmd in $cmds) {
        ExecCommandTrusted -Command $cmd -Output $out
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
        ExecCommandTrusted -Command $cmd -Output $out
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
    $cntrList = @("*Hyper*", "*ip*", "*udp*", "*tcp*", "*icmp*", "*nat*", "*network*", "*rdma*", "*smb*", "*wfp*", "*Mellanox*", "*intel*")
    $cntrPaths = Get-Counter -ListSet $cntrList | Sort-Object CounterSetName | ForEach-Object { $_.Paths }

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
        ExecCommandTrusted -Command ($cmd) -Output $out
    }
} # HwErrorReport()

function LogsReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "WinEVT.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "copy-item C:\Windows\System32\winevt $outdir -recurse -verbose 4>&1"
    ForEach($cmd in $cmds) {
        ExecCommandTrusted -Command ($cmd) -Output $out
    }
} # LogsReport()

function Metadata {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [Collections.Generic.Dictionary`2+Enumerator[String, Object]] $Params
    )

    $file = "Metadata.txt"
    $out = (Join-Path -Path $OutDir -ChildPath $file)
    [String []] $cmds = "Write-Output ""Version: $version"", ""Parameters: $Params"" | Out-String -Width $columns",
                        "Get-FileHash -Path $($MyInvocation.PSCommandPath) -Algorithm ""SHA256"" | Format-List -Property * | Out-String -Width $columns"
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

    # Validate user input or use desktop if none
    $baseDir = If ($OutputDirectory) {
                   If (Test-Path $OutputDirectory) {
                       (Resolve-Path $OutputDirectory).Path # full path
                   } Else {
                       Throw "Get-NetView : The directory '$OutputDirectory' does not exist."
                   }
               } ElseIf (($desktop = [Environment]::GetFolderPath("Desktop"))) {
                   $desktop
               } Else {
                   $env:temp
               }
    $workDirName = "msdbg." + $env:computername

    return Join-Path $baseDir $workDirName
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
    Try {
        New-Item -ItemType directory -Path $OutDir -ErrorAction Stop | Out-Null
    } Catch {
        Throw ("Get-NetView : Failed to create directory '$OutDir' because " + $error[0])
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

function Completion {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Src,
        [parameter(Mandatory=$true)] [String] $OutZip
    )

    # Zip output folder
    CreateZip -Src $Src -Out $OutZip

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
    Write-Host $OutZip
    Write-Host "Size:    $("{0:N2} MB" -f ((Get-Item $OutZip).Length / 1MB))"
    Write-Host ""
    Write-Host $Src
    Write-Host "Size:    $("{0:N2} MB" -f ($dirs.sum / 1MB))"
    Write-Host "Dirs:    $((Get-ChildItem $Src -Directory -Recurse | Measure-Object).Count)"
    Write-Host "Files:   $((Get-ChildItem $Src -File -Recurse | Measure-Object).Count)"
} # Completion()

function Worker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $OutputDirectory,
        [parameter(Mandatory=$false)] [Bool] $SkipAdminCheck
    )

    $columns   = 4096
    $version   = "2017.09.27.0" # Version within date context
    $timestamp = Get-Date -f yyyy.MM.dd_hh.mm.ss

    # Input Validation
    CheckAdminPrivileges $SkipAdminCheck
    $workDir   = (NormalizeWorkDir $OutputDirectory)

    EnvSetup          -OutDir $workDir

    # Start Run
    Clear-Host

    Metadata          -OutDir $workDir -Params $PSBoundParameters.GetEnumerator()
    HostInfo          -OutDir $workDir
    Environment       -OutDir $workDir
    NetworkSummary    -OutDir $workDir
    
    HwErrorReport     -OutDir $workDir
    LogsReport        -OutDir $workDir
     
    NetSetupDetail    -OutDir $workDir
    VMSwitchDetail    -OutDir $workDir
    LbfoDetail        -OutDir $workDir
    NativeNicDetail   -OutDir $workDir
    NicVendor         -OutDir $workDir
    QosDetail         -OutDir $workDir
    SMBDetail         -OutDir $workDir
    NetIp             -OutDir $workDir
    ServicesDrivers   -OutDir $workDir
    NetshTrace        -OutDir $workDir
    Counters          -OutDir $workDir

    Completion -Src $workDir -OutZip "$workDir-$timestamp.zip"
} # Worker()

function Get-NetView {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false,HelpMessage="Complete Path to the output directory")] [String] $OutputDirectory,
        [parameter(Mandatory=$false,HelpMessage="Skip check for Administrator privileges")] [Switch] $SkipAdminCheck
    )

    # If it moves, measure it.  We should know how long this takes...
    Measure-Command {Worker @PSBoundParameters} | select @{n="Execution Time:";e={$_.Minutes,"Min",$_.Seconds,"Sec" -join " "}}
} Get-NetView @PSBoundParameters # Entry Point
