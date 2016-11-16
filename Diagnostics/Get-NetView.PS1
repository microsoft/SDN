



<# 
  Execute this command on the PS windows to enable execution:

  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
#>

<#
 # INSTRUCTIONS:
    #Summary
    Use this tool to acquire OS and Platform data via PowerShell:

	Set the PS execution policy on target machines as follows:
		Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
	Run the script on each target machines of interest:
        NetView.ps1

        A working directory will be placed on the desktop.
        The script will reap the system data of interest (currently scoped to network and platform)
    
    After script complete a *.zip file will be placed on the desktop.
    Send this file to Microsoft.

    Output is most efficiently viewed with Visual Studio Code or equivalent editor with a navigation panel.
        Unzip the output file
        Open the base directory with Visual Studio Code and review via the Navigation Panel 
#>


function ExecCommandPrivate {
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

    # Execute Command and redirect to file.  Useful so users know what to run..
    Invoke-Expression $Command | Out-File -Encoding ascii -Append $Output
} 

function ExecCommandTrusted {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command, 
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
    )

    Write-Host -ForegroundColor Cyan "$Command"
    ExecCommandPrivate -Command ($Command) -Output $Output
}

function TestCommand {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command
    )

    Try {
        # pre-execution cleanup
        $error.clear()

        # Instrument the validate command for silent output
        #$tmp = "$Command -erroraction 'silentlycontinue' | Out-Null"
        $tmp = "$Command | Out-Null"

        # Redirect all error output to $Null to encompass all possible errors
        #Write-Host $tmp -ForegroundColor Yellow
        Invoke-Expression $tmp 2> $Null
        if ($error -ne $null) {
            # Some PS commands are incorrectly implemented in return code 
            # and require detecting SilentContinue
            if (-not ($tmp -like '*SilentlyContinue*')) {
                throw "Error: $error[0]" 
            }
        }

        # This is only reachable in success case
        Write-Host -ForegroundColor Green "$Command"
        $script:Err = 0
    }Catch {
        Write-Warning "[NOT_SUPPORTED] $Command"
        $script:Err = -1
    }Finally {
        # post-execution cleanup to avoid false positives
        $error.clear()
    }
}

# Powershell cmdlets have inconsistent implementations in command error handling.  This
# function performs a validation of the command prior to formal execution and logs said
# commands in a file suffixed with Not-Supported.txt.
function ExecCommand {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Output
    )
    
    # Use temp output to reflect the failed command, otherwise execute the command.
    $out = $Output
    TestCommand -Command ($cmd)
    if ($script:Err -ne 0) {
        #$out = $out.Replace(".txt",".UNSUPPORTED.txt")
        Write-Output "$Command" | Out-File -Encoding ascii -Append $out
        Write-Output "[ NOT_SUPPORTED!!! ]" | Out-File -Encoding ascii -Append $out
        Write-Output "`n`n" | Out-File -Encoding ascii -Append $out
    }else {
        ExecCommandPrivate -Command ($Command) -Output $out
    }
}

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
        [String []] $cmds = "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -AutoSize",
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
                            "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                            "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                            "Get-NetNeighbor | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetRoute.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                            "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                            "Get-NetRoute | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }                                  
}

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
}

function NetIpWorker {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [String] $OutDir
        )
        
        $dir  = $OutDir

        $file = "Get-NetIpAddress.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetIpAddress | Format-Table -AutoSize",
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
                            "Get-NetIPInterface | Format-Table -AutoSize",
                            "Get-NetIPInterface | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                            "Get-NetIPInterface | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetNeighbor.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetNeighbor | Format-Table -AutoSize",
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
}

function NetIp {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetIp"))
    New-Item -ItemType directory -Path $dir | Out-Null
    NetIpWorker -OutDir $dir
}

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
        [String []] $cmds = "Get-NetAdapter -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapter -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapter | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterAdvancedProperty.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Out-String -Width $columns",
                            "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-List  -Property *",
                            "Get-NetAdapterAdvancedProperty | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterBinding.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterBinding -Name ""$name"" -AllBindings | Out-String -Width $columns",
                            "Get-NetAdapterBinding -Name ""$name"" -AllBindings | Format-List  -Property *",
                            "Get-NetAdapterBinding | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterChecksumOffload.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterChecksumOffload -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterChecksumOffload -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterChecksumOffload | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterLso.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterLso -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterLso -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterLso | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterRss.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterRss -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterRss -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterRss | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        #<##### FIXME!!!!! - Detect properties for all below


        $file = "Get-NetAdapterStatistics.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterStatistics -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterStatistics -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterStatistics | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }   


        # Execute command list
        $file = "Get-NetAdapterEncapsulatedPacketTaskOffload.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterEncapsulatedPacketTaskOffload | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterHardwareInfo.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterHardwareInfo -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterHardwareInfo -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterHardwareInfo | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        # Execute command list - Detect Property
        $file = "Get-NetAdapterIPsecOffload.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterIPsecOffload -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterIPsecOffload -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterIPsecOffload | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }


        $file = "Get-NetAdapterPowerManagment.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterPowerManagment -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterPowerManagment -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterPowerManagment | Get-Member"
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterQos.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterQos -Name ""$name"" -ErrorAction SilentlyContinue | Out-String -Width $columns",
                            "Get-NetAdapterQos -Name ""$name"" -ErrorAction SilentlyContinue | Format-List  -Property *",
                            "Get-NetAdapterQos | Get-Member"                            
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }
        
        $file = "Get-NetAdapterRdma.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterRdma -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterRdma -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterRdma | Get-Member"                                                        
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterPacketDirect.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterPacketDirect -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterPacketDirect -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterPacketDirect | Get-Member"                            
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterRsc.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterRsc -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterRsc -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterRsc | Get-Member" 
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterSriov.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterSriov -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterSriov -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterSriov | Get-Member" 
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }
        
        $file = "Get-NetAdapterSriovVf.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterSriovVf -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterSriovVf -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterSriovVf | Get-Member" 
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterVmq.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterVmq -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterVmq -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterVmq | Get-Member" 
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterVmqQueue.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterVmqQueue -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterVmqQueue -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterVmqQueue | Get-Member" 
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }

        $file = "Get-NetAdapterVPort.txt"
        $out  = (Join-Path -Path $dir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapterVPort -Name ""$name"" | Out-String -Width $columns",
                            "Get-NetAdapterVPort -Name ""$name"" | Format-List  -Property *",
                            "Get-NetAdapterVPort | Get-Member" 
        ForEach($cmd in $cmds) {
            ExecCommand -Command ($cmd) -Output $out
        }
}

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
}

function ProtocolNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Variables
    $out = $OutDir

    ForEach($desc in (Get-VMSwitch -Name "$VMSwitchName").NetAdapterInterfaceDescriptions) {
        NetAdapterWorkerPrepare -NicDesc $desc -OutDir $out
    }
}

function NativeNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Normalize Variables
    $out = $OutDir

    ForEach($nic in Get-NetAdapter) {
        # Skip Host vNICs
        if (-not ($nic.DriverFileName -like "vmswitch.sys")) {
            # Only query the Native NICs, meaning NICs not acting as any vSwitch Protocol NICs.
            $native = 1
            ForEach($vms in Get-VMSwitch) {
                if (-not ($vms.SwitchType -like "Internal")) {
                    ForEach($desc in (Get-VMSwitch -Name $vms.Name).NetAdapterInterfaceDescriptions) {
                        if ($nic.InterfaceDescription -eq $desc) {
                            $native = 0;
                        }
                    }
                }
            }
        }

        if ($native) {
            NetAdapterWorkerPrepare -NicDesc $nic.InterfaceDescription -OutDir $out
        }
    }
}

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
}

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
        foreach($pnic in Get-NetAdapter) {
            if ($pnic.DeviceID -eq $nic.DeviceId) {
                $pnicname = $pnic.Name
                $idx      = $pnic.IfIndex
            }
        }
        
        # Create dir for each NIC
        $name    = $nic.Name
        $desc    = $nic.InterfaceDescription
        $nictype = "hNic"
        $title   = "$nictype." + $idx + ".$name" + ".$desc"
        $dir     = (Join-Path -Path $OutDir -ChildPath ("$title"))
        New-Item -ItemType directory -Path $dir | Out-Null
        
        Write-Host "Processing: $title"
        Write-Host "----------------------------------------------"
        HostVNicWorker   -HostVNicName $name     -OutDir $dir
        NetAdapterWorker -NicName      $pnicname -OutDir $dir
    }
}


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
}

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
}

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
    #
    # Lots more commands to add here....
    #
}

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
}

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
}

function VMSwitchDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    ##See this command to get VFs on vSwitch
    #Get-NetAdapterSriovVf -SwitchId 2



    ForEach($switch in Get-VMSwitch) {
        $name = $switch.Name
        $type = $switch.SwitchType
 
        $dir  = (Join-Path -Path $OutDir -ChildPath ("vms.$type.$name"))
        New-Item -ItemType directory -Path $dir | Out-Null
        
        Write-Host "Processing: $name"
        Write-Host "----------------------------------------------"
        VMSwitchWorker        -VMSwitchName $name -OutDir $dir
        ProtocolNicDetail     -VMSwitchName $name -OutDir $dir
        HostVNicDetail        -VMSwitchName $name -OutDir $dir
        VMNetworkAdapterPerVM -VMSwitchName $name -OutDir $dir
    }
}

function NetworkSummary {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "Get-VMSwitch.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-VMSwitch",
                            "Get-VMSwitch | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-VMNetworkAdapter.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-VMNetworkAdapter -All",
                            "Get-VMNetworkAdapter -All | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetAdapter.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetAdapter",
                            "Get-NetAdapter | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }

    $file = "Get-NetIpAddress.txt"
    $out  = (Join-Path -Path $OutDir -ChildPath $file)
        [String []] $cmds = "Get-NetIpAddress | ft",
                            "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    }
}

function QosDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("NetworkQoS"))
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
}


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

    Write-Host "Processing..."
    $file = "Get-WindowsDriver.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WindowsDriver –Online -All"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    } 

    $file = "Get-WindowsEdition.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WindowsEdition –Online"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    } 

    $file = "Get-WmiObject.Win32_PnPSignedDriver.txt"
    $out  = (Join-Path -Path $dir -ChildPath $file)
    [String []] $cmds = "Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion"
    ForEach($cmd in $cmds) {
        ExecCommand -Command $cmd -Output $out
    } 
}

function NetshTrace {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir    = (Join-Path -Path $OutDir -ChildPath ("Netsh"))
    New-Item -ItemType directory -Path $dir | Out-Null

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
        ExecCommand -Command $cmd -Output $out
    }   
}

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
                        "systeminfo"
    ForEach($cmd in $cmds) {
        ExecCommand -Command ($cmd) -Output $out
    }
}

function EnvDestroy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )
    If (Test-Path $OutDir) {
        Remove-Item $OutDir -Recurse
    }
}

function EnvCreate {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )
    New-Item -ItemType directory -Path $OutDir | Out-Null
}


function CreateZip {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Src,
        [parameter(Mandatory=$true)] [String] $Dest,
        [parameter(Mandatory=$true)] [String] $ZipName
    )

    $timestamp = $(get-date -f yyyy.MM.dd_hh.mm.ss)
    $out       = "$Dest" + "$ZipName" + "-$timestamp" + ".zip"

    If(Test-path $out) {
        Remove-item $out
    }

    add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($Src, $out)
}

function Worker {
    clear
    $columns = 4096

    $user          = [Environment]::UserName
    $workDirPrefix = "msdbg." + $env:computername
    $baseDir       = "C:\Users\$user\Desktop\"
    $workDir       = "$baseDir" + "$workDirPrefix"

    EnvDestroy        -OutDir $workDir
    EnvCreate         -OutDir $workDir

    Environment                 -OutDir $workDir
    NetworkSummary              -OutDir $workDir
    VMSwitchDetail              -OutDir $workDir  
    NativeNicDetail             -OutDir $workDir
    QosDetail                   -OutDir $workDir
    NetIp                       -OutDir $workDir
    ServicesDrivers             -OutDir $workDir
    NetshTrace                  -OutDir $workDir

    #FIXME!!!  SDN uses PA NIC in non-default compartments.  The Get-NetAdapter* cmdlets need to be updated to
    #          operate on the -includeHidden parameter and validated in an SDN setup.

    #PerfCounters                -OutDir $workDir
    #SMBDetail                   -OutDir $workDir
    
    CreateZip -Src $workDir -Dest $baseDir -ZipName $workDirPrefix
}

function Main {
    # If it moves, measure it.  We should know how long this takes...
    Measure-Command { Worker }
} Main #Entry Point
