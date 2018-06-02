Function Get-SWTimestamping {
<#
  .SYNOPSIS
  Gets the software timestamping configuration of a specified NICs
  
  .DESCRIPTION
  Software Timestamping is a feature that enables increased time accuracy by calculating the delay introduced by the network stack

  Use this command to enable Software Timestamping for a specified NIC

  Note: Enabling software timestamping on virtual NICs, WAN Miniport, WI-FI Adapters, is not supported

  .EXAMPLE
  Get-SWTimestamping -NetAdapterName NIC1, NIC2
  
  .EXAMPLE
  $tsAdapters = Get-SWTimestamping -NetAdapterName NIC1, NIC2

  .PARAMETER NetAdapterName
  The adapter to retrieve the timestamping configuration

  Reference the 'Name' Property of Get-NetAdapter for possible adapter names
#>

    param (
        [String[]] $NetAdapterName = (Get-NetAdapter).Name
    )

    $NetAdapterDescription = (Get-NetAdapter -Name $NetAdapterName).InterfaceDescription

    $status = Get-NetAdapterAdvancedProperty -InterfaceDescription $NetAdapterDescription `
                                             -RegistryKeyword SoftwareTimestampSettings -AllProperties `
                                             -ErrorAction SilentlyContinue | Select Name, RegistryKeyword, RegistryValue

    If (-not($status)) {
        Write-Error "Software Timestamping is not configured on $NetAdapterName"
    }

    $status
}

Function Enable-SWTimestamping {
<#
  .SYNOPSIS
  Enables software timestamping on specified NICs
  
  .DESCRIPTION
  Software Timestamping is a feature that enables increased time accuracy by calculating the delay introduced by the network stack

  Use this command to enable Software Timestamping for a specified NIC

  Note: This is a software only implementation and does not include the latency/uncertainty added by the miniport or hardware
  Note: Enabling software timestamping on virtual NICs, WAN Miniport, WI-FI Adapters, is not supported

  Known Issue: Devices that have special characters such as parenthesis currently do not work

  .EXAMPLE
  Enable-SWTimestamping -NetAdapterName NIC1, NIC2
  
  .EXAMPLE
  Enable-SWTimestamping -NetAdapterName NIC1, NIC2, NIC3, NIC4 -TimestampValue 5

  .PARAMETER NetAdapterName
  The adapter you want to enable timestamping on

  Reference the 'Name' Property of Get-NetAdapter for possible adapter names

  .PARAMETER TimestampValue
  Specifies the specific traffic to be timestamped.
    
  Default is 5
        1 - All RX
        2 - All Tx
        3 - All RX - ALL TX
        4 - Only Selective TX
        5 - ALL RX (Selective TX)
#>

    param (
        [Parameter(Mandatory=$true)]
        [String[]] $NetAdapterName ,

        [ValidateRange(1,5)]
        [int] $TimestampValue = 5
    )

    $Interface = @()
    $InterfaceGUIDs = (Get-NetAdapter -Name $NetAdapterName).InterfaceGuid

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($interfaceGUID in $interfaceGUIDs) {
            $psPath = $_.PSPath
            $driverDesc = (Get-ItemProperty -Path $PsPath).DriverDesc

            if ( (Get-ItemProperty -Path $PsPath) -match $InterfaceGUID) {
                Switch ($driverDesc) {
                    {
                        $PSItem -like '*Hyper-V*' -or 
                        $PSItem -like '*Microsoft Kernel Debug*' -or 
                        $PSItem -like '*WAN Miniport*' -or 
                        $PSItem -like '*WI-FI*'
                    } 
                    {
                        Write-Error 'Enabling software timestamps on Hyper-V vNICs, Kernel Debug adapters, WAN Miniports, or WI-FI adapters is not supported'
                        break
                    }
            
                    default {
                        Set-ItemProperty -Path $psPath -Name SoftwareTimestampSettings -Value $TimestampValue
                    }
                }
            }
        }
    }
}

Function Disable-SWTimestamping {
<#
  .SYNOPSIS
  Disables software timestamping on specified NICs
  
  .DESCRIPTION
  Software Timestamping is a feature that enables increased time accuracy by calculating the delay introduced by the network stack

  Use this command to remove the Software Timestamping configuration for a specified NIC

  Known Issue: Devices that have special characters such as parenthesis currently do not work

  .EXAMPLE
  Disable-SWTimestamping -NetAdapterName NIC1, NIC2
  
  .PARAMETER NetAdapterName
  The adapter you want to enable timestamping on

  Reference the 'Name' Property of Get-NetAdapter for possible adapter names
#>

    param (
        [Parameter(Mandatory=$true)]
        [String[]] $NetAdapterName
    )

    $Interface = @()
    $InterfaceGUIDs = (Get-NetAdapter -Name $NetAdapterName).InterfaceGuid

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($interfaceGUID in $interfaceGUIDs) {
            $psPath = $_.PSPath
            $driverDesc = (Get-ItemProperty -Path $PsPath).DriverDesc

            if ( (Get-ItemProperty -Path $PsPath) -match $InterfaceGUID) {
                Remove-ItemProperty -Path $psPath -Name SoftwareTimestampSettings
            }
        }
    }
}

Export-ModuleMember -Function *-SWTimestamping
