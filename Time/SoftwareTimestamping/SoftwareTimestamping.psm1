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
        [String[]] $NetAdapterName = (Get-NetAdapter | Where-Object `
                     {$_.InterfaceDescription -notlike '*Microsoft Kernel Debug*' -and
                      $_.InterfaceDescription -notlike '*WAN Miniport*' -and
                      $_.InterfaceDescription -notlike '*WI-FI*'}).Name
    )

    if ($NetAdapterName -eq $null) {
        Write-Warning -Message 'No acceptable adapters were found. Review the help of this cmdlet as some adapters are not eligible for software timestamping'
        break
    }
    
    $NetAdapterDescription = (Get-NetAdapter -Name $NetAdapterName).InterfaceDescription

    $status = Get-NetAdapterAdvancedProperty -InterfaceDescription $NetAdapterDescription `
                                             -RegistryKeyword SoftwareTimestampSettings -AllProperties `
                                             -ErrorAction SilentlyContinue | Select-Object Name, RegistryKeyword, RegistryValue

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

    $InterfaceGUIDs = (Get-NetAdapter -Name $NetAdapterName).InterfaceGuid

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($interfaceGUID in $interfaceGUIDs) {
            $psPath = $_.PSPath
            $driverDesc = (Get-ItemProperty -Path $PsPath).DriverDesc

            if ( (Get-ItemProperty -Path $PsPath) -match $InterfaceGUID) {
                Switch ($driverDesc) {
                    {
                        $PSItem -like '*Microsoft Kernel Debug*' -or 
                        $PSItem -like '*WAN Miniport*' -or 
                        $PSItem -like '*WI-FI*'
                    } 
                    {
                        Write-Error 'Enabling software timestamps on Kernel Debug adapters, WAN Miniports, or WI-FI adapters is not supported'
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

    $InterfaceGUIDs = (Get-NetAdapter -Name $NetAdapterName).InterfaceGuid

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($interfaceGUID in $interfaceGUIDs) {
            $psPath = $_.PSPath
            
            if ( (Get-ItemProperty -Path $PsPath) -match $InterfaceGUID) {
                Remove-ItemProperty -Path $psPath -Name SoftwareTimestampSettings
            }
        }
    }
}

enum Ensure {
   Absent
   Present
}

[DscResource()]
class SoftwareTimestamping {

    [DscProperty(Key)]
    [string] $NetAdapterName

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty()]
    [validaterange(1,5)]
    [int] $TimestampValue = 5

    [DscProperty(NotConfigurable)]
    [string] $RegistryKeyword

    [DscProperty(NotConfigurable)]
    [string] $RegistryValue

    [DscProperty(NotConfigurable)]
    [string] $interfaceGUID


    [SoftwareTimestamping] Get() {
        $NetAdapter = (Get-NetAdapter -Name $this.NetAdapterName)
        
        $status = Get-NetAdapterAdvancedProperty -InterfaceDescription $NetAdapter.InterfaceDescription `
                                                 -RegistryKeyword SoftwareTimestampSettings -AllProperties `
                                                 -ErrorAction SilentlyContinue | Select-Object Name, RegistryKeyword, RegistryValue
        
        $this.interfaceGUID   = $NetAdapter.InterfaceGUID
        
        If ($status.RegistryValue -eq $NULL) {
            $this.RegistryValue = 'Not Configured'
        } 
        Else {
            $this.RegistryValue   = $status.RegistryValue
        }

        If ($status.RegistryKeyword -eq $NULL) {
            $this.RegistryKeyword = 'Not Configured'
        } 
        Else {
            $this.RegistryKeyword   = $status.RegistryKeyword
        }

        return $this
    }

    [bool] Test() {
        $this.Get()

        switch ($this.Ensure) {
            'Absent' {
                if ($this.RegistryKeyword -ne 'Not Configured') {
                    Write-Verbose -Message " - Expected Software Timestamping Configuration for $($this.NetAdapterName) : Not Configured"
                    Write-Verbose -Message " - Actual Software Timestamping Configuration for $($this.NetAdapterName) : $($this.RegistryValue)"
                    Write-Verbose -Message " --- Configuration required for $($this.NetAdapterName) :: Removing Software Timestamping Configuration"

                    return $false
                }
                else { return $true }
            }

            'Present' {
                If ($this.TimestampValue -eq $this.RegistryValue) {
                    Write-Verbose "No configuration required for $($this.NetAdapterName)"
                } 
                else {
                    Write-Verbose -Message " - Expected Software Timestamping Configuration for $($this.NetAdapterName) : $($this.TimestampValue)"
                    Write-Verbose -Message " - Actual Software Timestamping Configuration for $($this.NetAdapterName) : $($this.RegistryValue)"
                    Write-Verbose -Message " --- Configuration required for $($this.NetAdapterName) :: Setting Software Timestamping Value"
                }
            }

            default { 
                $message = 'Catastrophic Failure: An invalid value for the enum ''Ensure'' was presented to the Test() Method.  Debug the DSC Resource using ''Enable-DscDebug -BreakAll'' and determine the cause of entry of the ''default'' switch case'
                Write-Error -Category InvalidArgument -Message $message 
            
                break 
            }
        }
        
        return ($this.TimestampValue -eq $this.RegistryValue)
    }

    [void] Set() {
        $this.Get()

        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ForEach-Object {
            $psPath = $_.PSPath
            $driverDesc = (Get-ItemProperty -Path $PsPath).DriverDesc

            if ( (Get-ItemProperty -Path $PsPath) -match $this.InterfaceGUID) {
                switch ($this.Ensure) {
                    'Absent' {
                        Write-Warning "Disabling Software Timestamping on adapter: $($this.NetAdapterName)"
                        
                        Remove-ItemProperty -Path $psPath -Name SoftwareTimestampSettings -ErrorAction SilentlyContinue
                    }

                    'Present' {
                        Switch ($driverDesc) {
                            {
                                $PSItem -like '*Microsoft Kernel Debug*' -or 
                                $PSItem -like '*WAN Miniport*' -or 
                                $PSItem -like '*WI-FI*'
                            } 
                            {
                                Write-Error "The following adapter is not supported for Software Timestamping: $($this.NetAdapterName)"
                                Write-Warning 'Enabling software timestamps on Kernel Debug adapters, WAN Miniports, or WI-FI adapters is not supported'

                                break
                            }
            
                            default {
                                Write-Verbose "Enabling Software Timestamping on adapter: $($this.NetAdapterName)"
                                Set-ItemProperty -Path $psPath -Name SoftwareTimestampSettings -Value $this.TimestampValue
                            }
                        }
                    }
                }
            }
        }
    }
}

Export-ModuleMember -Function *-SWTimestamping
