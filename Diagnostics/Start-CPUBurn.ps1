<#
  .SYNOPSIS
  Testing tool to initiate CPU utilization 
  
  .DESCRIPTION
  This tool allows you to initiate CPU Utilization on select processors or on all processors.

  .EXAMPLE
  .\Start-CPUBurn.ps1 -AllProcessors

  .EXAMPLE
  .\Start-CPUBurn.ps1 -Processors 3

  .EXAMPLE
  .\Start-CPUBurn.ps1 -Processors 0,2,3
  
  .PARAMETER AllProcessors
  This is a switch that flags all processors for burn

  .PARAMETER Processors
  Accepts 1 or more processors as input for burn

  The local system range can contain input of 0 - $env:NUMBER_OF_PROCESSORS
#>

param (
    [Parameter(ParameterSetName = "All Processors")]
    [Switch] $AllProcessors,
    
    [Parameter(Mandatory = $true, ParameterSetName = "Specific Processors")]
    [ValidateScript({ $_ -lt ${env:NUMBER_OF_PROCESSORS} })]
    [int[]] $Processors
)

If (!($Processors) -or $AllProcessors) {
    0..( $env:NUMBER_OF_PROCESSORS-1 ) | ForEach-Object {
        [int] $procNum = [Math]::Pow(2, $_)

        $processInfo           = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName  = 'powershell.exe'
        $processInfo.Arguments = " -NoExit -Command & {
                                        `$Host.UI.RawUI.WindowTitle=`'CPU Number: `' + $_ ; 
                                            Write-Output 'PID:' `$PID ;
                                        `$result = 1; foreach (`$number in 1..2147483647) {`$result = `$result * `$number}
                                }"

        $process           = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
    
        $process.Start() | Out-Null
        $process.ProcessorAffinity = $procNum
    }
}
Else {
    foreach ($Processor in $Processors) {
        [int] $procNum = [Math]::Pow(2, $processor)

        $processInfo           = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName  = 'powershell.exe'
        $processInfo.Arguments = " -NoExit -Command & {
                                        `$Host.UI.RawUI.WindowTitle=`'CPU Number: `' + $processor ; 
                                            Write-Output 'PID:' `$PID ;
                                        `$result = 1; foreach (`$number in 1..2147483647) {`$result = `$result * `$number}
                                }"

        $process           = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
    
        $process.Start() | Out-Null
        $process.ProcessorAffinity = $procNum
    }
}
