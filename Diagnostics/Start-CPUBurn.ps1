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
