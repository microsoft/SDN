[CmdletBinding()]
param
(
    # Path to the module defining the strategy to use for monitoring the node
    [string]
    $StrategyModulePath = "C:\k\debug\StrategyModulePath.psm1"
)  

function Start-HNSTrace
{
    .\collectlogs.ps1
    $sessionName = 'HnsCapture'
    Write-Host "Starting HNS tracing"

    $curDir = Get-Location
    # Generate a random directory to capture all the logs
    $etlPath = [io.Path]::Combine($curDir.Path, "HNSTrace.etl")
    .\starthnstrace.ps1 -NoPrompt -MaxFileSize 1024 -EtlFile $etlPath
}

function Stop-HNSTrace
{
    # Stop the tracing
    $sessionName = 'HnsCapture'
    Write-Host "Stopping $sessionName."
    Stop-NetEventSession $sessionName 

    # Collect logs
    .\collectlogs.ps1
    .\collect-windows-logs.ps1

    # Take a HNS Process dump
    $hnsProcessId = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Hns'" | Select-Object -ExpandProperty ProcessId
    .\Procdump\Procdump.exe -ma $hnsProcessId /accepteula
}

'''
Start-Monitoring

Monitors Windows node for an error condition by polling every 15 seconds.
Gathers all the necessary logs if Windows node goes into an error/faulted state. 
'''
function Start-Monitoring
{
    param
    (
        # Path with filename where the configuration module is located
        [string]
        $StrategyModulePath = "C:\k\debug\StrategyModule.psm1",

        # Interval to poll for failure in seconds 
        [int]
        $PollingInterval = 15,

        # Number of consecutive failures to declare the node is faulty
        [int]
        $FailureThreshold = 3
    )

    $curDir = Get-Location
    # Generate a random directory to capture all the logs
    $outDir = [io.Path]::Combine($curDir.Path, [io.Path]::GetRandomFileName())
    md $outDir
    pushd
    cd $outDir

    # Download necessary files
    wget https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1 -o collectlogs.ps1
    wget https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/VFP.psm1 -o VFP.psm1
    wget https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/hns.psm1 -o HNS.psm1
    wget https://raw.githubusercontent.com/Azure/aks-engine/master/scripts/collect-windows-logs.ps1 -o collect-windows-logs.ps1
    wget https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/starthnstrace.ps1 -o starthnstrace.ps1
    wget https://download.sysinternals.com/files/Procdump.zip -o Procdump.zip
    Expand-Archive .\Procdump.zip
    wget $StrategyModulePath -o StrategyModule.psm1
    ipmo .\VFP.psm1
    ipmo .\HNS.psm1
    ipmo .\StrategyModule.psm1

    Start-HNSTrace
    $consecutiveFailures = 0

    StartHandler

    LogMessage "Started Monitoring"

    while($true)
    {    
        if(IsNodeFaulted)
        {
            $consecutiveFailures++
            # Number of consecutive failures to confirm that the Windows node is faulted for real
            # and this is not an intermittent failure          
            if ($consecutiveFailures -ge $FailureThreshold)
            {
                Stop-HNSTrace

                popd

                TerminateHandler($outDir)

                LogMessage "Diagnostic logs are available at $outDir"
                return
            }
        }
        else
        {
            $consecutiveFailures = 0
        }

        # Adjust the sleep time to lower the polling frequency 
        Start-Sleep -Seconds $PollingInterval
    }
}

##### Start execution #########

Start-Monitoring -StrategyModulePath $StrategyModulePath