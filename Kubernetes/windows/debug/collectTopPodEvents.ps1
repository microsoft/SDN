$logFile = "topPodEvents.log"
$iMax = 360 # 6 hours

"" > $logFile

function logInfo() {
    Write-Output "============ Logging top Pods" >> $logFile
    kubectl top pods -A >> $logFile
    " " >> $logFile
    Write-Output "============ Logging top Nodes" >> $logFile
    kubectl top nodes >> $logFile
    " " >> $logFile
    Write-Output "============ Logging events" >> $logFile
    kubectl get events -A >> $logFile
    " " >> $logFile
    $nodes = (((kubectl get nodes -o json | ConvertFrom-Json).Items).metadata).name
    $nodes = ((kubectl get nodes -o json | ConvertFrom-Json).Items)
    Write-Output "============ Logging node info" >> $logFile
    foreach($node in $nodes) {
        if((($node.status).nodeInfo).operatingSystem -eq "windows") {
            $nodeName = ($node.metadata).name
            kubectl describe node $nodeName >> $logFile
            " " >> $logFile
        }
    }
    " " >> $logFile
}

for ($i = 1; $i -le $iMax; $i++) {
    $now = Get-Date
    Write-Output "$now : ============ Iteration : $i "
    Write-Output "$now : ============ Iteration : $i " >> $logFile
    logInfo
    Start-Sleep -Seconds 60
}