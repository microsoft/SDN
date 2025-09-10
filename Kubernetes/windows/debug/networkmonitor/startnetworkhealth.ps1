
function WaitForDaemonsetToBeReady {
    param (
        [parameter(Mandatory = $true)] [string] $dsName
    )
    Write-Host "Checking status of daemonset $dsName ..."
    $i = 0
    $maxWait = 300

    while($i -le $maxWait)
    {
        $status = (kubectl get ds $dsName -o json | ConvertFrom-Json).status
        if($status.currentNumberScheduled -eq $status.desiredNumberScheduled)
        {
            Write-Host "Deamonset $dsName is ready ..."
            return $true
        }
        Write-Host "Deamonset $dsName is not yet ready. Scheduled Pods : $status.currentNumberScheduled , Desired Pods : $status.desiredNumberScheduled ..."
        Start-Sleep -Seconds 2
        $i++
    }

    Write-Host "Creating $dsName daemonset failed. Scheduled Pods : $status.currentNumberScheduled , Desired Pods : $status.desiredNumberScheduled . Exiting..."
    return $false
}

Write-Host "Deleting networkhealth daemonset if anything running..." 
kubectl delete -f .\networkhealthlocal.yaml
Write-Host "Creating hetworkhealth daemonset to run script..."
kubectl create -f .\networkhealthlocal.yaml
$nwHlthPodStatus = WaitForDaemonsetToBeReady("networkhealth")
if(!$nwHlthPodStatus) {
    return
}
Start-Sleep -Seconds 5
$nwHlthPods = kubectl get pods --no-headers -o custom-columns=":metadata.name" | findstr "networkhealth"
Write-Host "Networkhealth Pods : $nwHlthPods"
foreach($pod in $nwHlthPods) 
{ 
    Write-Host "Copying networkhealth script to hpc pod : $pod ..."
    kubectl cp .\networkhealth.ps1 $pod`:C:\k\debug\networkhealth.ps1
    Write-Host "Copying networkhealth script to hpc pod : $pod completed"
}
Write-Host "Creating networkhealth daemonset completed..."