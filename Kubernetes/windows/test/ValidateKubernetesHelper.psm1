function GetContainers
{
    param(
        [ValidateSet("Local", "Remote")][string] $PodLocation,
        $DeploymentName
    )

    $hostname = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty name
    $containers = @()

    foreach ($pods in (kubectl get pods -o name | findstr $DeploymentName))
    {
        $c = ((kubectl get $pods -o json ) | ConvertFrom-Json)
        $container = @{
            Name = $c.metadata.name;
            Service = $c.metadata.labels.app;
            IPAddress = $c.status.podIP;
            HostName = $c.spec.nodeName;
            HostIP = $c.status.hostIP;
            Status = $c.status.phase
        }
        if ($PodLocation -ieq "Local") {
            if (!($container.HostName -ieq $hostname)) {
                continue
            }
        }
        if ($PodLocation -ieq "Remote") {
            if ($container.HostName -ieq $hostname) {
                continue
            }
        }
        Write-Verbose "$($container | ConvertTo-Json)"
        $containers += $container
    }

    return $containers;
}

function TestConnectivity()
{
    param(
        [string] $containerName,
        [string] $remoteHost = "www.google.com",
        [string] $port = "80",
        [switch] $fromHost
    )
    if ($fromHost.IsPresent)
    {
        Write-Verbose "Source [LocalHost] => [${remoteHost}:${port}]"
    }
    else
    {
        Write-Verbose "Source Container[$ContainerName] => [${remoteHost}:${port}]"
    }
    if ($fromHost) {
        $status = curl "http://${remoteHost}:${port}" -UseBasicParsing -DisableKeepAlive
        if ($status.StatusCode -eq "200") {
            return
        }
        throw "TCP connection to ${remoteHost}:${port} failed from host. Result [$status]"
    } else {
        $status = kubectl exec $containerName -- powershell.exe curl "http://${remoteHost}:${port}" -UseBasicParsing -DisableKeepAlive
    }

    if ($status -match "200")
    {
        return
    }

    throw "TCP connection to ${remoteHost}:${port} failed from $containerName. Result [$status]"
}

function GetContainerIPv4Address()
{
    param(
        [string] $containerName
    )

    $matches = (kubectl exec $containerName ipconfig | Out-String  | Select-String -Pattern '(?sm)(IPv4 Address).*?: (.*?)\r\n' -AllMatches).Matches
    if ($matches -and $matches.Count -gt 0 -and $matches.Groups.Count -gt 0)
    {
        return ($matches.Groups | Select -Last 1).Value
    }
    return $null
}

function PingTest()
{
    param(
        [string] $containerName,
        [string] $destination,
        [switch] $fromHost
    )
    
    if ($fromHost) {
        $returnStr =  ping $destination -n 4
    } else {
        $returnStr =  kubectl exec $containerName -- ping $destination -n 4
    }

    if ($returnStr -match "\(0% loss\)")
    {     
        return
    }
    
    throw "PingTest failed on $containerName for destination $destination. Result [$returnStr]"
}

function WaitForManagementIp()
{
    param(
        [string] $network = "vxlan0"
    )
   

    for ($i=0;$i -lt 60;$i++)
    {
        $hnsnetwork = Get-HnsNetwork | ? Name -EQ $network
        if (($hnsnetwork -ne $null) -and 
            $hnsnetwork.ManagementIp -and 
            (Get-NetIPAddress $hnsnetwork.ManagementIP -ErrorAction SilentlyContinue)
            )
        {
            return $hnsnetwork.ManagementIp
        }
        sleep -Milliseconds 1000
    }

    throw "Host is not connected to internet"

}

function WaitForDeploymentCompletion($DeploymentName)
{
    $startTime = Get-Date
    $waitTimeSeconds = 60

    while ($true)
    {
        $timeElapsed = $(Get-Date) - $startTime
        if ($($timeElapsed).TotalSeconds -ge $waitTimeSeconds)
        {
            throw "Fail to deploy ($DeploymentName)] in $waitTimeSeconds seconds"
        }
        $out = (kubectl get deployment $DeploymentName -o json  |ConvertFrom-Json)
        if (!$out)
        {
            throw "Deployment $DeploymentName not found"
        }
        if ($out.status.availableReplicas -eq $out.status.replicas)
        {
            break;
        }

        Write-Host "Waiting for the deployment ($DeploymentName) to be complete. $($out.status)"
        Start-Sleep 5
    }


}

