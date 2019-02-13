function GetContainers
{
    param(
        [ValidateSet("Local", "Remote")][string] $PodLocation
    )

    $hostname = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty name

    $out = ((kubectl get pods -o json) | ConvertFrom-Json).items

    $containers = @()
    foreach ($c in $out)
    {
        $container = @{
            Name = $c.metadata.name;
            Service = $c.metadata.labels.app;
            IPAddress = $c.status.podIP;
            HostName = $c.spec.nodeName;
            HostIP = $c.status.hostIP;
            Status = $c.status.phase
        }

        #TODO: check for service name

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
        $containers += $container
    }

    return $containers;
}

function TestConnectivity()
{
    param(
        [string] $containerName,
        [string] $remoteHost =  "172.217.3.206", #google.com
        [string] $port = "80",
        [switch] $fromHost
    )
    if ($fromHost) {
        $status = curl ${remoteHost}:${port} -UseBasicParsing -DisableKeepAlive
        if ($status.StatusCode -eq "200") {
            return
        }
        throw "TCP connection to ${remoteHost}:${port} failed from host"
    } else {
        $status = kubectl exec $containerName -- powershell.exe curl ${remoteHost}:${port} -UseBasicParsing -DisableKeepAlive
    }

    if ($status -match "200")
    {
        return
    }

    throw "TCP connection to ${remoteHost}:${port} failed from $containerName."
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
    
    throw "PingTest failed on $containerName for destination $destination ."
}

function WaitForManagementIp()
{
    param(
        [string] $network = "vxlan0"
    )
   

    for ($i=0;$i -lt 360;$i++)
    {
        $hnsnetwork = Get-HnsNetwork -Verbose | ? Name -EQ $network
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


