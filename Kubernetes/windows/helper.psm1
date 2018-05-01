function DownloadFileOverHttps()
{
    param(
    [parameter(Mandatory = $true)] $Url,
    [parameter(Mandatory = $true)] $DestinationPath
    )

    if (Test-Path $DestinationPath)
    {
        Write-Host "File $DestinationPath already exists."
        return
    }

    $secureProtocols = @()
    $insecureProtocols = @([System.Net.SecurityProtocolType]::SystemDefault, [System.Net.SecurityProtocolType]::Ssl3)

    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType]))
    {
        if ($insecureProtocols -notcontains $protocol)
        {
            $secureProtocols += $protocol
        }
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

    try {
        curl $Url -UseBasicParsing -OutFile $DestinationPath -Verbose
        Write-Log "Downloaded $Url=>$DestinationPath"
    } catch {
        Write-Error "Failed to download $Url"
    }
}

function CleanupOldNetwork($NetworkMode)
{
    $hnsNetwork = Get-HnsNetwork | ? Type -EQ $NetworkMode.ToLower()

    if ($hnsNetwork)
    {
        # Cleanup all containers
        docker ps -q | foreach {docker rm $_ -f} 

        Write-Host "Cleaning up old HNS network found"
        Write-Host ($hnsNetwork | ConvertTo-Json -Depth 10) 
        Remove-HnsNetwork $hnsNetwork
    }
    # Wait for the interface to come back with IP
    Start-Sleep 10
}

function WaitForNetwork($NetworkMode)
{
    # Wait till the network is available
    while( !(Get-HnsNetwork -Verbose | ? Type -EQ $NetworkMode.ToLower()) )
    {
        Write-Host "Waiting for the Network to be created"
        Start-Sleep 10
    }
}

function
IsNodeRegistered()
{
    c:\k\kubectl.exe --kubeconfig=c:\k\config get nodes/$($(hostname).ToLower())
    return (!$LASTEXITCODE)
}

function
RegisterNode()
{
    if (!(IsNodeRegistered))
    {
        $argList = @("--hostname-override=$(hostname)","--pod-infra-container-image=kubeletwin/pause","--resolv-conf=""""", "--kubeconfig=c:\k\config")
        $process = Start-Process -FilePath c:\k\kubelet.exe -PassThru -ArgumentList $argList

        # Wait till the 
        while (!(IsNodeRegistered))
        {
            Write-Host "waiting to discover node registration status"
            Start-Sleep -sec 1
        }

        $process | Stop-Process | Out-Null
    }
}


Export-ModuleMember DownloadFileOverHttps
Export-ModuleMember CleanupOldNetwork
Export-ModuleMember IsNodeRegistered
Export-ModuleMember RegisterNode
Export-ModuleMember WaitForNetwork