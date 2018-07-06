function DownloadFile()
{
    param(
    [parameter(Mandatory = $true)] $Url,
    [parameter(Mandatory = $true)] $Destination
    )

    if (Test-Path $Destination)
    {
        Write-Host "File $Destination already exists."
        return
    }

    try {
        Start-BitsTransfer $Url -Destination $Destination
        Write-Host "Downloaded $Url=>$Destination"
    } catch {
        Write-Error "Failed to download $Url"
	throw
    }
}

function CleanupOldNetwork($NetworkName)
{
    $hnsNetwork = Get-HnsNetwork | ? Name -EQ $NetworkName.ToLower()

    if ($hnsNetwork)
    {
        # Cleanup all containers
        docker ps -q | foreach {docker rm $_ -f} 

        Write-Host "Cleaning up old HNS network found"
        Write-Host ($hnsNetwork | ConvertTo-Json -Depth 10) 
        Remove-HnsNetwork $hnsNetwork
    }
}

function WaitForNetwork($NetworkName)
{
    # Wait till the network is available
    while( !(Get-HnsNetwork -Verbose | ? Name -EQ $NetworkName.ToLower()) )
    {
        Write-Host "Waiting for the Network to be created"
        Start-Sleep 1
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


Export-ModuleMember DownloadFile
Export-ModuleMember CleanupOldNetwork
Export-ModuleMember IsNodeRegistered
Export-ModuleMember RegisterNode
Export-ModuleMember WaitForNetwork