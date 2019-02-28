 
$BaseDir = "c:\k"

# Prepare POD infra Images
function tagImage
{
    if (!(docker images mcr.microsoft.com/windows/nanoserver:latest -q))
    {
        docker tag (docker images mcr.microsoft.com/windows/nanoserver -q) mcr.microsoft.com/windows/nanoserver
    }

    if (!(docker images mcr.microsoft.com/windows/servercore:latest -q))
    {
        docker tag (docker images mcr.microsoft.com/windows/servercore -q) mcr.microsoft.com/windows/servercore
    }
}

$infraPodImage=docker images kubeletwin/pause -q
if (!$infraPodImage)
{
    Write-Host "No infrastructure container image found. Building kubeletwin/pause image"
    tagImage
    pushd
    cd $BaseDir
    docker build -t kubeletwin/pause .
    popd
}

