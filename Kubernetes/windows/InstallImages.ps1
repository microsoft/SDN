 
$BaseDir = "c:\k"

# Prepare POD infra Images

if (!(docker images microsoft/nanoserver:latest -q))
{
    docker tag (docker images microsoft/nanoserver -q) microsoft/nanoserver
}

if (!(docker images microsoft/windowsservercore:latest -q))
{
    docker tag (docker images microsoft/windowsservercore -q) microsoft/windowsservercore
}

$infraPodImage=docker images kubeletwin/pause -q
if (!$infraPodImage)
{
    pushd
    cd $BaseDir
    docker build -t kubeletwin/pause .
    popd
}

