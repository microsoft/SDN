
$BaseDir = "c:\k"

# Prepare POD infra Images

$image=docker images microsoft/nanoserver -q
docker tag $image microsoft/nanoserver
$image=docker images microsoft/windowsservercore -q
docker tag $image microsoft/windowsservercore

$infraPodImage=docker images kubletwin/pause -q
if (!$infraPodImage)
{
    pushd
    cd $BaseDir
    docker build -t kubeletwin/pause .
    popd
}

