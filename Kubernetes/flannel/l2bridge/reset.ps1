C:\k\stop.ps1
docker stop $(docker ps -aq)
docker rm -f $(docker ps -aq)

Get-HNSEndpoint | Remove-HNSEndpoint
Get-HNSNetwork | ? Name -Like "cbr0" | Remove-HNSNetwork
Remove-Item -Recurse -Force C:\var
Remove-Item -Recurse -Force C:\usr
Remove-Item -Recurse -Force C:\run
Remove-Item -Recurse -Force C:\etc
Remove-Item -Recurse -Force C:\flannel