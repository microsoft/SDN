$BaseDir = "c:\k"
ipmo $BaseDir\hns.psm1
$Network = "L2Bridge"

$ScriptPath = Split-Path $MyInvocation.MyCommand.Path

Get-hnsnetwork | Convertto-json -Depth 20 > network.txt
Get-hnsendpoint | Convertto-json -Depth 20 > endpoint.txt
Get-hnspolicylist | Convertto-json -Depth 20 > policy.txt

vfpctrl.exe /list-vmswitch-port > ports.txt
$ScriptPath\dumpVfpPolicies.ps1 -switchName $Network > vfpOutput.txt

ipconfig /all > ip.txt
route print > routes.txt
