param(
  [string]$ServiceTypeName,
  [switch]$AllReplicas
)

$a = Connect-WindowsFabricCluster -WarningAction "SilentlyContinue"
Write-Host ""

if([String]::IsNullOrEmpty($ServiceTypeName))
{
    $services = Get-WindowsFabricApplication fabric:/NetworkController | Get-WindowsFabricService
}
else
{
    $servicename = "fabric:/NetworkController/" + $ServiceTypeName
    $services = Get-WindowsFabricService "fabric:/NetworkController" -ServiceName $servicename
}

foreach ($service in $services) 
{
    Write-Host "Replicas for service:" $service.ServiceTypeName -ForeGroundColor Yellow
    $replicas = Get-WindowsFabricPartition $service.ServiceName | Get-WindowsFabricReplica 
    if ($AllReplicas -eq $false) { $replicas = $replicas | where {$_.ReplicaRole -eq "Primary"} } 
    $replicas | Select-Object ReplicaRole,NodeName,ReplicaStatus | fl 
}