#Requires -RunAsAdministrator

Param(
    [parameter(Mandatory = $false)] [string] $NetworkName = "azure",
    [parameter(Mandatory = $false)] [string] $ServiceEndpoint = "20.124.54.159:5555",
    [parameter(Mandatory = $false)] [string] $Verbosity = "Normal"
)

class Backend 
{
    [string] $IpAddress
    [string] $EndPointId
    [bool] $IsRemoteEndpoint
    [string] $VfpPortGuid
    [string] $InternalPort
}

class LoadBalancerPolicyData {
    [string] $Id
    [string] $NetworkId
    [int] $State
    [string] $Vip
    [int] $ExternalPort
    [int] $InternalPort
    [int] $Protocol
    [bool] $IsDsr
    [bool] $LocalRoutedVip
    [Backend[]] $Backends = @()
}

$networkId = (Get-HnsNetwork -Detailed | Where-Object Name -eq $networkName).Id
$network = Get-HnsNetwork -Id $networkId -Detailed

$hostVfpPort = ($network | ForEach-Object { $_.Layer.Resources.Allocators } | Where-Object Tag -eq "Host Vnic").EndpointPortGuid     
$externalVfpPort = ($network | ForEach-Object { $_.Layer.Resources.Allocators } | Where-Object Tag -eq "External Adapter Info").ExternalNicPortGuid

$endpointsToMonitor = @()
$backendsToMonitor = @()
$endpointsToMonitor += $ServiceEndpoint

[LoadBalancerPolicyData] $loadBalancerPolicy = [LoadBalancerPolicyData]::new()
$recomputePolicyData = $true
while ($true) {

    if ($recomputePolicyData) {

        $endpointsToMonitor = @()
        $backendsToMonitor = @()
        $endpointsToMonitor += $ServiceEndpoint

        $hnsPolicyList = Get-HnsPolicyList
        foreach ($policy in $hnsPolicyList) {
            $svcEndpoint = ""
            if ($policy.Policies.LocalRoutedVip) {
                $svcEndpoint += $network.ManagementIP
            }
            else {
                $svcEndpoint += $policy.Policies.VIPs
            }

            $svcEndpoint += ":" 
            $svcEndpoint += $policy.Policies.ExternalPort

            if ($svcEndpoint -eq $ServiceEndpoint) {

                $loadBalancerPolicy.Id = $policy.ID
                $loadBalancerPolicy.IsDsr = $policy.Policies.IsDSR
                $loadBalancerPolicy.ExternalPort = $policy.Policies.ExternalPort
                $loadBalancerPolicy.InternalPort = $policy.Policies.InternalPort

                if ($policy.Policies.LocalRoutedVip) {
                    $loadBalancerPolicy.Vip = $network.ManagementIP
                }
                else {
                    $loadBalancerPolicy.Vip = $policy.Policies.VIPs
                }

                foreach ($endpointReference in $policy.References) {
                    $endpointReferenceGuid = $endpointReference.Replace("/endpoints/", "")

                    $hnsEndpoint = Get-HnsEndpoint -Id $endpointReferenceGuid
                    [Backend] $newBackEnd = [Backend]::new()
                    $newBackEnd.IPAddress = $hnsEndpoint.IPAddress
                    $newBackEnd.EndPointId = $hnsEndpoint.Id
                    $newBackEnd.IsRemoteEndpoint = $hnsEndpoint.IsRemoteEndpoint -eq $true
                    $newBackEnd.VfpPortGuid = ($hnsEndpoint.Resources.Allocators | Where-Object Tag -eq "Endpoint Port").EndpointPortGuid
                    $newBackEnd.InternalPort = $policy.Policies.InternalPort
                    $loadBalancerPolicy.Backends += $newBackEnd
                }
            }
        }

        foreach ($lbBackend in $loadBalancerPolicy.Backends) { 
            $endpointsToMonitor += $lbBackend.IPAddress + ":" + $lbBackend.InternalPort
            if ($lbBackend.IsRemoteEndpoint -ne $true) {
                $backendsToMonitor += $lbBackend
            }
        }

        $recomputePolicyData = $false
    }

    if ($loadBalancerPolicy.Id -eq "") {
        Write-Host "HNS Load balancer policy for the provided service endpoint not available"
        continue
    }

    $searchPatternForFlows = @()
    if ($Verbosity -eq "Normal") {
        $searchPatternForFlows += $ServiceEndpoint
    }
    elseif ($Verbosity -eq "Verbose") {
        $searchPatternForFlows = $endpointsToMonitor
    }

    $hostVfpPortUnifiedFlows = vfpctrl.exe /port $hostVfpPort /sample-unified-flow "100000 0 1" | Out-String -Stream | Select-String -Pattern $searchPatternForFlows -Context 1, 4 
    $externalVfpPortUnifiedFlows = vfpctrl.exe /port $externalVfpPort /sample-unified-flow "100000 0 1" | Out-String -Stream | Select-String -Pattern $searchPatternForFlows -Context 1, 4
             
    foreach ($externalUnifiedFlow in $externalVfpPortUnifiedFlows) {
        $flowData = $externalUnifiedFlow.ToString() -replace "`r*`n*"
        $message = "{0} {1} {2} {3}" -f "External VFP Port", (Get-Date).ToString(), $(hostname), $flowData
        Write-Host $message
    }
        
    foreach ($hostUnifiedFlow in $hostVfpPortUnifiedFlows) {
        $flowData = $hostUnifiedFlow.ToString() -replace "`r*`n*"
        $message = "{0} {1} {2} {3}" -f "Host VFP Port", (Get-Date).ToString(), $(hostname), $flowData
        Write-Host $message
    }

    foreach ($backendToMonitor in $backendsToMonitor) {
        $containerPortUnifiedFlows = vfpctrl.exe /port $backendToMonitor.VfpPortGuid /sample-unified-flow "100000 0 1" | Out-String -Stream | Select-String -Pattern $searchPatternForFlows -Context 1, 4

        foreach ($containerPortUnifiedFlow in $containerPortUnifiedFlows) {
            $flowData = $containerPortUnifiedFlow.ToString() -replace "`r*`n*"
            $message = "{0}:{1} {2} {3} {4}" -f "POD VFP Port", $backendToMonitor.IpAddress, (Get-Date).ToString(), $(hostname), $flowData
            Write-Host $message
        }
    }

    Start-Sleep 10
    $lbPolicy = Get-HnsPolicyList | Where-Object Id -eq $loadBalancerPolicy.Id
    if($null -eq $lbPolicy)
    {
        $recomputePolicyData = $true
    }
}







