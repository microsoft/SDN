#Requires -RunAsAdministrator

Param(
    [parameter(Mandatory = $false)] [string] $NetworkName = "azure",
    [parameter(Mandatory = $false)] [string] $ServiceIP = "20.124.54.159",
    [parameter(Mandatory = $false)] [string] $ServicePort = "5555"
)


class LoadBalancerPolicyData {
    [string] $Id
    [bool] $IsDsr
    [bool] $IsVfpHairpinRulePlumbed
}

$networkId = (Get-HnsNetwork -Detailed | Where-Object Name -eq $networkName).Id
$network = Get-HnsNetwork -Id $networkId -Detailed

$hostVfpPort = ($network | ForEach-Object { $_.Layer.Resources.Allocators } | Where-Object Tag -eq "Host Vnic").EndpointPortGuid     


[LoadBalancerPolicyData] $loadBalancerPolicy = [LoadBalancerPolicyData]::new()
$loadBalancerPolicy.IsVfpHairpinRulePlumbed = $false
$loadBalancerPolicy.Id = ""
while ($true) {

    $hnsPolicyList = Get-HnsPolicyList
    foreach ($policy in $hnsPolicyList) {
        $vip = ""
        if ($policy.Policies.LocalRoutedVip) {
            $vip = $network.ManagementIP
        }
        else {
            $vip = $policy.Policies.VIPs
        }

        if (($vip -eq $ServiceIP) -and ($ServicePort -eq $policy.Policies.ExternalPort)) {
            $loadBalancerPolicy.Id = $policy.ID
            $loadBalancerPolicy.IsDsr = $policy.Policies.IsDSR
        }
    }

    if ($loadBalancerPolicy.Id -eq "") {
        Write-Host (Get-Date).ToString() + "HNS Load balancer policy missing for the service"
    }

    $hairPinRulePattern = $ServiceIP + "_" + $ServicePort
    $hairpinRuleCount = (vfpctrl.exe /port $hostVfpPort /layer SLB_HAIRPIN_LAYER /list-rule | Select-String -Pattern $hairPinRulePattern).Count
    $loadBalancerPolicy.IsVfpHairpinRulePlumbed = ($hairpinRuleCount -gt 0)

    if ($loadBalancerPolicy.IsVfpHairpinRulePlumbed -eq $false) {
        Write-Host (Get-Date).ToString() + " Hairpin rule missing for the Service"
    }

    Start-Sleep -Milliseconds 500
}







