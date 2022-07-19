#################### CORE LOGIC ##################################
enum TestStatus {
    <# Specify a list of distinct values #>
    Inconclusive = 0
    Skipped = 1
    Passed = 2
    Failed = 3
}

#Base class that implements a diagnostic test
class DiagnosticTest
{
    [string]$RootCause = "Cause is not known"
    [string]$Resolution = "Resolution is not known"
    [TestStatus]$Status = [TestStatus]::Inconclusive

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider)
    {
        return $this.Status
    }

    [TestStatus]GetTestStatus()
    {   
        return $this.Status
    }

    [string]GetTestDescription()
    {
        return $this.GetType().FullName
    }

    [string]GetRootCause()
    {
        return $this.RootCause
    }

    [string]GetResolution()
    {   
        return $this.Resolution
    }
}


class DiagnosticDataProvider
{
    [PSCustomObject[]]GetEndpointData()
    {
        return @()
    }

    [PSCustomObject[]]GetNetworkData()
    {
        return @()
    }

    [PSCustomObject]GetHostData()
    {
        return @()
    }
}

class NetworkTroubleshooter {
    hidden [DiagnosticTest[]] $DiagnosticTests = @()
    hidden [DiagnosticDataProvider] $DiagnosticDataProvider

    NetworkTroubleshooter([DiagnosticDataProvider] $DiagnosticDataProvider)
    {
        $this.DiagnosticDataProvider = $DiagnosticDataProvider
    }

    [void] RegisterDiagnosticTest([DiagnosticTest]$diagnosticTest) {
        $this.DiagnosticTests += $diagnosticTest
    }

    [void] RunDiagnosticTests() {
        foreach($diagnosticTest in $this.DiagnosticTests)
        {
            $diagnosticTest.Run($this.DiagnosticDataProvider)
        }
    }

    [void] PrepareReport() {
        
        $report = @()
        foreach($diagnosticTest in $this.DiagnosticTests)
        {
            $testDescription = $diagnosticTest.GetTestDescription()
            $rootCause = $diagnosticTest.GetRootCause()
            $resolution = $diagnosticTest.GetResolution()
            $status = $diagnosticTest.GetTestStatus()
            $testReport = @{
                Description = $testDescription
                Status = $status
                RootCause = $rootCause
                Resolution = $resolution
            }

            $report += [PSCustomObject]$testReport
        }


        $Header = @"
            <style>
            TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
            TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
            TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
            </style>
"@

        $report | ConvertTo-Html -Head $Header | Out-File Report.html
    }
}

###################### Diagnostics Data Providers Implementation #######################

class RuleData
{
}

class DynamicNatRuleData : RuleData
{
    [string]$Type
    [string]$NatPool
}

class LbNatRuleData : RuleData
{
    [string[]]$DipRanges = @()
}

class VfpCondition
{
    [string] $Protocols
    [string] $SourceIP
    [string] $SourcePorts   
    [string] $DestinationIP
    [string] $DestinationPorts
}

class VfpRule
{
    [string]$Name
    [string]$Type
    [VfpCondition]$Condition
    [RuleData]$RuleData
}

class VfpGroup
{
    [string]$Name
    [string]$Direction
    [string]$Type
    [VfpRule[]]$Rules = @()
}

class VfpLayer
{
    [string]$Name
    [VfpGroup[]]$Groups = @()
}

class VfpPort
{
    [string] $Identifier
    [string] $PortState
    [VfpLayer[]] $Layers = @()
}

class NeighborCache
{

}

class EndpointData 
{
    [string] $Identifier
    [string] $IPAddress
    [string] $MacAddress
    [int] $EndpointState
    [int] $CompartmentId
    [int] $InterfaceId
    [hashtable] $NeighborCache = @{}
    [VfpPort] $VfpPort
}

class FakeDiagnosticDataProvider : DiagnosticDataProvider {


    [EndpointData[]]GetEndpointData() {

        $returnValue = @()

        $endpointData = [EndpointData]::new()
        $endpointData.Identifier = "CDE845C4-D117-497D-8956-4032FDEF704E"      
        $endpointData.IpAddress     = "10.0.0.10"
        $endpointData.MacAddress    = "12-34-56-78-9A"
        $endpointData.EndpointState = 3
        $endpointData.CompartmentId = 1
        $endpointData.InterfaceId   = 10

        $endpointData.NeighborCache["10.0.0.1"] = "12-34-56-78-9A"

        $endpointData.VfpPort = [VfpPort]::new()
        $endpointData.VfpPort.Identifier = "53020B6A-651A-46C8-B089-C825BEC0F1A9"
        $endpointData.VfpPort.PortState = "Unblocked" 

        $slbNatLayer = [VfpLayer]::new()
        $slbNatLayer.Name = "SLB_NAT_LAYER"

        $slbNatLayerOutGroup = [VfpGroup]::new()
        $slbNatLayerOutGroup.Name = "SLB_GROUP_NAT_IPv4_OUT"
        $slbNatLayerOutGroup.Type = "IPv4"
        $slbNatLayerOutGroup.Direction = "Out"

        $slbNatRule = [VfpRule]::new()
        $slbNatRule.Name = "SNAT_TCP_OUTBOUNDNAT_54194_10.180.160.134"
        $slbNatRule.Type = "dynnat"

        $slbNatRuleCondition = [VfpCondition]::new()
        $slbNatRuleCondition.Protocols = "6"
        $slbNatRuleCondition.SourceIP = "10.180.160.150"
        $slbNatRule.Condition = $slbNatRuleCondition

        $slbNatRuleData = [DynamicNatRuleData]::new()
        $slbNatRuleData.NatPool = "SLB_NATPOOL_IPV4_TCP_10.180.160.15010.180.160.1341F56A817-CD01-4A9E-9400-061317372B8F0"
        $slbNatRuleData.Type = "Source_Nat"
        $slbNatRule.RuleData = $slbNatRuleData

        $slbNatLayerOutGroup.Rules += $slbNatRule

        $slbNatLayer.Groups += $slbNatLayerOutGroup

        $endpointData.VfpPort.Layers += $slbNatLayer

        $returnValue += $endpointData

        return $returnValue
    }

    [PSCustomObject[]]GetNetworkData() {
        return @()
    }

    [PSCustomObject]GetHostData() {
        return @()
    }
}

class AKSNodeDiagnosticDataProvider : DiagnosticDataProvider {
    [EndpointData[]]GetEndpointData() {
        $returnValue = @()
        $hnsEndpoints = Get-HnsEndpoint

        foreach ($endpoint in $hnsEndpoints)
        {
            $endpointData = [EndpointData]::new()
            $endpointData.Identifier = $endpoint.ID     
            $endpointData.IpAddress     = $endpoint.IPAddress
            $endpointData.MacAddress    = $endpoint.MacAddress
            $endpointData.EndpointState = $endpoint.State

            $endpointPortResource = $endpoint.Resources.Allocators | Where-Object Tag -eq "Endpoint Port"

            $endpointData.VfpPort = [VfpPort]::new()
            if ($endpointPortResource)
            {
                $endpointData.CompartmentId = $endpointPortResource.CompartmentId
                $endpointData.VfpPort.Identifier = $endpointPortResource.EndpointPortGuid
            }

            if ((vfpctrl.exe /port $endpointData.VfpPort.Identifier /get-port-state | Out-String) -match "Blocked : FALSE")
            {
                $endpointData.VfpPort.PortState = "Unblocked"
            }

            $layerNames = @((vfpctrl.exe /port $endpointData.VfpPort.Identifier  /list-layer | Out-String -Stream | Select-String -Pattern "LAYER :") -replace "LAYER :")
            
            foreach($layer in $layerNames)
            {
                $vfpLayer = [VfpLayer]::new()
                $vfpLayer.Name = $layer.Trim()

                $groupNames = @((vfpctrl.exe /port $endpointData.VfpPort.Identifier /layer $vfpLayer.Name /list-group | Out-String -Stream | Select-String -Pattern "GROUP :") -replace "GROUP :")
                $groupTypes = @((vfpctrl.exe /port $endpointData.VfpPort.Identifier /layer $vfpLayer.Name /list-group | Out-String -Stream | Select-String -Pattern "Type :" -CaseSensitive) -replace "Type :")
                $groupDirections = @((vfpctrl.exe /port $endpointData.VfpPort.Identifier /layer $vfpLayer.Name /list-group | Out-String -Stream | Select-String -Pattern "Direction :") -replace "Direction :")
                for($group_num = 0; $group_num -lt $groupNames.Length; $group_num++)
                {
                    $vfpGroup = [VfpGroup]::new()
                    $vfpGroup.Name = $groupNames[$group_num].Trim()
                    $vfpGroup.Type = $groupTypes[$group_num].Trim()
                    $vfpGroup.Direction = $groupDirections[$group_num].Trim()
                    
                    # Add , at beginning to always convert the output to array even for single element
                    $ruleFriendlyNames = @((vfpctrl.exe /port $endpointData.VfpPort.Identifier /layer $vfpLayer.Name /group $vfpGroup.Name /list-rule | Out-String -Stream | Select-String -Pattern "Friendly name :") -replace "Friendly name :")
                    $ruleTypes = @((vfpctrl.exe /port $endpointData.VfpPort.Identifier /layer $vfpLayer.Name /group $vfpGroup.Name /list-rule | Out-String -Stream | Select-String -Pattern "Type :" -CaseSensitive) -replace "Type :")
                    
                    for($rule_num = 0; $rule_num -lt $ruleFriendlyNames.Length; $rule_num++)
                    {
                        $vfpRule = [VfpRule]::new()
                        $vfpRule.Name = $ruleFriendlyNames[$rule_num].Trim()
                        $vfpRule.Type = $ruleTypes[$rule_num].Trim()

                        $vfpGroup.Rules += $vfpRule
                    }

                    $vfpLayer.Groups += $vfpGroup
                }

                $endpointData.VfpPort.Layers += $vfpLayer
            }

            $returnValue += $endpointData
        }

        return $returnValue
    }
}

######################## Diagnostic Tests #######################################

class EndpointStateTest : DiagnosticTest
{
    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider)
    {
        [EndpointData[]] $endpoints = $DiagnosticDataProvider.GetEndpointData()

        $this.Status = [TestStatus]::Passed
        foreach ($endpoint in $endpoints)
        {
            [EndpointData] $endpointData = $endpoint
            if ($endpointData.EndpointState -ne 3)
            {
                $this.Status = [TestStatus]::Failed
                $this.RootCause = "Endpoint state in not valid : " + $endpointData.EndpointState.ToString()
                $this.Resolution = "Delete and recreate the POD"
            }
        }
        return $this.Status
    }

    [string]GetRootCause()
    {
        return $this.RootCause
    }

    [string]GetResolution()
    {   
        return $this.Resolution
    }
}

class EndpointVfpPortStateTest : DiagnosticTest
{
    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider)
    {
        [EndpointData[]] $endpoints = $DiagnosticDataProvider.GetEndpointData()

        $this.Status = [TestStatus]::Passed
        foreach ($endpoint in $endpoints)
        {
            [EndpointData] $endpointData = $endpoint
            if ($endpointData.VfpPort.PortState -ne "Blocked")
            {
                $this.Status = [TestStatus]::Failed
                $this.RootCause = "Endpoint vfp port state in not valid : " + $endpointData.VfpPort.PortState.ToString()
                $this.Resolution = "Delete and recreate the POD"
            }
        }
        return $this.Status
    }

    [string]GetRootCause()
    {
        return $this.RootCause
    }

    [string]GetResolution()
    {   
        return $this.Resolution
    }
}



####################### Main ###########################################



#$networkTroubleshooter = [NetworkTroubleshooter]::new([FakeDiagnosticDataProvider]::new())
$networkTroubleshooter = [NetworkTroubleshooter]::new([AKSNodeDiagnosticDataProvider]::new())

$networkTroubleshooter.RegisterDiagnosticTest([EndpointStateTest]::new())
$networkTroubleshooter.RegisterDiagnosticTest([EndpointVfpPortStateTest]::new())

$networkTroubleshooter.RunDiagnosticTests()
$networkTroubleshooter.PrepareReport()