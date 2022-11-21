#Requires -RunAsAdministrator

Param(
    [parameter(Mandatory = $false)] [switch] $CollectLogs,
    [parameter(Mandatory = $false)] [switch] $Replay,
    [parameter(Mandatory = $false)] [string] $NetworkName = "azure",
    [parameter(Mandatory = $false)] [ValidateSet("Event","Html","Stdout","All")] [string] $OutputMode = "event"
)

#################### CORE LOGIC ##################################
enum Mode {
    <# Specify a list of distinct values #>
    EventOnly = 0 # "Event"
    HtmlOnly = 1 # "Html"
    StdOut = 2 # 'Errors"
    All = 3 # "All"
}
enum TestStatus {
    <# Specify a list of distinct values #>
    Inconclusive = 0
    Skipped = 1
    Passed = 2
    Failed = 3
}

# Globals
set-variable -name MODE -value ([Mode]$OutputMode) -Scope Global

if ($MODE -ne [Mode]::HtmlOnly ) {
    set-variable -name EVENT_SOURCE_NAME -value ([string]"NetworkHealth") -Scope Global
    set-variable -name LOG_NAME -value ([string]"Application") -Scope Global
    set-variable -name EVENT_ID_INFORMATION -value ([int]0) -Scope Global
    set-variable -name EVENT_ID_WARNING -value ([int]1) -Scope Global
}


#Base class that implements a diagnostic test
class DiagnosticTest {
    [string]$RootCause = "n/a"
    [string]$Resolution = "n/a"
    [TestStatus]$Status = [TestStatus]::Inconclusive

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        return $this.Status
    }

    [TestStatus]GetTestStatus() {   
        return $this.Status
    }

    [string]GetTestDescription() {
        return $this.GetType().FullName
    }

    [string]GetRootCause() {
        return $this.RootCause
    }

    [string]GetResolution() {   
        return $this.Resolution
    }
}


class DiagnosticDataProvider {
    [PSCustomObject[]]GetEndpointData() {
        return @()
    }

    [PSCustomObject[]]GetNetworkData() {
        return @()
    }

    [PSCustomObject]GetNodeData() {
        return @()
    }

    [PSCustomObject]GetLoadBalancerPolicyData() {
        return @()
    }
}

class NetworkTroubleshooter {
    hidden [DiagnosticTest[]] $DiagnosticTests = @()
    hidden [DiagnosticDataProvider] $DiagnosticDataProvider
    # Set to false if any tests failed
    hidden [TestStatus]$NetworkStatus = [TestStatus]::Inconclusive
    # Stores test description
    hidden $ValidateSet = @()
    # Stores test failures
    hidden $FailureSet = @()

    NetworkTroubleshooter([DiagnosticDataProvider] $DiagnosticDataProvider) {
        $this.DiagnosticDataProvider = $DiagnosticDataProvider
        # Register event log provider, if it does not exist
        if (([System.Diagnostics.EventLog]::SourceExists($Global:EVENT_SOURCE_NAME) -eq $False) -and ($Global:MODE -ne [Mode]::HtmlOnly)) {
            New-EventLog -LogName $Global:LOG_NAME -Source $Global:EVENT_SOURCE_NAME
        }
    }

    [void] RegisterDiagnosticTest([DiagnosticTest]$diagnosticTest) {
        $this.DiagnosticTests += $diagnosticTest
    }
    [TestStatus] GetNetworkStatus() {
        return $this.NetworkStatus
    }

    [void] RunDiagnosticTests() {
        foreach ($diagnosticTest in $this.DiagnosticTests) {
            $diagnosticTest.Run($this.DiagnosticDataProvider)
            $testDescription = $diagnosticTest.GetTestDescription()
            $rootCause = $diagnosticTest.GetRootCause()
            $resolution = $diagnosticTest.GetResolution()
            $status = $diagnosticTest.GetTestStatus()

            if ($status -eq [TestStatus]::Failed) {
                $this.NetworkStatus = [TestStatus]::Failed
                $testReport = @{
                    Problem    = $rootCause
                    Resolution = $resolution
                }
                $this.FailureSet += [PSCustomObject]$testReport
            }
            else {
                $test = @{
                    Test        = $testDescription
                    Status      = $status
                    Comments    = $rootCause
                }

                $this.ValidateSet += [PSCustomObject]$test
            }
        }

        if ($this.NetworkStatus -ne [TestStatus]::Failed){
            # No tests failed
            $this.NetworkStatus = [TestStatus]::Passed
        }
    }

    [void] GenerateEvent() {
        # Gather HNS data
        $localEndpointCount = ($this.DiagnosticDataProvider.GetEndpointData() | Where-Object IsRemoteEndpoint -ne $true).Count
        $remoteEndpointCount = ($this.DiagnosticDataProvider.GetEndpointData() | Where-Object IsRemoteEndpoint -eq $true).Count
        $networkCount = $this.DiagnosticDataProvider.GetNetworkData().Count
        $lbCount = $this.DiagnosticDataProvider.GetLoadBalancerPolicyData().Count
        $hnsData = $this.DiagnosticDataProvider.GetNodeData() | Select-Object @{label="HnsThreadCount";expression={$_.HNSData.ThreadInfo.Count}}, @{label="HnsMemoryUsageMB";expression={$_.HNSData.MemoryUsage}}

        # Gather TCP/IP data
        $portData = $this.DiagnosticDataProvider.GetNodeData() | Select-Object AvailableTCPDynamicPortRanges, AvailableUDPDynamicPortRanges
        
        # Generate map summarizing network health information  
        $healthSummary = [ordered]@{}
        $healthSummary.Add("NetworkState", $this.NetworkStatus)
        $healthSummary.Add("Node", $(hostname))
        $healthSummary.Add("DynamicPorts", $portData)
        $hnsSummary =  [ordered]@{}
        $hnsCounts = [ordered]@{"LocalEndpointsCount"=$localEndpointCount;"RemoteEndpointsCount"=$remoteEndpointCount;"LoadBalancersCount"=$lbCount;"NetworksCount"=$networkCount;}
        $hnsSummary.Add("Resources", $hnsCounts)
        $hnsSummary.Add("HnsThreadCount", $hnsData.HnsThreadCount)
        $hnsSummary.Add("HnsMemoryUsageMB", $hnsData.HnsMemoryUsageMB)
        $healthSummary.Add("HNS",$hnsSummary)

        # Add failures and validations, if the tests failed
        if ($this.NetworkStatus -eq [TestStatus]::Failed) {
            $problemsDetected = $this.FailureSet | Select-Object Problem, Resolution
            $issuesChecked = $this.ValidateSet | Select-Object Test, Status, Comments
            $healthSummary.Add("TestSet", $issuesChecked)
            $healthSummary.Add("Failures", $problemsDetected)
        }
        # Create event message, write to host and event log
        $eventMessage = ($healthSummary | ConvertTo-Json -Depth 10)
        Write-Host ($eventMessage)

        if ($this.NetworkStatus -eq [TestStatus]::Failed){
            Write-EventLog -LogName $Global:LOG_NAME -Source $Global:EVENT_SOURCE_NAME -EntryType "Warning" -EventID $Global:EVENT_ID_WARNING -Message $eventMessage
        } else{
            Write-EventLog -LogName $Global:LOG_NAME -Source $Global:EVENT_SOURCE_NAME -EntryType "Information" -EventID $Global:EVENT_ID_INFORMATION -Message $eventMessage
        }
     }

    [void] GenerateHtml() {
        $heading = "<h1> Troubleshooting report for node: $env:computername</h1>"
        $Header = @"
            <style>
            TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
            TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
            TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
            </style>
"@

        $endpointData = $this.DiagnosticDataProvider.GetEndpointData() | Where-Object IsRemoteEndpoint -ne $true | Select-Object Identifier, IPAddress, MacAddress, EndpointState, CompartmentId  | ConvertTo-Html -Fragment -PreContent "<h2 style='color: blue'>Local Endpoint Information</h2>"
        $remoteEndpointData = $this.DiagnosticDataProvider.GetEndpointData() | Where-Object IsRemoteEndpoint -eq $true |  Select-Object Identifier, IPAddress, MacAddress, EndpointState | ConvertTo-Html -Fragment -PreContent "<h2 style='color: blue'>Remote Endpoint Information</h2>"
        $networkData = $this.DiagnosticDataProvider.GetNetworkData() | Select-Object Name, Identifier, ManagementIpAddress, ClusterCidr, ServiceCidr, DnsIp | ConvertTo-Html -Fragment -PreContent "<h2 style='color: blue'>Network Information</h2>"
        $lbData = $this.DiagnosticDataProvider.GetLoadBalancerPolicyData() | Select-Object Identifier, NetworkId, State, VIP, ExternalPort, InternalPort, Protocol, IsDSR, @{label="BackendIpAddresses";expression={$_.EndpointIpAddresses -join ", "}}, ServiceType | ConvertTo-Html -Fragment -PreContent "<h2 style='color: blue'>Load Balancer Policy Information</h2>"
        $nodeData = $this.DiagnosticDataProvider.GetNodeData() | Select-Object AvailableTCPDynamicPortRanges, AvailableUDPDynamicPortRanges, @{label="HNS Thread Count";expression={$_.HNSData.ThreadInfo.Count}}, @{label="HNS Memory Usage(MB)";expression={$_.HNSData.MemoryUsage}}| ConvertTo-Html -Fragment -PreContent "<h2 style='color: blue'>Node Information</h2>"

        $problemsDetectedHtml = $this.FailureSet | Select-Object Problem, Resolution | ConvertTo-Html -Fragment -PreContent "<h2 style='color: red'>Problems Detected</h2>"
        $issuesCheckedHtml = $this.ValidateSet | Select-Object Test, Status, Comments | ConvertTo-Html -Fragment -PreContent "<h2 style='color: green';>Potential Issues Checked</h2>"
       
        ConvertTo-Html -Body "$heading $problemsDetectedHtml $issuesCheckedHtml $endpointData $remoteEndpointData $networkData $lbData $nodeData" -Head $Header | Out-File TroubleshootingReport.html
    }
    
    [void] LogErrors() {
        
        if ($this.NetworkStatus -eq [TestStatus]::Failed) {
            foreach($problems in $this.FailureSet)
            {
                $message = "{0} {1} {2}" -f (Get-Date).ToString(),$(hostname), $problems.Problem
                Write-Host $message
            }
        }
    }
}

###################### Diagnostics Data Providers Implementation #######################


##### EndpointData ###########
class RuleData {
}

class DynamicNatRuleData : RuleData {
    [string]$Type
    [string]$NatPool
}

class LbNatRuleData : RuleData {
    [string[]]$DipRanges = @()
}

class VfpCondition {
    [string] $Protocols
    [string] $SourceIP
    [string] $SourcePorts   
    [string] $DestinationIP
    [string] $DestinationPorts
}

class VfpRule {
    [string]$Name
    [string]$Type
    [VfpCondition]$Condition
    [RuleData]$RuleData
}

class VfpGroup {
    [string]$Name
    [string]$Direction
    [string]$Type
    [VfpRule[]]$Rules = @()
}

class VfpLayer {
    [string]$Name
    [VfpGroup[]]$Groups = @()
}

class VfpPort {
    [string] $Identifier
    [string] $PortState
    [VfpLayer[]] $Layers = @()
}

class EndpointData {
    [string] $Identifier
    [string] $IPAddress
    [string] $MacAddress
    [int] $EndpointState
    [bool] $IsRemoteEndpoint
    [int] $CompartmentId
    [hashtable] $NeighborCache = @{}
    [VfpPort] $VfpPort
}

##### Network Data ###########
class NetworkData {
    [string] $Name
    [string] $Identifier
    [string] $ManagementIpAddress
    [string] $ClusterCidr
    [string] $ServiceCidr
    [string] $DnsIp
    [VfpPort] $HostVfpPort
    [VfpPort] $ExternalVfpPort
}

###### Node Data ########

class ThreadInformation {
    [int] $ThreadId
    [string] $ThreadState
    [string] $WaitReason
}

class HNSData {
    [int] $ProcessId
    [int] $MemoryUsage #In MB
    [ThreadInformation[]] $ThreadInfo = @()
}

class NodeData {
    [HNSData] $HNSData
    [int] $AvailableTCPDynamicPortRanges
    [int] $AvailableUDPDynamicPortRanges
    [hashtable] $NeighborCache = @{}
}

############ LoadBalancerPolicyData #######
enum ServiceType {
    Unknown = 0
    Cluster = 1
    NodePort = 2
    LoadBalancer = 3
}

class LoadBalancerPolicyData {
    [string] $Identifier
    [string] $NetworkId
    [int] $State
    [string] $VIP
    [int] $ExternalPort
    [int] $InternalPort
    [int] $Protocol
    [bool] $IsDSR
    [bool] $LocalRoutedVip
    [string[]] $Endpoints = @()
    [string[]] $EndpointIpAddresses = @()
    [ServiceType] $ServiceType
}

class FakeDiagnosticDataProvider : DiagnosticDataProvider {

    [EndpointData[]]GetEndpointData() {
        [EndpointData[]]$returnValue = Get-Content endpointdata.json | ConvertFrom-Json
        return $returnValue
    }

    [NetworkData]GetNetworkData() {   
        [NetworkData]$returnValue = Get-Content networkdata.json | ConvertFrom-Json
        return $returnValue
    }

    [NodeData]GetNodeData() {
        [NodeData]$returnValue = Get-Content nodedata.json | ConvertFrom-Json
        return $returnValue
    }

    [LoadBalancerPolicyData[]] GetLoadBalancerPolicyData() {
        [LoadBalancerPolicyData[]]$returnValue = Get-Content loadbalancerdata.json | ConvertFrom-Json
        return $returnValue
    }
}

class AKSNodeDiagnosticDataProvider : DiagnosticDataProvider {
    hidden [EndpointData[]] $endpointsData = @()
    hidden [NetworkData] $networkData
    hidden [LoadBalancerPolicyData[]] $loadbalancerData = @()
    hidden [NodeData] $nodeData

    AKSNodeDiagnosticDataProvider([string] $networkName)
    {
        $this.PopulateNetworkData($networkName)
        $this.PopulateEndpointData()
        $this.PopulateLoadBalancerPolicyData()
        $this.PopulateNodeData()
    }

    [uint32] CountAvailableEphemeralPorts([string]$protocol = "TCP") {

        [uint32]$portRangeSize = 64
        # First, remove all the text bells and whistle (plain text, table headers, dashes, empty lines, ...) from netsh output 
        $tcpRanges = (netsh int ipv4 sh excludedportrange $protocol) -replace "[^0-9,\ ]", '' | ? { $_.trim() -ne "" }
     
        # Then, remove any extra space characters. Only capture the numbers representing the beginning and end of range
        $tcpRangesArray = $tcpRanges -replace "\s+(\d+)\s+(\d+)\s+", '$1,$2' | ConvertFrom-String -Delimiter ","
    
        # Extract the ephemeral ports ranges
        $EphemeralPortRange = (netsh int ipv4 sh dynamicportrange $protocol) -replace "[^0-9]", '' | ? { $_.trim() -ne "" }
        $EphemeralPortStart = [Convert]::ToUInt32($EphemeralPortRange[0])
        $EphemeralPortEnd = $EphemeralPortStart + [Convert]::ToUInt32($EphemeralPortRange[1]) - 1
    
        # Find the external interface
        $externalInterfaceIdx = (Get-NetRoute -DestinationPrefix "0.0.0.0/0")[0].InterfaceIndex
        $hostIP = (Get-NetIPConfiguration -ifIndex $externalInterfaceIdx).IPv4Address.IPAddress
    
        # Extract the used TCP ports from the external interface
        $usedTcpPorts = (Get-NetTCPConnection -LocalAddress $hostIP -ErrorAction Ignore).LocalPort
        $usedTcpPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_ } }
    
        # Extract the used TCP ports from the 0.0.0.0 interface
        $usedTcpGlobalPorts = (Get-NetTCPConnection -LocalAddress "0.0.0.0" -ErrorAction Ignore).LocalPort
        $usedTcpGlobalPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_ } }
        # Sort the list and remove duplicates
        $tcpRangesArray = ($tcpRangesArray | Sort-Object { $_.P1 } -Unique)
    
        $tcpRangesList = New-Object System.Collections.ArrayList($null)
        $tcpRangesList.AddRange($tcpRangesArray)
    
        # Remove overlapping ranges
        for ($i = $tcpRangesList.P1.Length - 2; $i -gt 0 ; $i--) { 
            if ($tcpRangesList[$i].P2 -gt $tcpRangesList[$i + 1].P1 ) { 
                $tcpRangesList.Remove($tcpRangesList[$i + 1])
                $i++
            } 
        }
    
        # Remove the non-ephemeral port reservations from the list
        $filteredTcpRangeArray = $tcpRangesList | ? { $_.P1 -ge $EphemeralPortStart }
        $filteredTcpRangeArray = $filteredTcpRangeArray | ? { $_.P2 -le $EphemeralPortEnd }
        
        if ($null -eq $filteredTcpRangeArray) {
            $freeRanges = @($EphemeralPortRange[1])
        }
        else {
            $freeRanges = @()
            # The first free range goes from $EphemeralPortStart to the beginning of the first reserved range
            $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[0].P1) - $EphemeralPortStart)
    
            for ($i = 1; $i -lt $filteredTcpRangeArray.length; $i++) {
                # Subsequent free ranges go from the end of the previous reserved range to the beginning of the current reserved range
                $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[$i].P1) - [Convert]::ToUInt32($filteredTcpRangeArray[$i - 1].P2) - 1)
            }
    
            # The last free range goes from the end of the last reserved range to $EphemeralPortEnd
            $freeRanges += ($EphemeralPortEnd - [Convert]::ToUInt32($filteredTcpRangeArray[$filteredTcpRangeArray.length - 1].P2))
        }
        
        # Count the number of available free ranges
        [uint32]$freeRangesCount = 0
        ($freeRanges | % { $freeRangesCount += [Math]::Floor($_ / $portRangeSize) } )
    
        return $freeRangesCount
    }
    
    PopulateVfpPortInformation([ref] $VfpPortReference) {
        [VfpPort]$vfpPort = $VfpPortReference.Value
        $layerNames = @((vfpctrl.exe /port $vfpPort.Identifier  /list-layer | Out-String -Stream | Select-String -Pattern "LAYER :") -replace "LAYER :")
            
        foreach ($layer in $layerNames) {
            $vfpLayer = [VfpLayer]::new()
            $vfpLayer.Name = $layer.Trim()
            
            $vfpList = vfpctrl.exe /port $vfpPort.Identifier /layer $vfpLayer.Name /list-group | Out-String -Stream
            $groupNames = @(($vfpList | Select-String -Pattern "GROUP :") -replace "GROUP :")
            $groupTypes = @(($vfpList | Select-String -Pattern "Type :" -CaseSensitive) -replace "Type :")
            $groupDirections = @(($vfpList | Select-String -Pattern "Direction :") -replace "Direction :")
            if ($null -eq $vfpList){
                Write-Host "Skipping vfp port population for $layer due to null value return"
                continue
            }
            for ($group_num = 0; $group_num -lt $groupNames.Length; $group_num++) {
                $vfpGroup = [VfpGroup]::new()
                $vfpGroup.Name = $groupNames[$group_num].Trim()
                $vfpGroup.Type = $groupTypes[$group_num].Trim()
                $vfpGroup.Direction = $groupDirections[$group_num].Trim()
                
                # Add , at beginning to always convert the output to array even for single element
                $vfpRules = vfpctrl.exe /port $vfpPort.Identifier /layer $vfpLayer.Name /group $vfpGroup.Name /list-rule | Out-String -Stream
                $ruleFriendlyNames = @(($vfpRules | Select-String -Pattern "Friendly name :") -replace "Friendly name :")
                $ruleTypes = @(($vfpRules | Select-String -Pattern "Type :" -CaseSensitive) -replace "Type :")
                
                for ($rule_num = 0; $rule_num -lt $ruleFriendlyNames.Length; $rule_num++) {
                    $vfpRule = [VfpRule]::new()
                    $vfpRule.Name = $ruleFriendlyNames[$rule_num].Trim()
                    $vfpRule.Type = $ruleTypes[$rule_num].Trim()

                    $vfpGroup.Rules += $vfpRule
                }

                $vfpLayer.Groups += $vfpGroup
            }

            $vfpPort.Layers += $vfpLayer
        }
    }

    PopulateEndpointData() {
        $hnsEndpoints = Get-HnsEndpoint

        foreach ($endpoint in $hnsEndpoints) {
            $endpointData = [EndpointData]::new()
            $endpointData.Identifier = $endpoint.ID     
            $endpointData.IpAddress = $endpoint.IPAddress
            $endpointData.MacAddress = $endpoint.MacAddress
            $endpointData.EndpointState = $endpoint.State
            $endpointData.IsRemoteEndpoint = ($endpoint.IsRemoteEndpoint -eq $true)

            if ($endpointData.IsRemoteEndpoint -ne $true) {
                $endpointPortResource = $endpoint.Resources.Allocators | Where-Object Tag -eq "Endpoint Port"

                $endpointData.VfpPort = [VfpPort]::new()
                if ($endpointPortResource) {
                    $endpointData.CompartmentId = $endpointPortResource.CompartmendId
                    $endpointData.VfpPort.Identifier = $endpointPortResource.EndpointPortGuid
                }
    
                if ((vfpctrl.exe /port $endpointData.VfpPort.Identifier /get-port-state | Out-String) -match "Blocked : FALSE") {
                    $endpointData.VfpPort.PortState = "Unblocked"
                }
                else {
                    $endpointData.VfpPort.PortState = "Blocked"
                }
    
                $this.PopulateVfpPortInformation([ref]$endpointData.VfpPort)
            }

            $this.endpointsData += $endpointData
        }
    }

    [EndpointData[]] GetEndpointData() {
        return $this.endpointsData
    }

    PopulateNetworkData([string] $networkName) {

        $networkId = (Get-HnsNetwork -Detailed | Where-Object Name -eq $networkName).Id
        $network = Get-HnsNetwork -Id $networkId -Detailed

        $this.networkData = [NetworkData]::new()
        $this.networkData.Identifier = $network.Id
        $this.networkData.ManagementIpAddress = $network.ManagementIP
        $this.networkData.Name = $networkName
        $this.networkData.HostVfpPort = [VfpPort]::new()
        $this.networkData.HostVfpPort.Identifier = ($network | ForEach-Object { $_.Layer.Resources.Allocators } | Where-Object Tag -eq "Host Vnic").EndpointPortGuid     
        $this.PopulateVfpPortInformation([ref]$this.networkData.HostVfpPort)

        $this.networkData.ExternalVfpPort = [VfpPort]::new()
        $this.networkData.ExternalVfpPort.Identifier = ($network | ForEach-Object { $_.Layer.Resources.Allocators } | Where-Object Tag -eq "External Adapter Info").ExternalNicPortGuid
        $this.PopulateVfpPortInformation([ref]$this.networkData.ExternalVfpPort)

        $kubeClusterConfig = Get-Content C:\k\kubeclusterconfig.json | ConvertFrom-Json
        $this.networkData.ClusterCidr = $kubeClusterConfig.Kubernetes.Network.ClusterCidr
        $this.networkData.ServiceCidr = $kubeClusterConfig.Kubernetes.Network.ServiceCidr
        $this.networkData.DnsIp = $kubeClusterConfig.Kubernetes.Network.DnsIp
    }

    [NetworkData]GetNetworkData() {
        return $this.networkData
    }

    PopulateNodeData() {
        $this.nodeData = [NodeData]::new()
        $hnsData = [HNSData]::new()
        $hnsData.ProcessId = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Hns'" | Select-Object -ExpandProperty ProcessId

        $hnsThreads = (Get-Process -Id $hnsData.ProcessId).Threads
        $hnsData.MemoryUsage = (Get-Process -Id $hnsData.ProcessId).WS / 1MB

        foreach ($thread in $hnsThreads) {
            $threadInfo = [ThreadInformation]::new()
            $threadInfo.ThreadId = $thread.Id
            $threadInfo.ThreadState = $thread.ThreadState
            $threadInfo.WaitReason = $thread.WaitReason

            $hnsData.ThreadInfo += $threadInfo
        }

        $this.nodeData.HNSData = $hnsData
        $this.nodeData.AvailableTCPDynamicPortRanges = $this.CountAvailableEphemeralPorts("TCP")
        $this.nodeData.AvailableUDPDynamicPortRanges = $this.CountAvailableEphemeralPorts("UDP")
    }

    [NodeData] GetNodeData() {
        return $this.nodeData
    }

    PopulateLoadBalancerPolicyData() {
        $hnsPolicyList = Get-HnsPolicyList

        foreach ($policy in $hnsPolicyList) {
            $loadBalancerPolicy = [LoadBalancerPolicyData]::new()
            $loadBalancerPolicy.Identifier = $policy.ID
            $loadBalancerPolicy.State = $policy.State
            $loadBalancerPolicy.NetworkId = $policy.NetworkId
            $loadBalancerPolicy.ExternalPort = $policy.Policies.ExternalPort
            $loadBalancerPolicy.InternalPort = $policy.Policies.InternalPort
            $loadBalancerPolicy.Protocol = $policy.Policies.Protocol
            $loadBalancerPolicy.IsDSR = $policy.Policies.IsDSR
            $loadBalancerPolicy.LocalRoutedVip = $policy.Policies.LocalRoutedVip

            if ($null -ne $policy.Policies.VIPs) {
                $loadBalancerPolicy.VIP = $policy.Policies.VIPs
            }

            foreach ($endpointReference in $policy.References) {
                $endpointReferenceGuid =  $endpointReference.Replace("/endpoints/", "")
                $loadBalancerPolicy.Endpoints += $endpointReferenceGuid
                $loadBalancerPolicy.EndpointIpAddresses += ($this.GetEndpointData() | Where-Object Identifier -EQ $endpointReferenceGuid).IPAddress
            }

            if ($null -ne $loadBalancerPolicy.VIP) {
                # split the service cidr to address and bits
                [string]$serviceCidrAddress = $this.networkData.ServiceCidr.Split('/')[0]
                [int]$serviceCidrBits = $this.networkData.ServiceCidr.Split('/')[1]
    
                [int]$baseAddress = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($serviceCidrAddress)).GetAddressBytes()), 0)
                [int]$vipAddress = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($loadBalancerPolicy.VIP).GetAddressBytes()), 0)
                [int]$mask = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $serviceCidrBits))
    
                # Check if the vip is in the service CIDR.
                if (($baseAddress -band $mask) -eq ($vipAddress -band $mask)) {
                    $loadBalancerPolicy.ServiceType = [ServiceType]::Cluster
                }
                else {
                    $loadBalancerPolicy.ServiceType = [ServiceType]::LoadBalancer
                }
            }
            else {
                if ($loadBalancerPolicy.LocalRoutedVip -eq $true) {
                    $loadBalancerPolicy.ServiceType = [ServiceType]::NodePort
                }
            }

            $this.loadbalancerData += $loadBalancerPolicy
        }
    }

    [LoadBalancerPolicyData[]] GetLoadBalancerPolicyData() {
        return $this.loadbalancerData
    }
}

######################## Diagnostic Tests #######################################

class EndpointStateTest : DiagnosticTest {
    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [EndpointData[]] $endpoints = $DiagnosticDataProvider.GetEndpointData()

        $this.Status = [TestStatus]::Passed
        foreach ($endpoint in $endpoints) {
            [EndpointData] $endpointData = $endpoint
            if (($endpointData.IsRemoteEndpoint -ne $true) -and ($endpointData.EndpointState -ne 3)) {
                $this.Status = [TestStatus]::Failed
                $this.RootCause += " Endpoint state for the POD with IP address " + $endpointData.IPAddress + " is in invalid state " + $endpointData.EndpointState.ToString() + "|"
                $this.Resolution = "Delete and recreate the POD"
            }
        }
        return $this.Status
    }

    [string]GetTestDescription() {
        return "Local Endpoints are in a valid state"
    }
}

class EndpointVfpPortStateTest : DiagnosticTest {
    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [EndpointData[]] $endpoints = $DiagnosticDataProvider.GetEndpointData()

        $this.Status = [TestStatus]::Passed
        foreach ($endpoint in $endpoints) {
            [EndpointData] $endpointData = $endpoint
            if (($endpointData.IsRemoteEndpoint -eq $false) -and ($endpointData.VfpPort.PortState -eq "Blocked")) {
                $this.Status = [TestStatus]::Failed
                $this.RootCause += " VFP port state for the POD with IP address " + $endpointData.IPAddress + " is in invalid state " + $endpointData.VfpPort.PortState.ToString() + "|"
                $this.Resolution = "Delete and recreate the POD"
            }
        }

        [NetworkData] $networkData = $DiagnosticDataProvider.GetNetworkData()

        if ($networkData.HostVfpPort.PortState -eq "Blocked")
        {
            $this.Status = [TestStatus]::Failed
            $this.RootCause += " Host VFP port state is in invalid state " + $networkData.HostVfpPort.PortState.ToString() + "|"
            $this.Resolution = "Delete and recreate the HNS network"
        }

        if ($networkData.ExternalVfpPort.PortState -eq "Blocked")
        {
            $this.Status = [TestStatus]::Failed
            $this.RootCause += " External VFP port state is in invalid state " + $networkData.ExternalVfpPort.PortState.ToString() + "|"
            $this.Resolution = "Delete and recreate the HNS network"
        }

        return $this.Status
    }

    [string]GetTestDescription() {
        return "None of the VFP ports are in blocked state"
    }
}

class PortExhaustionTest : DiagnosticTest {
    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [NodeData] $nodeData = $DiagnosticDataProvider.GetNodeData()
        $this.Status = [TestStatus]::Passed

        if ($nodeData.AvailableTCPDynamicPortRanges -le 10) {
            $this.Status = [TestStatus]::Failed
            $this.RootCause = "TCP dynamic port ranges available for reservation is low : " + $nodeData.AvailableTCPDynamicPortRanges
            $this.Resolution = "Increase the TCP Dynamic Port range."
        }

        if ($nodeData.AvailableUDPDynamicPortRanges -le 10) {
            $this.Status = [TestStatus]::Failed
            $this.RootCause = "UDP dynamic port ranges available for reservation is low : " + $nodeData.AvailableUDPDynamicPortRanges
            $this.Resolution = "Increase the UDP Dynamic Port range."
        }
        return $this.Status
    }

    [string]GetTestDescription() {
        return "Dynamic TCP and UDP ports are not exhausted"
    }
}

class IncorrectManagementIpTest : DiagnosticTest {
    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [NetworkData] $networkData = $DiagnosticDataProvider.GetNetworkData()
        $this.Status = [TestStatus]::Passed

        if ($networkData.ManagementIP -match '169.254.*.*') {
            $this.Status = [TestStatus]::Failed
            $this.RootCause = "Management IP address shouldn't be an APIPA address : " + $networkData.ManagementIP
            $this.Resolution = "Recreate the HNS network."
        }

        return $this.Status
    }

    [string]GetTestDescription() {
        return "Management IP on the network is correct"
    }
}

class LoadBalancerPolicyState : DiagnosticTest {

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [LoadBalancerPolicyData[]] $lbPolicies = $DiagnosticDataProvider.GetLoadBalancerPolicyData()

        $this.Status = [TestStatus]::Passed
        foreach ($lbPolicy in $lbPolicies) {
            if ($lbPolicy.State -ne 2) {
                $this.Status = [TestStatus]::Failed
                $this.RootCause = "LoadBalancer Policy state in not valid : " + $lbPolicy.State.ToString()
                $this.Resolution = "Delete and recreate the LoadBalancer policy"
            }
        }
        return $this.Status
    }

    [string]GetTestDescription() {
        return "HNS LoadBalancer Policies are in valid state."
    }
}

class DSRLoadBalancerPolicyVfpRules : DiagnosticTest {
    # Verify the right VFP Rules are present for HNS Policy List

    [bool] IsVfpRuleConfigured([VfpPort]$port, [string]$ruleName, [string]$groupName, [string]$layerName)
    {
        foreach($layer in $port.Layers)
        {
            foreach($group in $layer.Groups)
            {
                foreach($rule in $group.Rules)
                {
                    if (($rule.Name -match $ruleName) -and ($group.Name -match $groupName) -and ($layer.Name -match $layerName))
                    {
                        return $true
                    }
                }
            }
        }

        return $false
    }

    [bool]LoadBalancerPolicyHasRemoteBackEnd([LoadBalancerPolicyData]$lbPolicyData, [EndpointData[]]$endpointsData) {
        foreach($endpoint in $lbPolicyData.Endpoints)
        {
            if(($endpointsData | Where-Object Identifier -EQ $endpoint).IsRemoteEndpoint -eq $true)
            {
                return $true
            }
        }

        return $false
    }

    [bool]LoadBalancerPolicyHasLocalBackEnd([LoadBalancerPolicyData]$lbPolicyData, [EndpointData[]]$endpointsData) {
        foreach($endpoint in $lbPolicyData.Endpoints)
        {
            if(($endpointsData | Where-Object Identifier -EQ $endpoint).IsRemoteEndpoint -eq $false)
            {
                return $true
            }
        }

        return $false
    }

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        $this.Status = [TestStatus]::Passed
        [LoadBalancerPolicyData[]] $lbPolicies = $DiagnosticDataProvider.GetLoadBalancerPolicyData()
        [EndpointData[]]$endpointsData = $DiagnosticDataProvider.GetEndpointData()
        [NetworkData]$networkData = $DiagnosticDataProvider.GetNetworkData()


        foreach ($lbPolicy in $lbPolicies) {
            if($lbPolicy.IsDSR -ne $true){
                continue
            }

            if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                $ruleName = "LB_DSR_\w*_{0}_{1}_{2}_{3}_{4}" -f $networkData.ManagementIpAddress, $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.InternalPort, $lbPolicy.Protocol
            }
            else {
                $ruleName = "LB_DSR_\w*_{0}_{1}_{2}_{3}_{4}" -f $networkData.ManagementIpAddress, $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.InternalPort, $lbPolicy.Protocol
            }

            if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                $natRuleName = "NAT_\w*_{0}_{1}_{2}" -f $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.Protocol
            }
            else {
                $natRuleName = "NAT_\w*_{0}_{1}_{2}" -f $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.Protocol
            }

            if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                $allowNatRuleName = "ALLOW_NAT_\w*_{0}_{1}_{2}" -f $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.Protocol
            }
            else {
                $allowNatRuleName = "ALLOW_NAT_\w*_{0}_{1}_{2}" -f $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.Protocol
            }
            
            foreach($endpoint in $endpointsData)
            {
                if ($endpoint.IsRemoteEndpoint -ne $true)
                {
                    if ($this.IsVfpRuleConfigured($endpoint.VfpPort, $ruleName, "LB_DSR_IPv4_OUT", "LB_DSR") -eq $false)
                    {
                        $this.Status = [TestStatus]::Failed
                        $this.RootCause += ",VFP port for POD with IP {0} has missing rule {1}" -f $endpoint.IPAddress, $ruleName
                        $this.Resolution = "Restart HNS service by executing: Restart-Service -f HNS"
                    }
                    
                    if ($lbPolicy.EndpointIpAddresses.Contains($endpoint.IPAddress))
                    {
                        if ($this.IsVfpRuleConfigured($endpoint.VfpPort, $natRuleName, "SLB_GROUP_NAT_IPv4_IN", "SLB_NAT_LAYER") -eq $false)
                        {
                            $this.Status = [TestStatus]::Failed
                            $this.RootCause += ",VFP port for POD with IP {0} has missing rule {1}" -f $endpoint.IPAddress, $ruleName
                            $this.Resolution = "Restart HNS service by executing: Restart-Service -f HNS"
                        }
    
                        if ($this.IsVfpRuleConfigured($endpoint.VfpPort, $allowNatRuleName, "SLB_GROUP_NAT_IPv4_OUT", "SLB_NAT_LAYER") -eq $false)
                        {
                            $this.Status = [TestStatus]::Failed
                            $this.RootCause += ",VFP port for POD with IP {0} has missing rule {1}" -f $endpoint.IPAddress, $ruleName
                            $this.Resolution = "Restart HNS service by executing: Restart-Service -f HNS"
                        }
    
                    }
                }
            }


            if ($this.LoadBalancerPolicyHasRemoteBackEnd($lbPolicy, $endpointsData)) {
                
                if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                    $ruleName = "LB_HOST_\w*_{0}_{1}_{2}_{3}" -f $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.InternalPort, $lbPolicy.Protocol
                }
                else {
                    $ruleName = "LB_HOST_\w*_{0}_{1}_{2}_{3}" -f $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.InternalPort, $lbPolicy.Protocol
                }

                if ($this.IsVfpRuleConfigured($networkData.HostVfpPort, $ruleName, "LB_OUT", "LB") -eq $false) {
                    $this.Status = [TestStatus]::Failed
                    $this.RootCause += ",Host VFP port has missing rule {0}" -f $ruleName
                    $this.Resolution = "Restart HNS service by executing: Restart-Service -f HNS"
                }
            }
            else {

                if ($lbPolicy.Endpoints.length -eq 1) {
                    if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                        $ruleName = "NAT_\w*_{0}_{1}_{2}_{3}" -f $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.ExternalPort, $lbPolicy.Protocol
                    }
                    else {
                        $ruleName = "NAT_\w*_{0}_{1}_{2}_{3}" -f $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.ExternalPort, $lbPolicy.Protocol
                    }
                }
                else {
                    if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                        $ruleName = "LB_\w*_{0}_{1}_{2}_{3}" -f $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.ExternalPort, $lbPolicy.Protocol
                    }
                    else {
                        $ruleName = "LB_\w*_{0}_{1}_{2}_{3}" -f $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.ExternalPort, $lbPolicy.Protocol
                    }
                }

                if ($this.IsVfpRuleConfigured($networkData.HostVfpPort, $ruleName, "SLB_GROUP_LB_IPv4_OUT", "SLB_LB_LAYER") -eq $false) {
                    $this.Status = [TestStatus]::Failed
                    $this.RootCause += ",Host VFP port has missing rule {0}" -f $ruleName
                    $this.Resolution = "Restart HNS service by executing: Restart-Service -f HNS"
                }
            }

            if ($this.LoadBalancerPolicyHasLocalBackEnd($lbPolicy, $endpointsData)) {
                if ($lbPolicy.ServiceType -eq [ServiceType]::NodePort) {
                    $ruleName = "HairPin_\w*_{0}_{1}_{2}_{3}" -f $networkData.ManagementIpAddress, $lbPolicy.ExternalPort, $lbPolicy.ExternalPort, $lbPolicy.Protocol
                }
                else {
                    $ruleName = "HairPin_\w*_{0}_{1}_{2}_{3}" -f $lbPolicy.VIP, $lbPolicy.ExternalPort, $lbPolicy.ExternalPort, $lbPolicy.Protocol
                }

                if ($this.IsVfpRuleConfigured($networkData.HostVfpPort, $ruleName, "SLB_GROUP_HAIRPIN_IPv4_IN", "SLB_HAIRPIN_LAYER") -eq $false) {
                    $this.Status = [TestStatus]::Failed
                    $this.RootCause += ",Host VFP port has missing rule {0}" -f $ruleName
                    $this.Resolution = "Restart HNS service by executing: Restart-Service -f HNS"
                }
            }
        }

        return $this.Status
    }

    [string]GetTestDescription() {
        return "VFP rules for HNS LoadBalancer Policies in DSR mode are configured correctly."
    }
}

class StaleRemoteEndpoints : DiagnosticTest {
    # Ensure that all remote endpoints on the node belong to atleast one policyList 

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [EndpointData[]]$endpointsData = $DiagnosticDataProvider.GetEndpointData()
        [LoadBalancerPolicyData[]] $lbPolicies = $DiagnosticDataProvider.GetLoadBalancerPolicyData()

        $this.Status = [TestStatus]::Passed
        $stale_endpoints = [System.Collections.ArrayList]::new()
        foreach($endpoint in $endpointsData)
        {
            $stale_remote_endpoint = $true
            if ($endpoint.IsRemoteEndpoint -eq $true) {
                foreach ($lbPolicy in $lbPolicies) {
                    if ($endpoint.IsRemoteEndpoint -eq $true -and $lbPolicy.EndpointIpAddresses.Contains($endpoint.IPAddress))
                    {
                        $stale_remote_endpoint = $false
                        break
                    }
                }
            }
            else{
                $stale_remote_endpoint = $false
            }

            if($stale_remote_endpoint) {
                $stale_endpoints.Add($endpoint.IPAddress)
            }
        }
        if($stale_endpoints.Count -gt 0) {
            $this.Status = [TestStatus]::Failed
            $this.RootCause = "Detected {0} stale remote endpoints {1} " -f $stale_endpoints.Count, ($stale_endpoints -join ' ')
            $this.Resolution = "Reconfigure Load balancer policies or remove the stale endpoints"
        }
        return $this.Status
    }

    [string]GetTestDescription() {
        return "No stale remote endpoints found"
    }
}

class ValidDNSLoadbalancerPolicy : DiagnosticTest {
    # Ensure that a valid HNS LoadBalancer policy exists for the DNS IP

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [LoadBalancerPolicyData[]] $lbPolicies = $DiagnosticDataProvider.GetLoadBalancerPolicyData()
        [NetworkData]$networkData = $DiagnosticDataProvider.GetNetworkData()

        $this.Status = [TestStatus]::Passed
        $dns_policy = 0
        foreach ($lbPolicy in $lbPolicies) {  
            if($lbPolicy.VIP -eq $networkData.DnsIp) {
                $dns_policy += 1
            }  
        }
        if ($dns_policy -eq 0) {
            $this.Status = [TestStatus]::Failed
            $this.RootCause = "DNS IP Policy missing"
            $this.Resolution = "Restart the kubeproxy service to reconfigure the LoadBalancer policies: Restart-Service kubeproxy" 
        }
        return $this.Status
    }

    [string]GetTestDescription() {
        return "Valid HNS LoadBalancer policy exists for the DNS IP"
    }
}

class ClusterIPServiceDSR : DiagnosticTest {
    # Ensure all the HNS Load balancer policies for the ClusterIP are configured in DSR mode

    [TestStatus]Run([DiagnosticDataProvider] $DiagnosticDataProvider) {
        [LoadBalancerPolicyData[]] $lbPolicies = $DiagnosticDataProvider.GetLoadBalancerPolicyData()

        $this.Status = [TestStatus]::Passed
        foreach ($lbPolicy in $lbPolicies) {
            if($lbPolicy.ServiceType -eq "cluster" -and (-not $lbPolicy.IsDSR)) {
                $this.Status = [TestStatus]::Failed
                $this.RootCause = "DSR mode not configured for Load balancer cluster type policy"
                $this.Resolution = "Reconfigure cluster type policies in DSR mode"
            }
        }
        return $this.Status
    }

    [string]GetTestDescription() {
        return "All cluster IP policies are configured with DSR mode"
    }
}

####################### Main ###########################################

if ($Replay) {
    $networkTroubleshooter = [NetworkTroubleshooter]::new([FakeDiagnosticDataProvider]::new())
}
else {
    $aksDiagnosticDataProvider = [AKSNodeDiagnosticDataProvider]::new($NetworkName)
    $networkTroubleshooter = [NetworkTroubleshooter]::new($aksDiagnosticDataProvider)
}

# Register diagnostic test cases
$networkTroubleshooter.RegisterDiagnosticTest([EndpointStateTest]::new())
$networkTroubleshooter.RegisterDiagnosticTest([EndpointVfpPortStateTest]::new())
$networkTroubleshooter.RegisterDiagnosticTest([PortExhaustionTest]::new())
$networkTroubleshooter.RegisterDiagnosticTest([IncorrectManagementIpTest]::new())
$networkTroubleshooter.RegisterDiagnosticTest([LoadBalancerPolicyState]::new())
$networkTroubleshooter.RegisterDiagnosticTest([DSRLoadBalancerPolicyVfpRules]::new())
$networkTroubleshooter.RegisterDiagnosticTest([StaleRemoteEndpoints]::new())
$networkTroubleshooter.RegisterDiagnosticTest([ValidDNSLoadbalancerPolicy]::new())
$networkTroubleshooter.RegisterDiagnosticTest([ClusterIPServiceDSR]::new())

# Run Diagnostic tests against data
$networkTroubleshooter.RunDiagnosticTests()

if (($MODE -ne [Mode]::EventOnly -or ($networkTroubleshooter.GetNetworkStatus() -eq [TestStatus]::Failed)) -and -NOT $Replay.IsPresent -and $MODE -ne [Mode]::StdOut){
    $curDir = Get-Location
    # Generate a random directory to capture all the logs
    $outDir = [io.Path]::Combine($curDir.Path, [io.Path]::GetRandomFileName())
    mkdir $outDir
    Push-Location
    Set-Location $outDir
    #save the files needed for replaying the troubleshooting later
    $aksDiagnosticDataProvider.GetEndpointData() | ConvertTo-Json -depth 100 | Out-File "endpointdata.json"
    $aksDiagnosticDataProvider.GetNetworkData() | ConvertTo-Json -depth 100 | Out-File "networkdata.json"
    $aksDiagnosticDataProvider.GetLoadBalancerPolicyData() | ConvertTo-Json -depth 100 | Out-File "loadbalancerdata.json"
    $aksDiagnosticDataProvider.GetNodeData() | ConvertTo-Json -depth 100 | Out-File "nodedata.json"
}

# Output events and/or HTML file
if ($MODE -eq [Mode]::EventOnly) {
    $networkTroubleshooter.GenerateEvent()
} elseif ($MODE -eq [Mode]::HtmlOnly) {
    $networkTroubleshooter.GenerateHtml()
}
elseif($MODE -eq [Mode]::StdOut) {
    $networkTroubleshooter.LogErrors()
}
else {
    $networkTroubleshooter.GenerateEvent()
    $networkTroubleshooter.GenerateHtml()
}

# Collect Logs, if tests failed or if flag is set
if ($CollectLogs -and -NOT $Replay.IsPresent){
    C:\k\debug\collect-windows-logs.ps1
}

if (($MODE -ne [Mode]::EventOnly -or ($networkTroubleshooter.GetNetworkStatus() -eq [TestStatus]::Failed)) -and -NOT $Replay.IsPresent -and $MODE -ne [Mode]::StdOut) {
    Copy-Item ..\networkhealth.ps1 .
    Pop-Location

    $timeStamp = get-date -format 'yyyyMMdd-hhmmss'
    $zipFileName = "$env:computername-$($timeStamp)_troubleshooting.zip"
    Compress-Archive -LiteralPath $outDir -DestinationPath $zipFileName

    Write-Host "Troubleshooting report is available at $zipFileName"
}

# Clean up globals
if ($MODE -ne [Mode]::HtmlOnly) {
    Remove-Variable -name EVENT_SOURCE_NAME -Scope Global
    Remove-Variable -name LOG_NAME -Scope Global
}
