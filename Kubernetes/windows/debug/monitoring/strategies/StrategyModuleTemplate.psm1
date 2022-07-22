#Implement these 4 methods:
# 1. LogMessage - Implements logic to log messages. Defaults to logging to a file.
# 2. StartHandler - Handler invoked after the monitoring starts (before the node is in repro state)
# 3. TerminateHandler - Handler invoked before the monitoring stops (after the node is in repro state)
# 4. IsNodeFaulted - Returns a $true when the node is in repro state, $false otherwise

function LogMessage
{
    param
    (
        [string] $Message = "" 
    )

    #re-implement if needed
    $FilePath = "C:\k\debug\MonitorWindowsNode.txt"
    Get-Date | Out-File -FilePath $FilePath -Append
    $Message | Out-File -FilePath $FilePath -Append

}

function StartHandler
{
    #download file
    wget https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/hns.v2.psm1 -o HNS.V2.psm1

    ipmo .\HNS.V2.psm1
}

function TerminateHandler
{
    param
    (
        [string] $LogPath = "" 
    )
    #logic here
}

function IsNodeFaulted
{
    #More specific lookup by azure name. Needs more testing before is used.
    #((get-hnsnetwork | ? name -like azure)[0].Policies | Where-Object PolicyType -eq IPSET).count
    $expectedNumPolicies = (((get-hnsnetwork | Select Policies)[1].Policies) | Where-Object PolicyType -eq IPSET).Count
    if($expectedNumPolicies -eq 0){
        return $false
    }
    $EndpointPorts = Get-HnsEndpoint | %{$_.Resources.Allocators} | Where-Object Tag -eq "Endpoint Port" | Select -ExpandProperty EndpointPortGuid
    foreach ($endPort in $EndpointPorts)
    {
        $currNumPolicies = (vfpctrl /port $endPort /list-tag | Select-String "Friendly Name").Count
        #if difference is greater than or equal to 10%
        if($currNumPolicies -le ($expectedNumPolicies - $expectedNumPolicies * .1)){

            #get the virtualNetwork
            $netId = Get-HnsEndpoint | where-object {$_.Resources.Allocators.EndPointPortGuid -eq $endPort} | Select -ExpandProperty VirtualNetwork
            #send test policy to simplify log lookup
            New-HNSSetPolicy -NetworkId $netId -setType 0 -setValues "10.22.0.44" -setName "spTestName" -setId "spTestId" -Verbose

            return $true
        }
    }
    return $false
}