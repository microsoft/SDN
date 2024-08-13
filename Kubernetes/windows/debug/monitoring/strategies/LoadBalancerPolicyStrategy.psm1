$ServiceIp  = "192.168.0.10"
$ServicePort = 53

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
    LogMessage "Capturing some information before the repro."   
    $hnsInfo = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'hns'" 
    $kubeproxyInfo = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Kubeproxy'"
    LogMessage $hnsInfo
    LogMessage $kubeproxyInfo
}

function TerminateHandler
{
    param
    (
        [string] $LogPath = "" 
    )
    LogMessage "Capturing some information after the repro."  
    $hnsInfo = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'hns'" 
    $kubeproxyInfo = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Kubeproxy'"
    LogMessage $hnsInfo
    LogMessage $kubeproxyInfo
    LogMessage "HNS Policy for K8's Service with IP $ServiceIp and Port $ServicePort is missing"
}

function IsNodeFaulted
{
    return ((Get-HnsPolicyList | where {($_.Policies.VIPs.Count -ge 1) -and $_.Policies.VIPs.Contains($ServiceIp) -and $_.Policies.ExternalPort -eq $ServicePort}) -eq $null)
}
