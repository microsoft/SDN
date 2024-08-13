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
    #logic here
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
    #logic here
    return $true
}