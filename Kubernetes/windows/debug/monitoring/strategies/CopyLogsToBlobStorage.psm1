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

    # copy the logs to Azure blob
    Invoke-WebRequest https://azcopyvnext.azureedge.net/release20211027/azcopy_windows_amd64_10.13.0.zip -OutFile azcopyv10.zip
    Expand-Archive .\azcopyv10.zip -Force

    $timeStamp = get-date -format 'yyyyMMdd-hhmmss'
    $zipFileName = "$env:computername-$($timeStamp)_logs.zip"
    Compress-Archive -LiteralPath $LogPath -DestinationPath $zipFileName
    .\azcopyv10\azcopy_windows_amd64_10.13.0\azcopy.exe copy $zipFileName "https://sban91storage.blob.core.windows.net/akslogs?sp=rw&st=2021-11-30T18:59:20Z&se=2021-12-12T02:59:20Z&spr=https&sv=2020-08-04&sr=c&sig=3uzRPB72k4NnM2q1k1vZ1xqugkjDSUSWSPMdiMQkwMI%3D"
}

function IsNodeFaulted
{
    #logic here
    return $true
}