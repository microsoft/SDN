param(
[String]$HostName,
[String]$MgmtIp,
[String]$User="",
[String]$Password="",
[string]$VMName,
[switch]$Sender,
[switch]$Listener,
[String]$SenderCAIP,
[Int32]$SenderVSID,
[String]$ListenerCAIP,
[Int32]$ListenerVSID,
[string]$VMNetworkAdapterName,
[Int32]$SequenceNumber
)

. .\sessionhelper.ps1
. .\log.ps1

$session, $creds = CreatePsRemotingSession $HostName $MgmtIp $User $Password
if ($session -eq $null) {
    WriteOutput "Could not establish session"
    return
}

ProvisionHost -MachineName $HostName -Cred $creds `
                -Session $session -SourceDir "\CaConnectivity" -MgmtIp $MgmtIp

$success, $rtt = RunScriptBlock -Session $session -ScriptBlock {
param($VMName, $Sender, $Listener, $SenderCAIP, $SenderVSID, `
     $ListenerCAIP, $ListenerVSID, $VMNetworkAdapterName, $SequenceNumber)
    cmd /c cd /d c:\CaConnectivity
    return .\Test-VMNetConnectivity.ps1 -VMName $VMName `
        -Sender:$Sender.IsPresent -Listener:$Listener.IsPresent `
        -SenderIPAddress $SenderCAIP -SenderVSID $SenderVSID `
        -ListenerIPAddress $ListenerCAIP -ListenerVSID $ListenerVSID `
        -VMNetworkAdapterName $VMNetworkAdapterName `
        -SequenceNumber $SequenceNumber
} -ArgList $VMName, $Sender, $Listener, $SenderCAIP, $SenderVSID,`
     $ListenerCAIP, $ListenerVSID, $VMNetworkAdapterName, $SequenceNumber


$fullTargetDir = "\CaConnectivity\" + $HostName

If (Test-Path $fullTargetDir) {
    Remove-Item $fullTargetDir -Recurse -Force
}
# copy back
CollectHostLogs -MachineName $HostName `
                    -Cred $creds `
                    -Session $session `
                    -RemoteDir "\CaConnectivity" `
                    -TargetDir $fullTargetDir `
                    -MgmtIp $MgmtIp

#dump logs 
Get-Content "$fullTargetDir\ConnectivityInfo.txt"
Get-Content "$fullTargetDir\PingTrace.txt"

DestroyPsRemotingSession($session)

## Examples
#Listener:
 #.\CaPingDriver.ps1 -HostName TestServer -MgmtIp 10.xx.xx.xx `
 #   -User "Administrator" -Password "P@ssw0rd1" -VMName VM2 `
 #   -Listener -SenderCAIP 192.168.1.2 -SenderVSID 5001 `
 #   -ListenerCAIP 192.168.1.3 -ListenerVSID 5001 `
 #   -VMNetworkAdapterName testnic -SequenceNumber 111

#Sender:
 #.\CaPingDriver.ps1 -HostName TestServer -MgmtIp 10.xx.xx.xx `
 #   -User "Administrator" -Password "P@ssw0rd1" -VMName VM1 `
 #   -Sender -SenderCAIP 192.168.1.2 -SenderVSID 5001 `
 #   -ListenerCAIP 192.168.1.3 -ListenerVSID 5001 `
 #   -VMNetworkAdapterName testnic -SequenceNumber 111

