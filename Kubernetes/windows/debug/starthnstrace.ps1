param(
    [bool] $Prompt = $true,
    [string] $EtlFile = "c:\server.etl"
)

Stop-NetEventSession HnsCapture -ErrorAction Ignore
Remove-NetEventSession HnsCapture -ErrorAction Ignore

New-NetEventSession HnsCapture -CaptureMode SaveToFile -LocalFilePath $EtlFile

Add-NetEventProvider "{564368D6-577B-4af5-AD84-1C54464848E6}" -Level 6 -SessionName HnsCapture # Microsoft-Windows-Overlay-HNSPlugin
Add-NetEventProvider "{0c885e0d-6eb6-476c-a048-2457eed3a5c1}" -Level 6 -SessionName HnsCapture # Microsoft-Windows-Host-Network-Service
Add-NetEventProvider "{80CE50DE-D264-4581-950D-ABADEEE0D340}" -Level 6 -SessionName HnsCapture # Microsoft.Windows.HyperV.Compute
Add-NetEventProvider "{9D911DDB-D45F-41C3-B766-D566D2655C4A}" -Level 6 -SessionName HnsCapture # Microsoft.Windows.Containers.Manager
Add-NetEventProvider "{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}" -Level 6 -SessionName HnsCapture # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
Add-NetEventProvider "{93f693dc-9163-4dee-af64-d855218af242}" -Level 6 -SessionName HnsCapture # Microsoft-Windows-Host-Network-Management
Add-NetEventProvider "{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}" -Level 6 -SessionName HnsCapture # Microsoft-Windows-SharedAccess_NAT
Add-NetEventProvider "{6C28C7E5-331B-4437-9C69-5352A2F7F296}" -Level 6 -SessionName HnsCapture # Microsoft.Windows.Hyper.V.VmsIf

# VmSwitch Enable ETW and WPP Events - Control Path Only
Add-NetEventProvider "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" -Level 6 -SessionName HnsCapture -MatchAnyKeyword 4292870139 # 0xFFDFFFFB 
Add-NetEventProvider "{67DC0D66-3695-47c0-9642-33F76F7BD7AD}" -Level 6 -SessionName HnsCapture -MatchAnyKeyword 4294967261 # 0xFFFFFFDD

if ([environment]::OSVersion.Version.Build -igt 19041)
{
    Add-NetEventProvider "{94DEB9D1-0A52-449B-B368-41E4426B4F36}" -Level 6 -SessionName HnsCapture # Microsoft.Windows.Hyper.V.NetSetupHelper
}

# VFPEXT is an optional component
Add-NetEventProvider "Microsoft-Windows-Hyper-V-VfpExt" -Level 6 -SessionName HnsCapture -ErrorAction Ignore -MatchAnyKeyword 4259840 # 0x00410000

Start-NetEventSession HnsCapture

if ($Prompt)
{
    Read-Host -Prompt "Press enter to stop capture"
    Stop-NetEventSession HnsCapture
    Remove-NetEventSession HnsCapture
}
else
{
    Write-Host "Use Stop-NetEventSession HnsCapture" to stop capture
    Write-Host "Use Remove-NetEventSession HnsCapture" to remove capture
}
