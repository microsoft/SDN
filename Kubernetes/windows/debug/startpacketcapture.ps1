param(
    [bool] $Prompt = $true,
    [string] $EtlFile = "c:\server.etl"
)

#
# Stop any existing session and create a new session
#
Stop-NetEventSession HnsPacketCapture -ErrorAction Ignore
Remove-NetEventSession HnsPacketCapture -ErrorAction Ignore
New-NetEventSession HnsPacketCapture -CaptureMode SaveToFile -LocalFilePath $EtlFile

#
# The set below does not account for the full "scenario=Virtualization" or "scenario=InternetClient_dbg" but it includes
# components commonly used in Windows Container Network scenarios
#

# Control Plane
Add-NetEventProvider "{564368D6-577B-4af5-AD84-1C54464848E6}" -Level 6 -SessionName HnsPacketCapture # Microsoft-Windows-Overlay-HNSPlugin
Add-NetEventProvider "{0c885e0d-6eb6-476c-a048-2457eed3a5c1}" -Level 6 -SessionName HnsPacketCapture # Microsoft-Windows-Host-Network-Service
Add-NetEventProvider "{80CE50DE-D264-4581-950D-ABADEEE0D340}" -Level 6 -SessionName HnsPacketCapture # Microsoft.Windows.HyperV.Compute
Add-NetEventProvider "{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}" -Level 6 -SessionName HnsPacketCapture # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
Add-NetEventProvider "{93f693dc-9163-4dee-af64-d855218af242}" -Level 6 -SessionName HnsPacketCapture # Microsoft-Windows-Host-Network-Management
Add-NetEventProvider "{6C28C7E5-331B-4437-9C69-5352A2F7F296}" -Level 6 -SessionName HnsPacketCapture # Microsoft.Windows.Hyper.V.VmsIf

# Protocols
Add-NetEventProvider "Microsoft-Windows-TCPIP"         -Level 6 -SessionName HnsPacketCapture
Add-NetEventProvider "Microsoft-Windows-DNS-Client"    -Level 6 -SessionName HnsPacketCapture
Add-NetEventProvider "Microsoft-Windows-Dhcp-Client"   -Level 6 -SessionName HnsPacketCapture
Add-NetEventProvider "Microsoft-Windows-DHCPv6-Client" -Level 6 -SessionName HnsPacketCapture

# NAT
Add-NetEventProvider "Microsoft-Windows-WinNat"               -Level 6 -SessionName HnsPacketCapture
Add-NetEventProvider "{AA7387CF-3639-496A-B3BF-DC1E79A6fc5A}" -Level 6 -SessionName HnsPacketCapture # WIN NAT WPP
Add-NetEventProvider "{AE3F6C6D-BF2A-4291-9D07-59E661274EE3}" -Level 6 -SessionName HnsPacketCapture # IP NAT WPP

# Shared Access
Add-NetEventProvider "{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}" -Level 6 -SessionName HnsPacketCapture # Shared Access Service WPP Provider
Add-NetEventProvider "{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}" -Level 6 -SessionName HnsPacketCapture # Microsoft-Windows-SharedAccess_NAT

# VmSwitch Enable ETW and WPP Events
Add-NetEventProvider "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" -Level 6 -SessionName HnsPacketCapture
Add-NetEventProvider "{67DC0D66-3695-47c0-9642-33F76F7BD7AD}" -Level 6 -SessionName HnsPacketCapture

if ([environment]::OSVersion.Version.Build -igt 19041)
{
    Add-NetEventProvider "{94DEB9D1-0A52-449B-B368-41E4426B4F36}" -Level 6 -SessionName HnsPacketCapture # Microsoft.Windows.Hyper.V.NetSetupHelper
}

# VFPEXT is an optional component
Add-NetEventProvider "Microsoft-Windows-Hyper-V-VfpExt" -Level 6 -SessionName HnsPacketCapture -ErrorAction Ignore

#
# Capture packets on all interfaces
#
Add-NetEventPacketCaptureProvider -Level 5 -SessionName HnsPacketCapture -CaptureType BothPhysicalAndSwitch

#
# Start the session and optionally wait for the user to stop the session
#
Start-NetEventSession HnsPacketCapture

if ($Prompt)
{
    Read-Host -Prompt "Press enter to stop capture"
    Stop-NetEventSession HnsPacketCapture
    Remove-NetEventSession HnsPacketCapture
}
else
{
    Write-Host "Use Stop-NetEventSession HnsPacketCapture" to stop capture
    Write-Host "Use Remove-NetEventSession HnsPacketCapture" to remove capture
}
