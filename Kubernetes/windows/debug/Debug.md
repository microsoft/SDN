1:[Log Collection]:

===================================================

Usage:

	On an Administrative Powershell Window

	Set-ExecutionPolicy Bypass

	Start-BitsTransfer https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1

	.\collectlogs.ps1 

		Would collect all the required logs to validate if all policies has been plumbled.
	
		Folder with a random name will be generate with a bunch of text files. Please send us the folder.

2. [Packet Capture]:

====================================================

After downloading and running CollectLogs.ps1, packet capture tracing cmd files will be downloaded to the following folder C:\k\debug.

Usage:

	Go to C:\k\debug\

	Start => .\startpacketcapture.cmd

	<Repro the issue>

	Stop  => .\stoppacketcapture.cmd

	After Stopping the trace, use the trace file from c:\server.etl
