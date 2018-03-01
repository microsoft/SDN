1. [Log Collection]

Usage:
======
powershell collectlogs.ps1


Would collect all the required logs to validate if all policies has been plumbled.


2. [Packet Capture]

Start => startpacketcapture.cmd
Stop  => stoppacketcapture.cmd

3. [Troubleshooting]

In case the cmd fails, try to install Hyper-V Role
	dism /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V /All /NoRestart
