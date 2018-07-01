# Time Configuration Tools

## SoftwareTimeStamping

### Description
This is a PowerShell Module that can Get/Enable/Disable the Software Time Stamping configuration.

### Warning
> This feature is not currently supported by Microsoft

### Installation
Copy the SoftwareTimeStamping Folder into C:\Program Files\WindowsPowerShell\Modules

### Test
Please try out our validation guide!
https://github.com/Microsoft/SDN/blob/master/FeatureGuide/Validation%20Guide%20-%20RS5%20-%20Software%20Timestamping.docx

### Known Issues
The PowerShell cmdlets and DSC resources do NOT restart the network adapters.  This is required prior to timestamping settings being effectual.  To do this, you can use Restart-NetAdapter or restart the computer.

## PTP

### Description
Contains automation helpers used to complete portions of the PTP setup

For more information, please see https://aka.ms/PTPValidation
