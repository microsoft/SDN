.COPYRIGHT 
    File="NCDiagnostics.ps1" Company="Microsoft"
    Copyright (c) Microsoft Corporation.  All rights reserved.   

.SYNOPSIS 
    Script to configure logging on Network Controller setup and collect diagnostics data.

.PARAMETERS
    [string][parameter(Mandatory=$true, HelpMessage="One Network controller Node Name/IP")]$NetworkController,
    [Switch][parameter(Mandatory=$false, HelpMessage="Setup Diagnostics. Will retrieve diagnostics information by default.")]$SetupDiagnostics = $false,
    [bool][parameter(Mandatory=$false, HelpMessage="Include Host Agent and NC Traces")]$IncludeTraces = $true,
    [string][parameter(Mandatory=$false,HelpMessage="Complete Path to the Output Directory")]$OutputDirectory = (Get-Location).Path,
    [System.Management.Automation.PSCredential][parameter(Mandatory=$false, HelpMessage="Credential to use for Network Controller. Specify in case of Kerberos deployment.")]$Credential = $null,
    [String][parameter(Mandatory=$false, HelpMessage="The URI to be used for Network Controller REST APIs. Specify in case of wild card certificate deployment.")]$RestURI = $null,
    [String][parameter(Mandatory=$false, HelpMessage="Certificate thumbprint to use for Network Controller. Specify in case of certificate deployment.")]$CertificateThumbprint = $null,
    [String][parameter(Mandatory=$false, HelpMessage="Complete path to the directory where NC Diagnostics tools are present. This should have ovsdb-client.exe")]$ToolsDirectory = (Get-Location).Path     

.EXAMPLE
    # To Setup logging on all NC Nodes and hosts.
    .\NCDiagnostics.ps1 NC-0.contoso.cloud.com -SetupDiagnostics
       
    # To collect diagnostics data and Logs from all NC Nodes and hosts.
    $cred = Get-Credential                                                                                                                                                                   
    .\NCDiagnostics.ps1 -NetworkController NC-0.contoso.cloud.com -Credential $cred -OutputDirectory C:\DiagnosticsData

    # To collect only diagnostics data
    .\NCDiagnostics.ps1 -NetworkController NC-0.contoso.cloud.com -Credential $cred -OutputDirectory C:\DiagnosticsData -IncludeTraces $false
	
.PREREQUISITES
	* Hosts and Network Controller machines should be accessible using the credentials provided.
	* Hosts and Network Controller should be added to winrm trusted hosts list
	* ovsdb-client.exe should be present in the tools folder