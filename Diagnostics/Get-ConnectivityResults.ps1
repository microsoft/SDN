# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------


##################################################
#
# Command: 
#    Get-ConnectivityResults.ps1
#
# Description: 
#    This PowerShell script will do a GET on the Network Controller's NorthBound API at URI ~networkinv/v1/diagnostics/connectivityCheckResults
#    to get the results back from Test-VNetPing.ps1
#
# Usage: 
#    Get-ConnectivityResults -RestUri <NC REST FQDN> [-operationId <Id>] 
#
# Output:
#    The output of this command will be to return the original test parameters from Test-VNetPing.ps1 as well as the Results
#    
# Results:
#    Results include status, error message (if applicable) and trace output through the different VFP layers and rules
#    NOTE: Results are only available for 60 minutes
#
# Example: 
#    .\Get-ConnectivityResults.ps1 -RestURI https://sa18n30nc.sa18.nttest.microsoft.com -operationId "d807168c-70d3-4663-b71e-e4df5794d9fe"
#
#
##################################################

[cmdletbinding()]
Param(
    [Parameter(mandatory=$true)]
    [String] $RestURI=$null,
    [Parameter(mandatory=$false)]
    [String] $operationId=$null,
    [Parameter(mandatory=$false)]
    [Switch] $IsKerberosAuthentication
)

# Build HTTP Header
$headers = @{"Accept"="application/json"}
$method = "Get"
$content = "application/json; charset=UTF-8"
$network = "$RestURI/Networking/v1"
$timeout = 10

if ($operationId -eq $null)
{
   $uri = "$network/diagnostics/connectivityCheckResults"
} else {
   $uri = "$network/diagnostics/connectivityCheckResults/$operationId"
}


Write-Host
Write-Host "GET $uri" -ForegroundColor Green

try
{
  $response = Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -DisableKeepAlive -UseBasicParsing -UseDefaultCredentials:$IsKerberosAuthentication
  Write-Host $response.Content
}
catch
{
  $_
  $_.Exception.Response
}


