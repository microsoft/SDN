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
#    Test-VNetPing.ps1
#
# Description: 
#    This PowerShell script will invoke the Network Controller's NorthBound API to trigger a connectivity test between two VM NIC IPs -
#    CA IP Addresses. The PUT operation will return an OperationId which can be referenced in a subsequent GET call to query the status
#
# Usage: 
#    Test-VNetPing.ps1 -RestUri <NC REST FQDN>  -senderIp <IP Address> -receiverIp <IP Address> -vNetResourceId <VNet Resource Ref> 
#
# Output:
#    The output will be an operation Id and Status Code (201 for created - successful)
#
# Results:
#    In order to collect results, run the Get-ConnectivityResults.ps1 script. If you reference the OperationId, only the results for that
#    particular opeation will be reported. If you do not reference an OperationId, all results will be reported. NOTE: Results are only
#    available for 60 minutes
#
# Example: 
#    Test-VNetPing.ps1 -RestUri https://sa18n30nc.sa18.nttest.microsoft.com -senderIp "24.30.1.101" -receiverIp "24.30.1.102" -vnetResourceId "Fabrikam_VNet1"
#
##################################################

[cmdletbinding()]
Param(
    [Parameter(mandatory=$true)]
    [String] $RestURI=$null,
    [Parameter(mandatory=$true)]
    [String] $senderIp=$null,
    [Parameter(mandatory=$true)]
    [String] $receiverIp=$null,
    [Parameter(mandatory=$true)]
    [String] $vnetResourceId=$null,
    [Parameter(mandatory=$false)]
    [Switch] $IsKerberosAuthentication
    )

#TODO: Validate that VNet Resource IDs are correct

# Get VNet Resource Ref
$vnetRef = Get-NetworkControllerVirtualNetwork -ConnectionURI $RestUri -ResourceId $vnetResourceId

#EXTRA TODO: Validate that the IPs referenced (senderIp and receiverIp) have a corresponding IPConfiguration in the VNet / subnet

# Build JSON Body
$ConnectivityCheckResource = @{}
$ConnectivityCheckResource.resourceId =  "action"
$ConnectivityCheckResource.properties = @{}
$ConnectivityCheckResource.properties.senderIpAddress = $senderIp
$ConnectivityCheckResource.properties.receiverIpAddress = $receiverIp
$ConnectivityCheckResource.properties.senderVirtualNetwork = @{}
$ConnectivityCheckResource.properties.senderVirtualNetwork.resourceRef = $vnetRef.ResourceRef
$ConnectivityCheckResource.properties.receiverVirtualNetwork = @{}
$ConnectivityCheckResource.properties.receiverVirtualNetwork.resourceRef = $vnetRef.ResourceRef
$ConnectivityCheckResource.properties.protocol = "ICMP"
$ConnectivityCheckResource.properties.icmpProtocolConfig = @{}
$ConnectivityCheckResource.properties.icmpProtocolConfig.sequenceNumber = 0
$ConnectivityCheckResource.properties.icmpProtocolConfig.length = 0

# Currently, the VNet refs must point to the same resource. In the future, we may allow cross-vnet ping for validation through GW / SLB


<# Sample Body for reference
{
  "resourceId": "action",
  "resourceMetadata": {
    "client": "Test",
    "tenantId": "{subscriptionid}",
    "groupId": "{groupname}",
    "resourceName": "action",
    "originalHref": "https://test",
  },
  "properties":  {
    "senderIpAddress" : "10.2.2.4",
    "receiverIpAddress" : "10.2.2.5",
    "sendervirtualNetwork" : {"resourceRef":"/VirtualNetworks/00000000-1111-0000-0001-000000000000"},
    "receivervirtualNetwork" : {"resourceRef":"/VirtualNetworks/00000000-1111-0000-0001-000000000000"},
    "protocol": "Icmp",
    "icmpProtocolConfig": {
      "sequenceNumber": 0,
      "length": 0
    }
  }
}
#>

# Build HTTP Header
$headers = @{"Accept"="application/json"}
$method = "Put"
$content = "application/json; charset=UTF-8"
$network = "$RestURI/Networking/v1"
$timeout = 10
$uri = "$network/diagnostics/connectivityCheck"

$body = convertto-json $ConnectivityCheckResource -Depth 100

#Write-Host
#Write-Host "PUT $uri" -ForegroundColor Green
#Write-Host "BODY $body" -ForegroundColor White

# Send Request - Output Raw Contenat as response
try
{
  $response = Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -Body $body -DisableKeepAlive -UseDefaultCredentials:$IsKerberosAuthentication
  Write-Host $response.RawContent
}
catch
{
  $_
  $_.Exception.Response
}


#TODO: Parse the OperationId from this response and then immediately do a GET on this URI with the Operation Id
# GET "$network/diagnostics/connectivityCheckResults/OperationId". Loop until we get results

