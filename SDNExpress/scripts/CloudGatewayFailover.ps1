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


[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $NetworkControllerRestIP = "<<Replace>>.$env:USERDNSDOMAIN",                      #Example: (after evaluation of $env:USERDNSDOMAIN): myname.contoso.com
    [Parameter(Mandatory=$false)]
    [string] $NCUsername = "<<Replace>>",                                                      #Example: CONTOSO\AlYoung
    [Parameter(Mandatory=$false)]
    [string] $NCPassword = "<<Replace>>",                                                      #Example: MySuperS3cretP4ssword
    [Parameter(Mandatory=$false)]
    [string] $TenantName = "<<Replace>>"                                                       #Example: "Contoso"
)

$verbosePreference = "continue"

function GenerateCredentials
{
    param ([Parameter(mandatory=$true)][string]$Username,
           [Parameter(mandatory=$true)][string]$Password)

    $securePassword =  convertto-securestring $Password -asplaintext -force
    $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Username,$securePassword

    return $credential
}

function GetOrCreate-PSSession
{
    param ([Parameter(mandatory=$true)][string]$ComputerName,
           [PSCredential]$Credential = $null )

    # Get or create PS Session to the HyperVHost and remove all the VMs
    $PSSessions = @(Get-PSSession | ? {$_.ComputerName -eq $ComputerName})

    if ($PSSessions -ne $null -and $PSSessions.count -gt 0)
    {
        foreach($session in $PSSessions)
        {
            if ($session.State -ne "Opened" -and $session.Availability -ne "Available")
            { $session | remove-pssession -Confirm:$false -ErrorAction ignore }
            else
            { return $session }
        }
    }

    # No valid PSSession found, create a new one
    if ($Credential -eq $null)
    { return (New-PSSession -ComputerName $ComputerName -ErrorAction Ignore) }
    else
    { return (New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Ignore) }
}

. ".\NetworkControllerRESTWrappers.ps1" -ComputerName $script:NetworkControllerRestIP -Username $script:NCUsername -Password $script:NCPassword

$virtualGatewayInfo = Get-NCVirtualGateway -resourceId $TenantName
if ($virtualGatewayInfo -eq $null)
{
    return
}

$gatewayResourceRefs = @($virtualGatewayInfo.properties.networkConnections.properties.gateway)
$gatewayResourceRefs = $gatewayResourceRefs | sort -Unique

$gatewayList = @()
foreach($gatewayResource in $gatewayResourceRefs)
{
    $tokens = $gatewayResource.resourceRef.split("/")
    $gatewayList += $tokens[2]
}
$gatewayList = $gatewayList | sort -Unique

Write-Verbose ("Failing Virtual Gateway for tenant $script:TenantName ...")

# Shut down the Gateway VM(s)
foreach($gateway in $gatewayList)
{
    # Get a remote PSSession
    $psSession = GetOrCreate-PSSession -ComputerName $gateway -Credential (GenerateCredentials -Username $script:NCUsername -Password $script:NCPassword)

    if ($psSession -ne $null)
    {
        # Restart the Gateway VM
        Invoke-Command -Session $psSession -ScriptBlock {Restart-Computer -Force} -ErrorAction continue

        Remove-PSSession -Session $psSession -Confirm:$false -ErrorAction Ignore
    }
}


$virtualGatewaysNotReady = $true
$virtualGatewayInfo      = $null
$gatewayResourceRefs     = @()

while ($virtualGatewaysNotReady)
{
    Write-Verbose ("Waiting for the NC to plumb the tenant network connections on new Cloud Gateway(s) ...")
    Start-Sleep 10

    # check the gateway(s) for assignment
    $virtualGatewayInfo  = Get-NCVirtualGateway -resourceID $script:TenantName
    $connectionCount     = $virtualGatewayInfo.properties.networkConnections.count
    $gatewayResourceRefs = @($virtualGatewayInfo.properties.networkConnections.properties.gateway)

    # Check if the virtual Gateway is ready
    if ($gatewayResourceRefs -ne $null -and $gatewayResourceRefs.count -eq $connectionCount)
    { $virtualGatewaysNotReady = $false }
}
