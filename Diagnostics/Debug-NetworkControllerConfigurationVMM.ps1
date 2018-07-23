# Copyright (C) Microsoft Corporation.  All rights reserved.

function Debug-NetworkControllerConfigurationState
{
    [CmdletBinding()]
    Param (
        [string]
        [parameter(Mandatory = $true)]
        $NcIpAddress,
        [string]
        [parameter(Mandatory = $false)]
        $ResourceId="",
        [string]
        [parameter(Mandatory = $false)]
        $ResourceType=""
        )

    $headers = @{"Accept"="application/json"}
    $content = "application/json; charset=UTF-8"
    $network = "https://$($NcIpAddress)/Networking/v1"
    $timeout = 10
    $method = "Get"

    $resTypes = @("accessControlLists", "servers", "virtualNetworks", "networkInterfaces", "virtualGateways", "loadbalancerMuxes")
   
    if ([string]::IsNullOrEmpty($ResourceType) -eq $false)
    {
        $resTypes = @("$($ResourceType)");
    }

    foreach ($resType in $resTypes)
    {
        try
        {
            $resources = Invoke-RestMethod -Headers $headers -ContentType $content -Method $method -Uri $network/$resType -DisableKeepAlive -UseBasicParsing -UseDefaultCredentials
            
            foreach ($resource in $resources.value)
            {

                if ([string]::IsNullOrEmpty($ResourceId) -eq $false)
                {
                    if ([string]::Compare($ResourceId, $resource.resourceId) -ne 0)
                    {
                        continue;
                    }
                }

                $fullUri = $network + $resource.resourceRef
                $a = Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $fullUri -DisableKeepAlive -UseBasicParsing -UseDefaultCredentials
                $myObj =  $a.Content | ConvertFrom-Json
                
                if ($myObj -ne $null)
                {
                    if ($myObj.properties.ConfigurationState -ne $null)
                    {
                        if($myObj.properties.ConfigurationState.Status -eq "Success")
                        {
                            continue;
                        }

                        Write-Output "---------------------------------------------------------------------------------------------------------";
                        Write-Output "ResourcePath:     $($fullUri)";
                        Write-Output "Status:           $($myObj.resourcemetadata.resourcename)";
                        Write-Output "Status:           $($myObj.properties.ConfigurationState.Status)";

                        if ($myObj.properties.ConfigurationState.detailedInfo -ne $null)
                        {
                            foreach($errorInfo in $myObj.properties.ConfigurationState.detailedInfo)
                            {
                                Write-Output " "   
                                Write-Output "Source:           $($errorInfo.source)";
                                Write-Output "Code:             $($errorInfo.code)";
                                Write-Output "Message:          $($errorInfo.message)";
                            }
                        }

                        Write-Output "----------------------------------------------------------------------------------------------------------";
                    }
                }

            }
        }
        catch
        {
            Write-Host $_
        }
    }
}
Debug-NetworkControllerConfigurationState
