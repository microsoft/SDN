 [CmdletBinding()]  
 param(  
        [string][parameter(Mandatory=$false, HelpMessage="Network controller Base REST URI e.g. https://192.168.0.4")]$NcURI
            = 'https://sa18n30nc.sa18.nttest.microsoft.com'
    )

$headers = @{"Accept"="application/json"}
$content = "application/json; charset=UTF-8"
$network = "$NCURI/Networking/v1"
$slbStateRetry = 30
$maxRetryCount = 20

$method = "Put"
$uri = "$network/diagnostics/slbstate"

$body = '{"properties": { }}'

try
{

    $result = Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -Body $body -DisableKeepAlive -UseBasicParsing -UseDefaultCredentials
    $result.Content
    $resultObject = ConvertFrom-Json  $result.Content
    $resultsUri = $network + $resultObject.properties.slbStateResult.resourceRef

    $totalWait=0

    do
    {
      $totalWait += $slbStateRetry
      Write-Host ">>> Sleeping ... for $slbStateRetry seconds ..."
      Start-Sleep -Seconds $slbStateRetry
      Write-Host ">>> Polling ... $resultsUri"
      $tempResult = Invoke-WebRequest -Headers $headers -Method GET -Uri $resultsUri -UseBasicParsing -UseDefaultCredentials
      $tempResultObject = ConvertFrom-Json  $tempResult.Content
      Write-Host ">>> $(Get-Date -Format G) Current State: $($tempResultObject.properties.provisioningState)"
    }
    until (($tempResultObject.properties.provisioningState) -ne "Updating" -or $totalWait -gt $slbStateRetry * $maxRetryCount)

    $fileName = "stateOp_" + [System.Math]::Truncate((Get-Date -UFormat %s)) + ".txt"
    $tempResult.Content > $fileName
    Write-Host "Success output written to $fileName" -ForegroundColor Green
}

catch
{
    Write-Error "Failed $_"
    throw
}