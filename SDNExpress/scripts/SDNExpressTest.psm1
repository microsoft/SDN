function New-ASLocalSupplementalPolicy
{
param
(
    [string]
    [Parameter(Mandatory=$true)]
    $ScanPath,

    [string]
    [Parameter(Mandatory=$true)]
    $PolicyGuid
 )
 Write-Verbose "Create supplemental policy for $ScanPath" -Verbose
 if (Test-Path "$PSScriptRoot\policy.xml")
 {
    Get-Item "$PSScriptRoot\policy.xml" | Remove-Item -Recurse
 }
 New-CIPolicy -MultiplePolicyFormat -ScanPath $ScanPath -UserPEs -FilePath "$PSScriptRoot\policy.xml" -Level Publisher -Fallback Hash
 Set-CIPolicyIdInfo -FilePath "$PSScriptRoot\policy.xml" -SupplementsBasePolicyID '{A6368F66-E2C9-4AA2-AB79-8743F6597683}'
 $policyContent = Get-Content "$PSScriptRoot\policy.xml"
 $policyXml = [xml]$policyContent
 $policyContent -Replace $policyXml.SiPolicy.PolicyID,$PolicyGuid | Out-File "$PSScriptRoot\policy.xml" -encoding "UTF8"
 ConvertFrom-CIPolicy -XmlFilePath "$PSScriptRoot\policy.xml" -BinaryFilePath "$PSScriptRoot\$PolicyGuid.cip" | Out-Null
 Write-Verbose -Verbose "Generate supplemental policy $PolicyGuid"
 Copy-Item -Path "$PSScriptRoot\$PolicyGuid.cip" -Destination "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
}

Export-ModuleMember -Function New-ASLocalSupplementalPolicy
#New-ASLocalSupplementalPolicy -ScanPath "C:\Windows\System32" -PolicyGuid '{9A438E45-7865-4848-8AA1-F1D6D0A1BDA8}'