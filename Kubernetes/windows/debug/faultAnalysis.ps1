# Enlist the fixed crashes to detect codepath execution
$fixedCrashes = @(
    [pscustomobject]@{
        faultStr='*ElbDsrPolicy-Update-Failure*';
        bugId='41071049';
    },
    [pscustomobject]@{
        faultStr='*Network-Not-Found*';
        bugId='42521831';
    }
)

$errStr=""
$crashDetected=$false
$hnsCrash=(Get-WinEvent -FilterHashtable @{logname = 'System'; ProviderName = 'Service Control Manager' } | Select-Object -Property TimeCreated, Message | Where-Object Message -like "*The Host Network Service terminated unexpectedly*").TimeCreated;
if($hnsCrash.Count -gt 0) {
    $crashDetected=$true
    # Log HNS Crashes
    $errStr += "HNS crash detected at ";
    foreach ($ts in $hnsCrash) {
        $errStr += "("+$ts+") ";
    }
    $errStr += "`n";
}

foreach($fault in $fixedCrashes.GetEnumerator()) {
    $faultEvent=(Get-WinEvent -FilterHashtable @{logname = 'Microsoft-Windows-Host-Network-Service-Admin'  } | Select-Object -Property TimeCreated, Message | Where-Object Message -like $fault.faultStr).TimeCreated
    if ($faultEvent.Count -gt 0) {
        $errStr += "Bug #" + $fault.bugId + " gracefully handled at ";
        foreach ($ts in $faultEvent) {
            $errStr += "("+$ts+") ";
        }
        $errStr += "`n";
    }
}

if ($crashDetected -eq $false) {
    Write-Host "$(date) HNS crash not detected"
}

Write-Host $errStr;
