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

$crashDetected=$false
$hnsCrash=(Get-WinEvent -FilterHashtable @{logname = 'System'; ProviderName = 'Service Control Manager' } | Select-Object -Property TimeCreated, Id, LevelDisplayName, Message | Where-Object Message -like \"*The Host Network Service terminated unexpectedly*\").TimeCreated;
if($hnsCrash.Count -gt 0) {
    $crashDetected=$true
    # Log HNS Crashes
    $errStr += "HNS crash detected at ";
    foreach ($ts in $hnsCrash) {
        $errStr += "( "+$ts+" ) ";
    }
}

$errStr += "`nChecking for known issues that were handled... `n";
$isKnownCrash=$false;
foreach($fault in $fixedCrashes.GetEnumerator()) {
    $faultEvent=(Get-WinEvent -FilterHashtable @{logname = 'Microsoft-Windows-Host-Network-Service-Admin'  } | Select-Object -Property TimeCreated, Id, LevelDisplayName, Message | Where-Object Message -like $fault.faultStr).TimeCreated
    if ($faultEvent.Count -gt 0) {
        $isKnownCrash=$true;
        $errStr += "Bug #" + $fault.bugId + " gracefully handled at ";
        foreach ($ts in $faultEvent) {
            $errStr += "("+$ts+") ";
        }
        $errStr += "`n";
    }
}

if($isKnownCrash -eq false) {
    $errStr += "No known issues were hit`n"
}

if ($crashDetected -eq $false) {
    Write-Host "$(date) HNS crash not detected"
} else {
    Write-Host $errStr;
}
