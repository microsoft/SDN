$ZipPath = "Binaries.zip"
$DirPath = "Binaries"

$CreateZip = $true
$CopyBinaries = $true
$ReplaceHns = $true
$ReplaceVfpCtrl = $false
$ReplaceVfpExt = $false
$ReplaceVfpApi = $false
$ReplaceKubeProxy = $false
$ReplaceAzureVnet = $false
$SetRegKeys = $false

$HpcName = "hpc-ds-win22"
$Namespace = "demo"

$RegKeys = @(
    "reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns\State /v HNSLbNatDupRuleChange /t REG_DWORD /d 1 /f", 
    "reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VfpExt\Parameters /v VfpIpv6DipsPrintingIsEnabled /t REG_DWORD /d 1 /f",
    "reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns\State /v HnsTcpNodeToClusterIPChange /t REG_DWORD /d 1 /f"
)

function GetAllPodNames {
    param (
        [Parameter (Mandatory = $true)] [String]$namespace,
        [Parameter (Mandatory = $true)] [String]$daemonsetName
    )
    $podNames = @()
    $metadatas = ((kubectl get pods -n $namespace -o json | ConvertFrom-Json).Items).metadata
    foreach($metadata in $metadatas) { 
        if(($metadata.labels).Name -eq $daemonsetName ) { 
            $podNames += $metadata.name 
        } 
    }
    return $podNames
}

function ValidateBinariesDir {

    if((Test-Path $DirPath) -eq $false) {
        Write-Host "Missing dir [$DirPath] "
        return $false
    }

    $missingBins = @()
    $sfpcopyNeeded = $false

    if($ReplaceHns -and ((Test-Path $DirPath\hostnetsvc.dll) -eq $false)) {
        $missingBins += "hostnetsvc.dll"
    }

    if($ReplaceVfpCtrl -and ((Test-Path $DirPath\vfpctrl.exe) -eq $false)){
        $missingBins += "vfpctrl.exe"
    }

    if($ReplaceVfpExt -and ((Test-Path $DirPath\vfpext.sys) -eq $false)) {
        $missingBins += "vfpext.sys"
    }

    if($ReplaceVfpApi -and ((Test-Path $DirPath\vfpapi.dll) -eq $false)){
        $missingBins += "vfpapi.dll"
    }

    if($ReplaceKubeProxy -and ((Test-Path $DirPath\kube-proxy.exe) -eq $false)) {
        $missingBins += "kube-proxy.exe"
    }

    if($ReplaceAzureVnet -and ((Test-Path $DirPath\azure-vnet.exe) -eq $false)){
        $missingBins += "azure-vnet.exe"
    }

    if($ReplaceHns -or $ReplaceVfpCtrl -or $ReplaceVfpExt -or $ReplaceVfpApi -or $ReplaceKubeProxy) {
        $sfpcopyNeeded = $true
    }

    if($sfpcopyNeeded -and ((Test-Path $DirPath\sfpcopy.exe) -eq $false)) {
        $missingBins += "sfpcopy.exe"
    }

    if($missingBins.Count -gt 0) {
        Write-Host "Missing binaries in dir [$DirPath] : $missingBins"
        return $false
    }

    return $true
}

if($CreateZip) {
    if(!(ValidateBinariesDir)) {
        return
    }
    Write-Host "Creating Binary zip."
    Remove-Item -Recurse -Force $ZipPath -ErrorAction Ignore
    Compress-Archive -Path $DirPath -DestinationPath $ZipPath
}

$allHpcPods = GetAllPodNames -namespace $Namespace -daemonsetName $HpcName
foreach($hpcPod in $allHpcPods) {

    Write-Host "Setting up host pod : $hpcPod"
    if($CopyBinaries) {
        Write-Host "Cleaning up existing binaries : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command rm -r -Force $ZipPath -ErrorAction Ignore
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command rm -r -Force Binaries -ErrorAction Ignore
        Write-Host "Copying binaries to : $hpcPod"
        kubectl cp .\$ZipPath $hpcPod`:$ZipPath -n $Namespace
        Start-Sleep -Seconds 1
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Expand-Archive -Path $ZipPath -DestinationPath .
    }
    
    # Taking Backup of originals
    $origDirExists = kubectl exec $hpcPod -n $Namespace -- powershell -command Test-Path orig
    if($origDirExists -eq $false) {
        Write-Host "Taking backup of original binaries : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command mkdir orig
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\k\azure-vnet.json .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\k\azurecni\netconf\10-azure.conflist .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\Windows\system32\vfpctrl.exe .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\Windows\system32\hostnetsvc.dll .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\k\azurecni\bin\azure-vnet.exe .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\Windows\system32\drivers\vfpext.sys .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\Windows\system32\vfpapi.dll .\orig\
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp C:\k\kube-proxy.exe .\orig\
    }

    if($SetRegKeys) {
        Write-Host "Setting up host pod reg keys : $hpcPod"
        foreach($key in $RegKeys) {
            kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command $key
        }
        Write-Host "Reg keys set : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns\State
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VfpExt\Parameters
    }

    if($ReplaceAzureVnet) {
        Write-Host "Replacing azure vnet in : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command cp .\Binaries\azure-vnet.exe C:\k\azurecni\bin\azure-vnet.exe
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command rm C:\k\azure-vnet.json -ErrorAction Ignore
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command "Get-HnsNetwork | Where name -eq azure | Remove-HnsNetwork"
        Write-Host "FileHash for azure vnet : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-FileHash C:\k\azurecni\bin\azure-vnet.exe
    }

    if($ReplaceHns) {
        Write-Host "Replacing hns in : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command .\Binaries\sfpcopy.exe .\Binaries\HostNetSvc.dll C:\Windows\system32\hostnetsvc.dll
        Start-Sleep -Seconds 3
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Restart-Service -f hns
        Start-Sleep -Seconds 2
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-Service hns
        Write-Host "FileHash for hns : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-FileHash C:\Windows\system32\hostnetsvc.dll
    }

    if($ReplaceVfpExt) {
        Write-Host "Replacing vfpext.sys in : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command .\Binaries\sfpcopy.exe .\Binaries\vfpext.sys C:\Windows\system32\drivers\vfpext.sys
        Start-Sleep -Seconds 2
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Restart-Service -f vfpext
        Start-Sleep -Seconds 2
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-Service vfpext
        Write-Host "FileHash for vfpext.sys : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-FileHash C:\Windows\system32\drivers\vfpext.sys
    }

    if($ReplaceVfpApi) {
        Write-Host "Replacing vfpapi.dll in : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command .\Binaries\sfpcopy.exe .\Binaries\vfpapi.dll C:\Windows\system32\vfpapi.dll
        Write-Host "FileHash for vfpapi.dll : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-FileHash C:\Windows\system32\vfpapi.dll
    }

    if($ReplaceVfpCtrl) {
        Write-Host "Replacing vfpctrl in : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command .\Binaries\sfpcopy.exe .\Binaries\vfpctrl.exe C:\Windows\system32\vfpctrl.exe
        Write-Host "FileHash for vfpctrl : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-FileHash C:\Windows\system32\vfpctrl.exe
    }

    if($ReplaceKubeProxy) {
        Write-Host "Replacing KubeProxy in : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command .\Binaries\sfpcopy.exe .\Binaries\kube-proxy.exe C:\k\kube-proxy.exe
        Start-Sleep -Seconds 2
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Restart-Service -f kubeproxy
        Start-Sleep -Seconds 2
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-Service kubeproxy
        Write-Host "FileHash for KubeProxy : $hpcPod"
        kubectl exec $hpcPod -n $Namespace -- powershell -ExecutionPolicy Unrestricted -command Get-FileHash C:\k\kube-proxy.exe
    }

    Write-Host "Setting up host pod : $hpcPod completed"
}
