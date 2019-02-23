
[CmdletBinding(PositionalBinding=$false)]
Param
(
    [parameter(ParameterSetName='Default', Mandatory = $true, HelpMessage='Kubernetes Config File')] [string]$ConfigFile,
    [parameter(ParameterSetName='Default', Mandatory = $false, HelpMessage='Kubernetes cluster cidr')] [string]$ClusterCIDR,
    [parameter(ParameterSetName='Default', Mandatory = $false, HelpMessage='Kubernetes pod service cidr')] [string]$ServiceCIDR,
    [parameter(ParameterSetName='Default', Mandatory = $false, HelpMessage='Kubernetes DNS Ip')] [string]$KubeDnsServiceIP,
    [parameter(ParameterSetName='Default', Mandatory = $false, HelpMessage='Kubernetes version to download')] [string]$KubernetesVersion = "1.13.3",
    [parameter(ParameterSetName='Default', Mandatory = $false, HelpMessage='Skip downloading binaries')] [switch] $SkipInstall,

    [parameter(ParameterSetName='OnlyInstall', Mandatory = $true)] [switch] $OnlyInstall
)
$ProgressPreference = 'SilentlyContinue'

$kubernetesPath = "C:\k"
$cniDir = Join-Path $kubernetesPath cni
$cniConfigDir = Join-Path $cniDir config
$containerdPath = "$Env:ProgramFiles\containerd"
$flanneldPath = "C:\flannel"
$flanneldConfPath = "C:\etc\kube-flannel"
$lcowPath = "$Env:ProgramFiles\Linux Containers"

$networkMode = "L2Bridge"
$networkName = "cbr0"
$kubeDnsSuffix="svc.cluster.local"
$kubeletConfigPath = Join-Path $kubernetesPath "kubelet-config.yaml"
$cniConfig = Join-Path $cniConfigDir "cni.conf"

# create all the necessary directories if they don't already exist
New-Item -ItemType Directory -Path $kubernetesPath -Force > $null
New-Item -ItemType Directory -Path $cniConfigDir -Force > $null
New-Item -ItemType Directory -Path $containerdPath -Force > $null
New-Item -ItemType Directory -Path $flanneldPath -Force > $null
New-Item -ItemType Directory -Path $flanneldConfPath -Force > $null
New-Item -ItemType Directory -Path $lcowPath -Force > $null

# Setup functions

Function GetHelper() {
    $helper = Join-Path $kubernetesPath helper.psm1
    if (!(Test-Path $helper))
    {
        Start-BitsTransfer https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -Destination $helper
    }
    Import-Module $helper
}

Function DownloadAllFiles() {
    # download k8s binaries
    DownloadFile "https://storage.googleapis.com/kubernetes-release/release/v$KubernetesVersion/bin/windows/amd64/kubeadm.exe" (Join-Path $kubernetesPath kubeadm.exe)
    DownloadFile "https://storage.googleapis.com/kubernetes-release/release/v$KubernetesVersion/bin/windows/amd64/kubectl.exe" (Join-Path $kubernetesPath kubectl.exe)
    DownloadFile "https://storage.googleapis.com/kubernetes-release/release/v$KubernetesVersion/bin/windows/amd64/kubelet.exe" (Join-Path $kubernetesPath kubelet.exe)
    DownloadFile "https://storage.googleapis.com/kubernetes-release/release/v$KubernetesVersion/bin/windows/amd64/kube-proxy.exe" (Join-Path $kubernetesPath kube-proxy.exe)

    # download cni binaries
    DownloadFile https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe $cniDir\flannel.exe
    DownloadFile https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe $cniDir\host-local.exe
    DownloadFile https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/win-bridge.exe $cniDir\win-bridge.exe

    # download available cri binaries
    if(-not (Test-Path (Join-Path $containerdPath crictl.exe))) {
        Write-Output "Downloading crictl"
        DownloadAndExtractTarGz https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.13.0/crictl-v1.13.0-windows-amd64.tar.gz $containerdPath
    }
    DownloadFile https://github.com/Microsoft/hcsshim/releases/download/v0.8.4/runhcs.exe $containerdPath\runhcs.exe

    # download SDN scripts and configs
    DownloadFile https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 (Join-Path $kubernetesPath hns.psm1)
    DownloadFile https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/net-conf.json (Join-Path $kubernetesPath net-conf.json)
    Copy-Item (Join-Path $kubernetesPath net-conf.json) $flanneldConfPath

    # download flannel
    DownloadFile https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe (Join-Path $kubernetesPath flanneld.exe)
    Copy-Item (Join-Path $kubernetesPath flanneld.exe) $flanneldPath

    # download containerd's config
    DownloadFile https://github.com/Microsoft/SDN/raw/master/Kubernetes/containerd/containerd-config.toml $containerdPath\config.toml

    # download LCOW
    if(-not (Test-Path (Join-Path $lcowPath kernel))) {
        Write-Output "Downloading LCOW"
        DownloadAndExtractZip https://github.com/linuxkit/lcow/releases/download/v4.14.35-v0.3.9/release.zip  $lcowPath
    }
}

Function UpdateCrictlConfig() {
    # set crictl to access the configured container endpoint by default
    $crictlConfigDir = Join-Path  $env:USERPROFILE ".crictl"
    $crictlConfigPath = Join-Path $crictlConfigDir "crictl.yaml"

    if(Test-Path $crictlConfigPath) {
        return;
    }

    Write-Output "Updating crictl config"
    New-Item -ItemType Directory -Path $crictlConfigDir -Force > $null
@"
runtime-endpoint: npipe:\\\\.\pipe\containerd-containerd
image-endpoint: npipe:\\\\.\pipe\containerd-containerd
timeout: 0
debug: false
"@ | Out-File $crictlConfigPath
}

Function UpdateEnv() {
    # update the path variable if it doesn't have the needed paths
    $path = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    $updated = $false
    if(-not ($path -match $kubernetesPath.Replace("\","\\")+"(;|$)"))
    {
        $path += ";"+$kubernetesPath
        $updated = $true
    }
    if(-not ($path -match $containerdPath.Replace("\","\\")+"(;|$)"))
    {
        $path += ";"+$containerdPath
        $updated = $true
    }
    if($updated)
    {
        Write-Output "Updating path"
        [Environment]::SetEnvironmentVariable("Path", $path, [EnvironmentVariableTarget]::Machine)
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    }

    # update the kubeconfig env variable
    $env:KUBECONFIG = (Join-Path $kubernetesPath "config")
    [Environment]::SetEnvironmentVariable("KUBECONFIG", $env:KUBECONFIG, [EnvironmentVariableTarget]::User)

    # update the NODE_NAME env variable, needed for flanneld
    $env:NODE_NAME = (hostname).ToLower()
    [Environment]::SetEnvironmentVariable("NODE_NAME", $env:NODE_NAME, [EnvironmentVariableTarget]::User)

    # update the KUBE_NETWORK env variable, needed for kubeproxy
    $env:KUBE_NETWORK=$networkName.ToLower()
    [Environment]::SetEnvironmentVariable("KUBE_NETWORK", $env:KUBE_NETWORK, [EnvironmentVariableTarget]::User)
}

Function CreateKubeletConfig() {
    if(Test-Path $kubeletConfigPath) {
        return;
    }

    Write-Output "Updating kubelet config"
@"
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
featureGates:
    RuntimeClass: true
runtimeRequestTimeout: 20m
resolverConfig: ""
enableDebuggingHandlers: true
clusterDomain: "cluster.local"
hairpinMode: "promiscuous-bridge"
cgroupsPerQOS: false
enforceNodeAllocatable: []
"@ | Out-File $kubeletConfigPath
}

Function RegisterContainerDService() {
    Assert-FileExists (Join-Path $containerdPath containerd.exe)

    Write-Host "Registering containerd as a service"
    $cdbinary = Join-Path $containerdPath containerd.exe
    $svc = Get-Service -Name containerd -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        & $cdbinary --unregister-service
    }
    & $cdbinary --register-service
    $svc = Get-Service -Name "containerd" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        throw "containerd.exe did not get installed as a service correctly."
    }
}

Function IsContainerDUp() {
    return get-childitem \\.\pipe\ | ?{ $_.name -eq "containerd-containerd" }
}

# Deployment functions

Function Update-CNIConfig() {
    $jsonSampleConfig = @"
{
  "cniVersion": "0.2.0",
  "name": "<NetworkMode>",
  "type": "flannel",
  "delegate": {
    "ApiVersion": 2,
    "type": "<BridgeCNI>",
      "dns" : {
        "Nameservers" : [ "10.96.0.10" ],
        "Search": [ "svc.cluster.local" ]
      },
      "HcnPolicyArgs" : [
        {
          "Type" : "OutBoundNAT", "Settings" : { "Exceptions": [ "<ClusterCIDR>", "<ServerCIDR>", "<MgmtSubnet>" ] }
        },
        {
          "Type" : "SDNRoute", "Settings" : { "DestinationPrefix": "<ServerCIDR>", "NeedEncap" : true }
        },
        {
          "Type" : "SDNRoute", "Settings" : { "DestinationPrefix": "<MgmtIP>/32", "NeedEncap" : true }
        }
      ]
    }
}
"@
    $configJson =  ConvertFrom-Json $jsonSampleConfig
    $configJson.name = $networkName
    $configJson.delegate.type = "win-bridge"
    $configJson.delegate.dns.Nameservers[0] = $KubeDnsServiceIP
    $configJson.delegate.dns.Search[0] = $kubeDnsSuffix

    $configJson.delegate.HcnPolicyArgs[0].Settings.Exceptions[0] = $clusterCIDR
    $configJson.delegate.HcnPolicyArgs[0].Settings.Exceptions[1] = $serviceCIDR
    $configJson.delegate.HcnPolicyArgs[0].Settings.Exceptions[2] = Get-MgmtSubnet

    $configJson.delegate.HcnPolicyArgs[1].Settings.DestinationPrefix  = $serviceCIDR
    $configJson.delegate.HcnPolicyArgs[2].Settings.DestinationPrefix  = "$(Get-HnsMgmtIpAddress)/32"

    if (Test-Path $cniConfig) {
        Clear-Content -Path $cniConfig
    }

    Write-Host "Generated CNI Config [$configJson]"
    Add-Content -Path $cniConfig -Value (ConvertTo-Json $configJson -Depth 20)
}

if(-not $SkipInstall) {
    # ask to install 7zip, if it's not already installed
    if (-not (Get-Command Expand-7Zip -ErrorAction Ignore)) {
        $confirmation = Read-Host "7Zip4PowerShell is required to extract some packages but it is not installed, would you like to install it? (y/n)"
        if ($confirmation -ne 'y') {
            Write-Error "Aborting setup"
            Exit 1
        }
        Install-Package -Scope CurrentUser -Force 7Zip4PowerShell > $null
        if(-not $?) {
            Write-Error "Failed to install package"
            Exit 1
        }
    }

    GetHelper
    DownloadAllFiles
    UpdateCriCtlConfig
    UpdateEnv
    RegisterContainerDService
    CreateKubeletConfig
}

if($OnlyInstall) {
    Exit
}

Assert-FileExists (Join-Path $containerdPath containerd.exe)
Assert-FileExists (Join-Path $containerdPath containerd-shim-runhcs-v1.exe)
Assert-FileExists (Join-Path $containerdPath ctr.exe)

# copy the config file
Copy-Item $ConfigFile $env:KUBECONFIG
New-Item -ItemType Directory -Path $home\.kube -Force > $null
Copy-Item $env:KUBECONFIG $home\.kube\

Write-Output "Getting cluster properties"

# get the cluster cidr
if($ClusterCIDR.Length -eq 0) {
    $ccFlag = (kubectl describe pod kube-controller-manager- -n kube-system | ? { $_.Contains("--cluster-cidr") })
    if(-not $? -or $ccFlag.Length -eq 0) {
        Write-Error "Unable to get cluster cidr from config, please set -ClusterCIDR manually"
        Exit 1
    }
    $ClusterCIDR = $ccFlag.SubString($ccFlag.IndexOf("=")+1)
    Write-Output "Using cluster cidr $ClusterCIDR"
}

# get the service cidr
if($ServiceCIDR.Length -eq 0) {
    $scFlag = (kubectl describe pod kube-apiserver- -n kube-system | ? { $_.Contains("--service-cluster-ip-range") })
    if(-not $? -or $scFlag.Length -eq 0) {
        Write-Error "Unable to get service cidr from config, please set -ServiceCIDR manually"
        Exit 1
    }
    $ServiceCIDR = $scFlag.SubString($scFlag.IndexOf("=")+1)
    Write-Output "Using service cidr $ServiceCIDR"
}

# get the dns ip
if($KubeDnsServiceIP.Length -eq 0) {
    $KubeDnsServiceIP = kubectl get svc/kube-dns -o jsonpath='{.spec.clusterIP}' -n kube-system
    if(-not $? -or $KubeDnsServiceIP.Length -eq 0) {
        Write-Error "Unable to get dns ip from config, please set -KubeDnsServiceIP manually"
        Exit 1
    }
    Write-Output "Using dns ip $KubeDnsServiceIP"
}

# get the management ip
if($ManagementIP.Length -eq 0) {
    $na = Get-NetAdapter -InterfaceIndex (Get-WmiObject win32_networkadapterconfiguration | Where-Object {$_.defaultipgateway -ne $null}).InterfaceIndex
    $ManagementIP = (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4).IPAddress
    if(-not $? -or $ManagementIP.Length -eq 0) {
        Write-Error "Unable to get dns ip from config, please set -ManagementIP manually"
        Exit 1
    }
    Write-Output "Using management ip $ManagementIP"
}

#start containerd
if(-not (IsContainerDUp)) {
    Write-Output "Starting containerd"
    Start-Service -Name "containerd"
    if(-not $?) {
        Write-Error "Unable to start containerd"
        Exit 1
    }
}

# wait for containerd to accept inputs, otherwise kubectl will close immediately
Start-Sleep 1
while(-not (IsContainerDUp)) {
    Write-Output "Waiting for containerd to start"
    Start-Sleep 1
}

# prepare network & start infra services
Write-Output "Clearing old network and registering node"
CleanupOldNetwork $networkName $false
RegisterNode $true
Import-Module (Join-Path $kubernetesPath hns.psm1) -DisableNameChecking

# Create a L2Bridge to trigger a vSwitch creation. Do this only once as it causes network blip
Write-Output "Creating network"
if(!(Get-HnsNetwork | Where-Object Name -EQ "External")) {
    New-HNSNetwork -Type $networkMode -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
}
Start-Sleep 5

# Stop any running processes
StopKubeProcesses

# Start FlannelD, which would recreate the network. Expect disruption in node connectivity for few seconds
Write-Output "Starting flanneld"
Start-Process (Join-Path $flanneldPath flanneld.exe) -ArgumentList "--kubeconfig-file=$($env:KUBECONFIG) --iface=$ManagementIP --ip-masq=1 --kube-subnet-mgr=1" -NoNewWindow

# Wait till the network is available
while( !(Get-HnsNetwork -Verbose | Where-Object Name -EQ $networkName.ToLower()) ) {
    Write-Host "Waiting for the Network to be created"
    Start-Sleep 1
}

# Start kubelet
Write-Output "Starting kubelet"
Update-CNIConfig

Start-Process powershell -ArgumentList "-c","$(Join-Path $kubernetesPath kubelet.exe) --config=$kubeletConfigPath --kubeconfig=$env:KUBECONFIG --hostname-override=$(hostname) --cluster-dns=$KubeDnsServiceIp --v=6 --log-dir=$kubernetesPath --logtostderr=false --network-plugin=cni --cni-bin-dir=$cniDir --cni-conf-dir $cniConfigDir --container-runtime=remote --container-runtime-endpoint='npipe:////./pipe/containerd-containerd'"
Start-Sleep 10

# Start kube-proxy
Write-Output "Starting kubeproxy"
Get-HnsPolicyList | Remove-HnsPolicyList
Start-Process powershell -ArgumentList "-c","$(Join-Path $kubernetesPath kube-proxy.exe) --kubeconfig=$env:KUBECONFIG --hostname-override=$(hostname) --proxy-mode=kernelspace --v=4"
