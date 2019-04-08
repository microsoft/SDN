Param(
    #[switch] $init, No support for Windows Master
    [parameter(Mandatory = $false,HelpMessage="Print the help")]
    [switch] $help,
    [parameter(Mandatory = $false,HelpMessage="Install pre-requisites")]
    [switch] $InstallPrerequisite,
    [parameter(Mandatory = $false,HelpMessage="Join the windows node to the master")]
    [switch] $join,
    [parameter(Mandatory = $false,HelpMessage="Reset this windows node and cleanup everything")]
    [switch] $reset,
    [parameter(Mandatory = $false,HelpMessage="Path to install the binaries and scripts")] 
    $Destination = "C:\kubeadm",
    [parameter(Mandatory = $true,HelpMessage="Name or IpAddress of the master to fetch the configuration from")] 
    $Master,
    [parameter(Mandatory = $false,HelpMessage="Name of the interface to use")] 
    $InterfaceName = "Ethernet",
    [ValidateSet("dockerd", "containerd",IgnoreCase = $true)] 
    [parameter(Mandatory = $false,HelpMessage="Specify the container runtime to use")] 
    $Cri = "dockerd",
    [ValidateSet("flannel", "kubenet",IgnoreCase = $true)] 
    [parameter(Mandatory = $false,HelpMessage="CNI to use")] 
    $Cni = "flannel",
    [ValidateSet("bridge", "vxlan",IgnoreCase = $true)] 
    [parameter(Mandatory = $false,HelpMessage="Network plugin to deploy")] 
    $NetworkPlugin = "bridge",
    [ValidateSet("1.14.0", "1.13.0")] 
    [parameter(Mandatory = $false,HelpMessage="Kubernetes release version number")] 
    $Release = "1.14.0"
)

function Usage()
{
    $bin = $PSCommandPath 
    Get-Help $bin -Detailed

    $usage = "
    Usage: 
		$bin [-help] [-reset] [-join -cni <flannel/kubenet> -networkplugin <bridge/vxlan>] [-destination <InstallDestination>] [-release KUBE_RELEASE]

	Examples:
        $bin -help                                                           print this help
        $bin -reset                                                          reset the kubernetes cluster
        $bin -join -cni flannel -networkplugin bridge -release 1.14.0        joins the windows node to existing cluster     
        $bin -join -cni flannel -networkplugin vxlan  -release 1.14.0        joins the windows node to existing cluster
    "

    Write-Host $usage
}

function ValidateParams()
{
    if ($NetworkPlugin -eq "overlay" -and $cni -ne "flannel")
    {
        throw "Overlay plugin works only with flannel"
    }
}

######################################################################################################################

Write-Host "####################################"
Write-Host "User Input "
Write-Host "Destination       : $Destination"
Write-Host "Master            : $Master"
Write-Host "InterfaceName     : $InterfaceName"
Write-Host "Cri               : $Cri"
Write-Host "Cni               : $Cni"
Write-Host "NetworkPlugin     : $NetworkPlugin" 
Write-Host "Release           : $Release"
Write-Host "####################################"

ValidateParams
######################################################################################################################
# Download pre-req scripts
$BaseDir = $Destination
if (!(Test-Path $BaseDir))
{
    mkdir -p $BaseDir
}
$_GithubSDNRepository = 'Microsoft/SDN'
$_GithubSDNBranch = "master"
if ((Test-Path env:GITHUB_SDN_REPOSITORY) -and ($env:GITHUB_SDN_REPOSITORY -ne ''))
{
    $_GithubSDNRepository = $env:GITHUB_SDN_REPOSITORY
}

if ((Test-Path env:GITHUB_SDN_BRANCH) -and ($env:GITHUB_SDN_BRANCH -ne ''))
{
    $_GithubSDNBranch = $env:GITHUB_SDN_BRANCH
}

$helper = "$BaseDir\helper.v2.psm1"
if (!(Test-Path $helper))
{
    $url = "https://raw.githubusercontent.com/$_GithubSDNRepository/$_GithubSDNBranch/Kubernetes/windows/helper.v2.psm1"
    wget $url -o $BaseDir\helper.v2.psm1 -DisableKeepAlive -Verbose
}
ipmo $helper -DisableNameChecking
$Global:GithubSDNRepository = $_GithubSDNRepository
$Global:GithubSDNBranch = $_GithubSDNBranch
$Global:BaseDir = $Destination
InitHelper
$Global:Configuration = @{
    Destination = $Destination;
    Master      = $Master;
    InterfaceName = $InterfaceName;
    CRI = $Cri;
    CNI = $Cni;
    NetworkPlugin = $NetworkPlugin;
    Release = $Release;
}
WriteKubeadmConfig
# Initialize internal network modes of windows corresponding to 
# the plugin used in the cluster
$Global:NetworkName = "cbr0"
$Global:NetworkMode = "l2bridge"
if ($NetworkPlugin -eq "vxlan")
{
    $Global:NetworkMode = "overlay"
    $Global:NetworkName = "vxlan0"
}
######################################################################################################################

# Handle --help
if ($help.IsPresent)
{
    Usage
    exit
}

# Handle --InstallPrerequisite
if ($InstallPrerequisite.IsPresent)
{
    InstallContainersRole
    #InstallHypervRole
    $defaultValue = "Y"
    if (!(Test-Path $env:HOMEDRIVE/$env:HOMEPATH/.ssh/id_rsa.pub))
    {
        $res = Read-Host "Do you wish to generate a SSH Key & Add it to the Linux Master [Y/n] - Default [Y] : "
        if ($res -eq '' -or $res -eq 'Y'  -or $res -eq 'y')
        {
            ssh-keygen.exe
        }
    }

    $pubKey = Get-Content $env:HOMEDRIVE/$env:HOMEPATH/.ssh/id_rsa.pub
    Write-Host "Execute the below cmd in Linux Master($Master) to add this Windows Node's public key to its authorized keys"
    
    Write-Host "touch ~/.ssh/authorized_keys"
    Write-Host "echo $pubKey >> ~/.ssh/authorized_keys"

    $res = Read-Host "Continue to Reboot the host [Y/n] - Default [Y] : "
    if ($res -eq '' -or $res -eq 'Y'  -or $res -eq 'y')
    {
        Restart-Computer -Force
    }

    exit
}

# Handle -Join
if ($Join.IsPresent)
{
    $kubeConfig = GetKubeConfig
    if (!(KubeConfigExists))
    {
        # Fetch KubeConfig from the master
        DownloadKubeConfig -Master $Master
        if (!(KubeConfigExists))
        {
            throw $kubeConfig + " does not exist. Cannot connect to the master cluster"
        }
    }

    InstallCRI $Cri
    InstallKubernetesBinaries -Destination  $BaseDir -Release $Release

    # Validate connectivity with Master API Server
    $ManagementIp = Get-InterfaceIpAddress -InterfaceName $InterfaceName
    Write-Host "Trying to connect to the Kubernetes master"
    try {
        ReadKubeClusterInfo 
    } catch {
        throw "Unable to connect to the master. Reason [$_]"
    }

    $KubeDnsServiceIP = GetKubeDnsServiceIp
    $ClusterCIDR = GetClusterCidr
    $ServiceCIDR = GetServiceCidr
    
    Write-Host "####################################"
    Write-Host "Able to connect to the Master"
    Write-Host "Discovered the following"
    Write-Host "Cluster CIDR    : $ClusterCIDR"
    Write-Host "Service CIDR    : $ServiceCIDR"
    Write-Host "DNS ServiceIp   : $KubeDnsServiceIP"
    Write-Host "####################################"

    #
    # Install Services & Start in the below order
    # 1. Install & Start Kubelet
    InstallKubelet -KubeConfig $KubeConfig -CniDir $(GetCniPath) `
                -CniConf $(GetCniConfigPath) -KubeDnsServiceIp $KubeDnsServiceIp `
                -NodeIp $ManagementIp -KubeletFeatureGates $KubeletFeatureGates
    StartKubelet

    # 2. Install CNI & Start services
    InstallCNI -Cni $Cni -NetworkMode $Global:NetworkMode `
                  -ManagementIP $ManagementIp `
                  -InterfaceName $InterfaceName `
                  -CniPath $(GetCniPath)

    if ($Cni -eq "flannel")
    {
        CreateExternalNetwork -NetworkMode $Global:NetworkMode -InterfaceName $InterfaceName
        StartFlanneld 
        WaitForNetwork $Global:NetworkName
    }

    # 3. Install & Start Kubeproxy
    if ($NetworkMode -eq "overlay")
    {
        $sourceVip = GetSourceVip -NetworkName $Global:NetworkName
        InstallKubeProxy -KubeConfig $(GetKubeConfig) `
                -NetworkName $Global:NetworkName -ClusterCIDR  $ClusterCIDR `
                -SourceVip $sourceVip `
                -ProxyFeatureGates "WinOverlay=true"
    }
    else 
    {
        $env:KUBE_NETWORK=$Global:NetworkName
        InstallKubeProxy -KubeConfig $(GetKubeConfig) `
                -NetworkName $Global:NetworkName -ClusterCIDR  $ClusterCIDR
    }
    
    StartKubeproxy

    GetKubeNodes
    Write-Host "Node $(hostname) successfully joined the cluster"
}
# Handle -Reset
elseif ($Reset.IsPresent)
{
    if ((HasKubeadmConfig))
    {
        ReadKubeadmConfig
        if ($Global:Configuration.Keys)
        {
            # Initialize all global variables
            $Destination = $Global:Configuration["Destination"]
            $Global:Basedir = $Destination
            $Cni = $Global:Configuration["CNI"]
            $Global:NetworkName = $Global:Configuration["NetworkName"]
            $Global:NetworkMode = $Global:Configuration["NetworkMode"]
        }
    }
    RemoveKubeNode
    # Initiate cleanup
    CleanupOldNetwork $Global:NetworkName
    RemoveExternalNetwork
    UninstallCNI $Cni
    UninstallKubeProxy
    UninstallKubelet
    UninstallKubernetesBinaries -Destination  $Destination
    #UninstallCRI $Cri
    Remove-Item $Destination -ErrorAction SilentlyContinue
    Remove-Item $env:HOMEDRIVE\$env:HOMEPATH\.kube -ErrorAction SilentlyContinue
}
