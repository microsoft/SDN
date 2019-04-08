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
    [parameter(Mandatory = $true,HelpMessage="Path to input configuration json ")] 
    $ConfigFile
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
        $bin -join -ConfigFile kubecluster.json                              joins the windows node to existing cluster
    "

    Write-Host $usage
}

function ReadKubeclusterConfig($ConfigFile)
{
    # Read the configuration and initialize default values if not found
    $Global:ClusterConfiguration = ConvertFrom-Json ((GetFileContent $ConfigFile -ErrorAction Stop) | out-string)
    if (!$Global:ClusterConfiguration.Install)
    {
        $Global:ClusterConfiguration += @{
            Install = @{
                Destination = "$env:HOMEDRIVE\$env:HOMEPATH\kubeadm";
                Source = @{
                    SDNRepo = "Microsoft/SDN";
                    SDNBranch = "master";
                }
            }
        }
    }
    if (!$Global:ClusterConfiguration.Kubernetes)
    {
        throw "Master information missing in the configuration file"
    }
    if (!$Global:ClusterConfiguration.Kubernetes.Release)
    {
        $Global:ClusterConfiguration.Kubernetes += @{
            Release = "1.14.0";
        }
    }
    if (!$Global:ClusterConfiguration.Kubernetes.Master)
    {
        throw "Master information missing in the configuration file"
    }

    if (!$Global:ClusterConfiguration.Cni)
    {
        $Global:ClusterConfiguration += @{
            Cni = @{
                Name = "flannel";
                Plugin = @{
                    Name = "vxlan";
                };
                InterfaceName = "Ethernet";
            }
        }
    }

    if (!$Global:ClusterConfiguration.Cri)
    {
        $Global:ClusterConfiguration += @{
            Cri = @{
                Name = "dockerd";
                Images = @{
                    Nanoserver = "mcr.microsoft.com/windows/nanoserver:1809";
                    ServerCore = "mcr.microsoft.com/windows/servercore:ltsc2019";
                }
            }
        }
    }
    
}

function LoadPsm1($Path)
{
    $tmpPath = [io.Path]::Combine([System.IO.Path]::GetTempPath(), [io.path]::GetFileName($Path))
    wget $Path -o $tmpPath
    ipmo $tmpPath  -DisableNameChecking
    Remove-Item $tmpPath
}

###############################################################################################
# Download pre-req scripts
$BaseDir = [System.IO.Path]::GetTempPath()
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

LoadPsm1 -Path "https://raw.githubusercontent.com/$_GithubSDNRepository/$_GithubSDNBranch/Kubernetes/windows/helper.v2.psm1"
LoadPsm1 -Path "https://raw.githubusercontent.com/$_GithubSDNRepository/$_GithubSDNBranch/Kubernetes/windows/hns.psm1"

ReadKubeclusterConfig -ConfigFile $ConfigFile
InitHelper
PrintConfig
WriteKubeadmConfig


# Initialize internal network modes of windows corresponding to 
# the plugin used in the cluster
$Global:NetworkName = "cbr0"
$Global:NetworkMode = "l2bridge"
if ($Global:NetworkPlugin -eq "vxlan")
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
    Write-Host "Execute the below cmd in Linux Master($Global:MasterIp) to add this Windows Node's public key to its authorized keys"
    
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
        DownloadKubeConfig -Master $Global:MasterIp -User $Global:MasterUsername
        if (!(KubeConfigExists))
        {
            throw $kubeConfig + " does not exist. Cannot connect to the master cluster"
        }
    }

    InstallCRI $Global:Cri
    InstallKubernetesBinaries -Destination  $Global:BaseDir -Release $Global:Release

    # Validate connectivity with Master API Server
    $ManagementIp = Get-InterfaceIpAddress -InterfaceName $Global:InterfaceName
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
    InstallCNI -Cni $Global:Cni -NetworkMode $Global:NetworkMode `
                  -ManagementIP $ManagementIp `
                  -InterfaceName $Global:InterfaceName `
                  -CniPath $(GetCniPath)

    if ($Global:Cni -eq "flannel")
    {
        CreateExternalNetwork -NetworkMode $Global:NetworkMode -InterfaceName $Global:InterfaceName
        StartFlanneld 
        WaitForNetwork $Global:NetworkName
    }

    # 3. Install & Start Kubeproxy
    if ($Global:NetworkMode -eq "overlay")
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
    ReadKubeadmConfig
    
    RemoveKubeNode
    # Initiate cleanup
    CleanupOldNetwork $Global:NetworkName
    RemoveExternalNetwork
    UninstallCNI $Global:Cni
    UninstallKubeProxy
    UninstallKubelet
    UninstallKubernetesBinaries -Destination  $Global:BaseDir
    #UninstallCRI $Cri
    Remove-Item $Global:BaseDir -ErrorAction SilentlyContinue
    Remove-Item $env:HOMEDRIVE\$env:HOMEPATH\.kube -ErrorAction SilentlyContinue
}
