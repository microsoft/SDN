How to join a Windows node to a Linux Master using KubeCluster.ps1
==================================================================

Min. Windows Operating System Version : 1809 (Tested).

## Install Pre-Requisite 
    This option would do the following.

    a. This step would **generate** a SSH key for the windows node and asks the user to add it to the master
    b. This step would **install** containers role. [If containers role was already installed, nothing is done here]
    c. A prompt to **restart** the computer, if required (Required when Containers feature is installed.)

    Optionally you can also run this script on a machine, which has containers role, docker and docker images installed. In that case, this option would help generate ssh keys for the windows node.

    d. Usage
        cd  $env:HOMEDRIVE\$env:HOMEPATH
        wget  https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/KubeCluster.ps1 -o kubecluster.ps1
        $env:GITHUB_SDN_REPOSITORY="Microsoft/SDN"
        $env:GITHUB_SDN_BRANCH="master"
       	$env:MASTER_USERNAME="localadmin"
        $env:DOCKER_IMAGE_TAG="insider"

        .\KubeCluster.ps1 -InstallPrerequisite -Master <IpAddressOfMaster> -Destination $env:HOMEDRIVE\$env:HOMEPATH\kubeadm
        <The machine might need to be rebooted, if containers role was installed. If not, you can say no>

## Join node to Master
    This option would do the following
    
    a. Install CRI (docker), if not already present
    b. Install Kubernetes binaries from the specified Release param
    c. Downloads the kube config from the master. If no auth is set, it would prompt for the password
    d. Install & Start Kubelet service.
    e. Install CNI & Configurations. Networking Options  -NetworkPlugin vxlan/bridge, -Cni flannel
    f. Install & Start FlannelD service
    g. Install & Start KubeProxy Service.
    _Note: For service installation, a stub service executable is generated & hooked up with Windows SCM._

    cd  $env:HOMEDRIVE\$env:HOMEPATH
    $env:GITHUB_SDN_REPOSITORY="madhanrm/SDN"
    $env:GITHUB_SDN_BRANCH="kubeadm"
    $env:MASTER_USERNAME="localadmin"
    $env:DOCKER_IMAGE_TAG="insider"

### Flannel VxLan
	.\KubeCluster.ps1 -join -Master <IpAddressOfMaster> -Destination $env:HOMEDRIVE\$env:HOMEPATH\kubeadm -InterfaceName "Ethernet" -Cri dockerd -Cni flannel -NetworkPlugin vxlan
### Flannel Bridge
	.\KubeCluster.ps1 -join -Master <IpAddressOfMaster> -Destination $env:HOMEDRIVE\$env:HOMEPATH\kubeadm -InterfaceName "Ethernet" -Cri dockerd -Cni flannel -NetworkPlugin bridge

## Reset the node
    This option would undo whatever join did to the node & removes the node from the Kubernetes cluster.
    
    .\KubeCluster.ps1 -reset -Master <IpAddressOfMaster> -Destination $env:HOMEDRIVE\$env:HOMEPATH\kubeadm -InterfaceName "Ethernet" -Cri dockerd -Cni flannel -NetworkPlugin vxlan


## Sample Output
```
    PS C:\Users\azureuser> .\KubeCluster.ps1 -join -Master 172.16.18.4 -Destination $env:HOMEDRIVE\$env:HOMEPATH\kubeadm -Cri dockerd -Cni flannel -NetworkPlugin vxlan -InterfaceName 'Ethernet 2'
####################################
User Input
Destination       : C:\\Users\azureuser\kubeadm
Master            : 172.16.18.4
InterfaceName     : Ethernet 2
Cri               : dockerd
Cni               : flannel
NetworkPlugin     : vxlan
Release           : 1.14.0
####################################


    Directory: C:\Users\azureuser


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   1:59 AM                kubeadm
VERBOSE: GET https://raw.githubusercontent.com/madhanrm/SDN/kubeadm/Kubernetes/windows/helper.v2.psm1 with 0-byte
payload
VERBOSE: received 44753-byte response of content type text/plain; charset=utf-8
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/windows/hns.psm1] => [C:\\Users\azureuser\kubeadm\hns.psm1]


    Directory: C:\Users\azureuser\kubeadm


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   1:59 AM                logs
Downloading Kubeconfig from 172.16.18.4:~/.kube/config to C:\\Users\azureuser\kubeadm\config
config                                                                                100% 5447     5.3KB/s   00:00
Downloaded [https://dl.k8s.io/v1.14.0/kubernetes-node-windows-amd64.tar.gz] => [C:\Users\azureuser\AppData\Local\Temp\2\tmp9341.tar.gz]
Trying to connect to the Kubernetes master
FINDSTR: Line 5761 is too long.
FINDSTR: Line 5761 is too long.
####################################
Able to connect to the Master
Discovered the following
Cluster CIDR    : 10.244.0.0/16
Service CIDR    : 10.96.0.0/12
DNS ServiceIp   : 10.96.0.10
####################################
Installing Kubelet Service


    Directory: C:\Users\azureuser\kubeadm\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   2:02 AM                kubelet
Create a SCMService Binary for [Kubelet] [C:\\Users\azureuser\kubeadm\kubernetes\node\bin\kubelet.exe --hostname-override=k8swinworker1 --v=6 --pod-infra-container-image=kubeletwin/pause --resolv-conf="" --allow-privileged=true --enable-debugging-handlers --cluster-dns=10.96.0.10 --cluster-domain=cluster.local --kubeconfig=C:\\Users\azureuser\kubeadm\config --hairpin-mode=promiscuous-bridge --image-pull-progress-deadline=20m --cgroups-per-qos=false --log-dir=C:\\Users\azureuser\kubeadm\logs\kubelet --logtostderr=false --enforce-node-allocatable="" --network-plugin=cni --cni-bin-dir=C:\\Users\azureuser\kubeadm\cni --cni-conf-dir=C:\\Users\azureuser\kubeadm\cni\config --node-ip=172.16.18.5 --feature-gates=] => [C:\\Users\azureuser\kubeadm\KubeletSvc.exe]

Status      : Stopped
Name        : Kubelet
DisplayName : Kubelet

    ++++++++++++++++++++++++++++++++
    Successfully created the service
    ++++++++++++++++++++++++++++++++
    Service [Kubelet]
    Cmdline [C:\\Users\azureuser\kubeadm\KubeletSvc.exe]
    Env     []
    Log     [C:\\Users\azureuser\kubeadm\logs\kubelet\kubeletsvc.log]
    ++++++++++++++++++++++++++++++++


    Directory: C:\Users\azureuser\kubeadm


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   2:02 AM                cni
Downloading Flannel binaries
Downloaded [https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe] => [C:\\Users\azureuser\kubeadm\flanneld.exe]
Downloading CNI binaries for overlay to C:\\Users\azureuser\kubeadm\cni


    Directory: C:\Users\azureuser\kubeadm\cni


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   2:02 AM                config
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/overlay/cni/config/cni.conf] => [C:\\Users\azureuser\kubeadm\cni\config\cni.conf]
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/l2bridge/cni/flannel.exe] => [C:\\Users\azureuser\kubeadm\cni\flannel.exe]
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/l2bridge/cni/host-local.exe] => [C:\\Users\azureuser\kubeadm\cni\host-local.exe]
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/overlay/cni/win-overlay.exe] => [C:\\Users\azureuser\kubeadm\cni\win-overlay.exe]
Installing FlannelD Service


    Directory: C:\Users\azureuser\kubeadm\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   2:02 AM                flanneld
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/overlay/net-conf.json] => [C:\\Users\azureuser\kubeadm\net-conf.json]


    Directory: C:\etc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   2:02 AM                kube-flannel
Create a SCMService Binary for [FlannelD] [C:\\Users\azureuser\kubeadm\flanneld.exe --kubeconfig-file=C:\\Users\azureuser\kubeadm\config --iface=172.16.18.5 --ip-masq=1 --kube-subnet-mgr=1] => [C:\\Users\azureuser\kubeadm\FlannelDSvc.exe]

Status      : Stopped
Name        : FlannelD
DisplayName : FlannelD

    ++++++++++++++++++++++++++++++++
    Successfully created the service
    ++++++++++++++++++++++++++++++++
    Service [FlannelD]
    Cmdline [C:\\Users\azureuser\kubeadm\FlannelDSvc.exe]
    Env     [{
    "NODE_NAME":  "k8swinworker1"
}]
    Log     [C:\\Users\azureuser\kubeadm\logs\flanneld\flanneldsvc.log]
    ++++++++++++++++++++++++++++++++

ActivityId             : 52CDA7D5-7997-4116-91D5-7732743891AB
AdditionalParams       :
CurrentEndpointCount   : 0
DNSServerCompartment   : 3
DrMacAddress           : 00-15-5D-DD-28-F4
Extensions             : {@{Id=E7C3B2F0-F3C5-48DF-AF2B-10FED6D72E7A; IsEnabled=False; Name=Microsoft Windows Filtering
                         Platform}, @{Id=E9B59CFA-2BE1-4B21-828F-B6FBDBDDC017; IsEnabled=True; Name=Microsoft Azure
                         VFP Switch Extension}, @{Id=EA24CD6C-D17A-4348-9190-09F0D5BE83DD; IsEnabled=True;
                         Name=Microsoft NDIS Capture}}
Flags                  : 0
Health                 : @{LastErrorCode=0; LastUpdateTime=131995945293944191}
ID                     : 5596E3F0-3771-49D4-9966-951F8E438634
IPv6                   : False
LayeredOn              : 5F40441C-838B-4091-99D0-8F3F24235ED8
MacPools               : {@{EndMacAddress=00-15-5D-E3-9F-FF; StartMacAddress=00-15-5D-E3-90-00}}
ManagementIP           : 172.16.18.5
MaxConcurrentEndpoints : 0
Name                   : External
NetworkAdapterName     : Ethernet 2
Policies               : {}
Resources              : @{AdditionalParams=; AllocationOrder=1; Allocators=System.Object[]; Health=;
                         ID=52CDA7D5-7997-4116-91D5-7732743891AB; PortOperationTime=0; State=1; SwitchOperationTime=0;
                         VfpOperationTime=0; parentId=6CCDC9D4-C82D-4064-A0D5-7D5D62C927CE}
State                  : 1
Subnets                : {@{AdditionalParams=; AddressPrefix=192.168.255.0/30; GatewayAddress=192.168.255.1; Health=;
                         ID=3634A229-0941-4513-92DB-6A3CD51BA4FB; ObjectType=5; Policies=System.Object[]; State=0}}
TotalEndpoints         : 0
Type                   : overlay
Version                : 38654705666

Waiting for the Network (vxlan0) to be created by flanneld


    Directory: C:\Users\azureuser\kubeadm\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/13/2019   2:02 AM                kube-proxy
Installing Kubeproxy Service
Create a SCMService Binary for [Kubeproxy] [C:\\Users\azureuser\kubeadm\kubernetes\node\bin\kube-proxy.exe --hostname-override=k8swinworker1 --v=4 --proxy-mode=kernelspace --kubeconfig=C:\\Users\azureuser\kubeadm\config --network-name=vxlan0 --cluster-cidr=10.244.0.0/16 --log-dir=C:\\Users\azureuser\kubeadm\logs\kube-proxy --logtostderr=false --feature-gates=WinOverlay=true --source-vip=10.244.6.2] => [C:\\Users\azureuser\kubeadm\KubeproxySvc.exe]

Status      : Stopped
Name        : Kubeproxy
DisplayName : Kubeproxy

    ++++++++++++++++++++++++++++++++
    Successfully created the service
    ++++++++++++++++++++++++++++++++
    Service [Kubeproxy]
    Cmdline [C:\\Users\azureuser\kubeadm\KubeproxySvc.exe]
    Env     []
    Log     [C:\\Users\azureuser\kubeadm\logs\kube-proxy\kubproxysvc.log]
    ++++++++++++++++++++++++++++++++
NAME            STATUS     ROLES    AGE     VERSION
k83winworker3   NotReady   <none>   5m58s   v1.14.0
k8smaster       Ready      master   157m    v1.14.1
k8swinworker1   Ready      <none>   18s     v1.14.0
Node k8swinworker1 successfully joined the cluster


PS C:\Users\azureuser>
```
