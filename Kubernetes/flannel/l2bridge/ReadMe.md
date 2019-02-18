# How to deploy Kubernetes on Windows with Flannel + HostGW

## Prerequisites
* You have a Kubernetes Master that was successfully setup using Flannel *with host-gateway as the network backend*. This can be done using [kubeadm](https://kubernetes.io/docs/tasks/tools/install-kubeadm/), or our [Kubernetes master from scratch](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/creating-a-linux-master) instructions, for example.
  * Kube-Proxy and Flannel DaemonSets are scheduled to only target Linux nodes. You can do this by applying this [node-selector](./manifests/node-selector-patch.yml).
* You are using Windows Server, version 1709 or above.

## Instructions

A more detailed version of these instructions can be found [here](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows).

#### 1. Install Docker
```
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
Install-Package -Name Docker -ProviderName DockerMsftProvider
Restart-Computer -Force
```

#### 2. Create the Kubernetes for Windows directory
```
mkdir C:\k
```

#### 3. Download [start.ps1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/start.ps1) into `C:\k` and do the following:
  * Download [latest Kubernetes Windows binaries](https://github.com/kubernetes/kubernetes/releases/) (kubelet.exe, kubectl.exe, kube-proxy.exe) into `C:\k`
  * Download [latest flanneld.exe](https://github.com/coreos/flannel/releases/) into C:\k
  * Copy Kubeconfig file `$HOME/.kube/config` or `/etc/kubernetes/admin.conf` from Kubernetes Master and save as `config` into `C:\k`
  * Use `docker pull` to download images from `mcr.microsoft.com/windows/nanoserver` matching your host OS version.

#### 4. Join the Kubernetes cluster:
```
.\start.ps1 -ManagementIP <Windows_Worker_Node_IP> -ClusterCIDR <ClusterCIDR> -ServiceCIDR <SvcCIDR> -KubeDnsServiceIP <KubeDNSIP>
```

Where:
  * `ManagementIP`: The IP address of the machine you are trying to join.
  * `ClusterCIDR`: The address range used by [Kubernetes pods](https://kubernetes.io/docs/concepts/workloads/pods/pod/).
  * `ServiceCIDR`: The address range used by [Kubernetes services](https://kubernetes.io/docs/concepts/services-networking/service/).
  * `KubeDnsServiceIP`: The DNS service VIP used by [kube-dns](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/).

#### 5. Deploy an [example Windows service](./manifests/simpleweb.yml) (make sure container image matches host OS)

## Temp Binaries that will be removed soon
There are several pending PRs, because of which the bins are published here. We are planning to transition to a new CNI repo separately from Microsoft/SDN.
* cni\flannel.exe - 
* cni\host-local.exe
* cni\l2bridge.exe