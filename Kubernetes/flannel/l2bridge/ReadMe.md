# How to deploy Kuberbetes on Windows with Flannel + HostGW

## Prerequisites
* You have a Kubernetes Master that was successfully setup using Flannel. For example, using [kubeadm](https://kubernetes.io/docs/tasks/tools/install-kubeadm/).

## Instructions 
1. Create the Kubernetes for Windows directory
```
PS C:> mkdir C:\k
```

2. Download the contents of [l2bridge directory](.) into `C:\k` and do the following:
  * Donwload Kubernetes Windows binaries (kubelet.exe, kubectl.exe, kube-proxy.exe) into `C:\k`
    * See [Kubernetes release notes](https://github.com/kubernetes/kubernetes/releases/) for newest version
  * Copy Kubeconfig file `$HOME/.kube/config` or `/etc/kubernetes/admin.conf` from Kubernetes Master and save as `config` into `C:\k`
  * Ensure the cluster CIDR (e.g. "10.244.0.0/16") is correct in:
    * [net-conf.json](./net-conf.json)

3. Run the following inside `C:\k` to join the Windows worker:
```
PS C:\k> .\start.ps1 -ManagementIP <Windows_Worker_Mgmt_IP> -ClusterCIDR <ClusterCIDR> -ServiceCIDR <SvcCIDR> -KubeDnsServiceIP <KubeDNSIP>
```

Where:
  * `ManagementIP`: The IP address of your Windows container host.
  * `ClusterCIDR`: The address range used by [Kubernetes pods](https://kubernetes.io/docs/concepts/workloads/pods/pod/).
  * `ServiceCIDR`: The address range used by [Kubernetes services](https://kubernetes.io/docs/concepts/services-networking/service/).
  * `KubeDnsServiceIP`: The DNS service VIP used by [kube-dns](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/).


## Temp Binaries that will be removed soon
There are several pending PRs, because of which the bins are published here
[host-gw: add windows support](https://github.com/coreos/flannel/pull/921)
* flanned.exe - 

[Windows CNI for overlay (vxlan) and host-gw (l2bridge) modes](https://github.com/containernetworking/plugins/pull/85)
* cni\flannel.exe - 
* cni\host-local.exe
* cni\l2bridge.exe