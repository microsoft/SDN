# How to deploy Kuberbetes on Windows with Flannel + HostGW
* Download Kubelet.exe, Kubectl.exe, Kube-Proxy.exe to c:\k
* Copy Kubeconfig from Linux master to c:\k
* Download start.ps1 to c:\k and run powershell powershell c:\k\start.ps1


# Temp Binaries that will be removed soon
There are several pending PRs, because of which the bins are published here
[host-gw: add windows support](https://github.com/coreos/flannel/pull/921)
* flanned.exe - 

[Windows CNI for overlay (vxlan) and host-gw (l2bridge) modes](https://github.com/containernetworking/plugins/pull/85)
* cni\flannel.exe - 
* cni\host-local.exe
* cni\l2bridge.exe