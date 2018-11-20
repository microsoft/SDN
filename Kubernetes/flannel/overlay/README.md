# How to deploy Kubernetes on Windows with Flannel + VxLan
* Download/Build the appropriate versions of Kubelet.exe, Kubectl.exe, Kube-Proxy.exe to c:\k
* Copy Kubeconfig from Linux master to c:\k
* Download the following files to c:\k
    [start.ps1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/start.ps1) 
    [helper.psm1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/helper.psm1) 
* run powershell c:\k\start.ps1 -ManagementIP <IPAddressOfTheCurrentNode>


# Temp Binaries that will be removed soon
There are several pending PRs, because of which the bins are published here
[vxlan: add windows support](https://github.com/coreos/flannel/pull/922)

[Windows CNI for overlay (vxlan) and host-gw (l2bridge) modes](https://github.com/containernetworking/plugins/pull/85)
* cni\overlay.exe

# What works
* Pod to Pod connectivity will work (Windows to Windows)
* Outbound Internet connectivity will work
* Node port access


# Pending Validation
* Kubeproxy support for Overlay mode
* Service Vip access

# What will not work
* Pod to Pod connectivity (Linux to Windows)
