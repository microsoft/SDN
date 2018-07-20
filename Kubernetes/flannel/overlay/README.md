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
* Pod to Pod connectivity will work
* Outbound Internet connectivity will work

# Pending Validation
* Node port access

# What will not work
* Service Vip access (There might be a workaround for this, which will be documented soon)
* Kubeproxy currently is meant for L2Bridge only. It doesnt support Overlay mode. Needs some minor work there.