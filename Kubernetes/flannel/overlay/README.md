# How to deploy Kubernetes on Windows with Flannel + VxLan
* Requires Windows Server Insider Build 18301 or higher
* Download/Build the appropriate versions of Kubelet.exe and Kubectl.exe to c:\k
* Build Kube Proxy from [PR 70896](https://github.com/kubernetes/kubernetes/pull/70896) and copy to c:\k
* Copy Kubeconfig from Linux master to c:\k
* Download the following files to c:\k
    [start.ps1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/start.ps1) 
    [helper.psm1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/helper.psm1) 
* run powershell c:\k\start.ps1 -ManagementIP <IPAddressOfTheCurrentNode>

# Temp Binaries that will be removed soon
* cni\win-overlay.exe

# What works
* Pod to Pod connectivity will work (Windows and Linux)
* Outbound Internet connectivity will work
* Node port access
* Service Vip access

# Validated but pending approval 
* Kubeproxy support for Overlay mode [PR 70896](https://github.com/kubernetes/kubernetes/pull/70896)

# What will not work
* Pod to host and vice versa
