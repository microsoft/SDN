# How to deploy Kubernetes on Windows with Flannel + VxLan
* Requires Windows Server Insider Build 18301 or higher
* Requires Flannel on Linux modifications:
  * Ensure that Flannel on Linux has [VNI 4096](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/overlay/manifests/kube-flannel-example.yml#L130) set and [port 4789](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/overlay/manifests/kube-flannel-example.yml#L131)
  * Ensure that Flannel on Linux has [network name](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/overlay/manifests/kube-flannel-example.yml#L108) set to "vxlan0"
* Download/Build the appropriate versions of Kubelet.exe and Kubectl.exe to c:\k
* Build Kube Proxy from [PR 70896](https://github.com/kubernetes/kubernetes/pull/70896) and copy to c:\k
* Copy Kubeconfig from Linux master to c:\k
* Download the following files to c:\k
  * [start.ps1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/start.ps1) 
  * [latest flanneld.exe](https://github.com/coreos/flannel/releases/)
* run powershell c:\k\start.ps1 -ManagementIP <IPAddressOfTheCurrentNode> -NetworkMode overlay -ClusterCIDR <ClusterSubnet> -ServiceCIDR <ServiceSubnet>

# Temp Binaries that will be removed soon
* cni\win-overlay.exe

# What works
* Pod to Pod connectivity will work (Windows and Linux)
* Outbound Internet connectivity will work
* Node port access
    * (Except from pods scheduled on the same host)
* Service Vip access

# Validated but pending approval 
* Kubeproxy support for Overlay mode [PR 70896](https://github.com/kubernetes/kubernetes/pull/70896)
* Pod to host and vice versa requires [#1096](https://github.com/coreos/flannel/pull/1096)
