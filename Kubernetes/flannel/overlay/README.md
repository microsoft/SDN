# How to deploy Kubernetes on Windows with Flannel + VxLan
* Requires Windows Server Insider Build 18317 or higher, or Windows Server 2019 with KB4489899
* Requires Flannel on Linux modifications:
  * Ensure that Flannel on Linux has [VNI 4096](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/overlay/manifests/kube-flannel-example.yml#L130) set and [port 4789](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/overlay/manifests/kube-flannel-example.yml#L131)
  * Ensure that Flannel on Linux has [network name](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/overlay/manifests/kube-flannel-example.yml#L108) set to "vxlan0"
* Download/Build the appropriate versions of Kubelet.exe and Kubectl.exe to c:\k
* Kube-proxy v1.14 (or above) 
* Copy Kubeconfig from Linux master to c:\k
* Download the following files to c:\k
  * [start.ps1](https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/start.ps1) 
  * [latest flanneld.exe](https://github.com/coreos/flannel/releases/)
* run powershell c:\k\start.ps1 -ManagementIP <IPAddressOfTheCurrentNode> -NetworkMode overlay -ClusterCIDR <ClusterSubnet> -ServiceCIDR <ServiceSubnet>

# Temp Binaries that will be removed soon
* cni\win-overlay.exe => available now on https://github.com/containernetworking/plugins/releases

# What works
* Pod to Pod connectivity will work (Windows and Linux)
* Outbound Internet connectivity will work
* Node port access
    * (Except from pods scheduled on the same host, requires Flannel PR https://github.com/coreos/flannel/pull/1096)
* Service Vip access
