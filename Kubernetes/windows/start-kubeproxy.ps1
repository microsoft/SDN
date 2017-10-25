$env:KUBE_NETWORK="l2bridge"
c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$(hostname) --kubeconfig=c:\k\config
