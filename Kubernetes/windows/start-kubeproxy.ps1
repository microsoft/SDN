
#$env:INTERFACE_TO_ADD_SERVICE_IP="vEthernet (forwarder)"
#c:\k\kube-proxy.exe --v=4 --proxy-mode=usermode --hostname-override=15992acs9000 --kubeconfig=c:\k\config

$env:KUBE_NETWORK="l2bridge"
c:\k\kube-proxy.exe --v=4 --proxy-mode=kernelspace --hostname-override=$(hostname) --kubeconfig=c:\k\config
