#!/usr/bin/python2
import sys
import os.path

# Inputs:
#
#   - Master IP, the external IP address of the masas inter
#   - Cluster CIDR, likely a /16
#
# Outputs:
#   - 5 manifest files:
#       kube-etcd.yaml
#       kube-scheduler.yaml
#       kube-apiserver.yaml
#       kube-addon-manager.yaml
#       kube-control-manager.yaml

MANIFEST_TEMPLATES = {
    "kube-addon-manager.yaml": """apiVersion: v1
kind: Pod
metadata:
  name: kube-addon-manager
  namespace: kube-system
  version: v1
spec:
  hostNetwork: true
  containers:
  - name: kube-addon-manager
    image: gcr.io/google_containers/kube-addon-manager-amd64:v6.4-beta.2
    resources:
      requests:
        cpu: 5m
        memory: 50Mi
    volumeMounts:
    - name: addons
      mountPath: "/etc/kubernetes/addons"
      readOnly: true
  volumes:
  - name: addons
    hostPath:
      path: "$HOME/kube/addons"
""",
    "kube-apiserver.yaml": """apiVersion: "v1"
kind: "Pod"
metadata:
  name: "kube-apiserver"
  namespace: "kube-system"
  labels:
    tier: control-plane
    component: kube-apiserver
spec:
  hostNetwork: true
  containers:
    - name: "kube-apiserver"
      image: "gcr.io/google_containers/hyperkube-amd64:v1.7.3"
      command:
        - "/hyperkube"
        - "apiserver"
        - "--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota"
        - "--address=0.0.0.0"
        - "--allow-privileged"
        - "--insecure-port=8080"
        - "--secure-port=443"
        - "--service-cluster-ip-range=11.0.0.0/16"
        - "--etcd-servers=http://127.0.0.1:2379"
        - "--etcd-quorum-read=true"
        - "--advertise-address=$MASTERIP"
        - "--tls-cert-file=/etc/kubernetes/certs/apiserver.pem"
        - "--tls-private-key-file=/etc/kubernetes/certs/apiserver-key.pem"
        - "--client-ca-file=/etc/kubernetes/certs/ca.pem"
        - "--service-account-key-file=/etc/kubernetes/certs/apiserver-key.pem"
        - "--storage-backend=etcd2"
        - "--v=4"
      ports:
        - name: "https"
          containerPort: 443
          hostPort: 443
        - name: "local"
          containerPort: 8080
          hostPort: 8080
      volumeMounts:
        - name: "etc-kubernetes"
          mountPath: "/etc/kubernetes"
        - name: "var-lib-kubelet"
          mountPath: "/var/lib/kubelet"
  volumes:
    - name: "etc-kubernetes"
      hostPath:
        path: "$HOME/kube"
    - name: "var-lib-kubelet"
      hostPath:
        path: "$HOME/kube/kubelet"
""",
    "kube-control-manager.yaml": """apiVersion: "v1"
kind: "Pod"
metadata:
  name: "kube-controller-manager"
  namespace: "kube-system"
  labels:
    tier: control-plane
    component: kube-controller-manager
spec:
  hostNetwork: true
  containers:
    - name: "kube-controller-manager"
      image: "gcr.io/google_containers/hyperkube-amd64:v1.7.3"
      command:
        - "/hyperkube"
        - "controller-manager"
        - "--kubeconfig=/var/lib/kubelet/config"
        - "--allocate-node-cidrs=True"
        - "--cluster-cidr=$CLUSTER"
        - "--cluster-name=kubernetes"
        - "--root-ca-file=/etc/kubernetes/certs/ca.pem"
        - "--cluster-signing-cert-file=/etc/kubernetes/certs/ca.pem"
        - "--cluster-signing-key-file=/etc/kubernetes/certs/ca-key.pem"
        - "--service-account-private-key-file=/etc/kubernetes/certs/apiserver-key.pem"
        - "--leader-elect=true"
        - "--v=2"
      volumeMounts:
        - name: "etc-kubernetes"
          mountPath: "/etc/kubernetes"
        - name: "var-lib-kubelet"
          mountPath: "/var/lib/kubelet"
        - name: "varlog"
          mountPath: "/var/log"
  volumes:
    - name: "etc-kubernetes"
      hostPath:
        path: "$HOME/kube"
    - name: "var-lib-kubelet"
      hostPath:
        path: "$HOME/kube/kubelet"
    - name: "varlog"
      hostPath:
        path: "$HOME/kube/log/kube-controller-manager"
""",
    "kube-scheduler.yaml": """apiVersion: "v1"
kind: "Pod"
metadata:
  name: "kube-scheduler"
  namespace: "kube-system"
  labels:
    tier: control-plane
    component: kube-scheduler
spec:
  hostNetwork: true
  containers:
    - name: "kube-scheduler"
      image: "gcr.io/google_containers/hyperkube-amd64:v1.7.3"
      command:
        - "/hyperkube"
        - "scheduler"
        - "--kubeconfig=/var/lib/kubelet/config"
        - "--leader-elect=true"
        - "--v=4"
      volumeMounts:
        - name: "etc-kubernetes"
          mountPath: "/etc/kubernetes"
        - name: "var-lib-kubelet"
          mountPath: "/var/lib/kubelet"
        - name: "varlog"
          mountPath: "/var/log"
  volumes:
    - name: "etc-kubernetes"
      hostPath:
        path: "$HOME/kube"
    - name: "var-lib-kubelet"
      hostPath:
        path: "$HOME/kube/kubelet"
    - name: "varlog"
      hostPath:
        path: "$HOME/kube/log/kube-scheduler"
""",
    "kube-etcd.yaml": """apiVersion: "v1"
kind: "Pod"
metadata:
  name: "kube-etcd"
  namespace: "kube-system"
  labels:
    tier: control-plane
    component: kube-etcd
spec:
  hostNetwork: true
  containers:
    - name: "etcd-container"
      image: "gcr.io/google_containers/etcd:3.0.17"
      env:
        - name: TARGET_STORAGE
          value: "etcd3"
        - name: TARGET_VERSION
          value: "3.0.17"
        - name: DATA_DIRECTORY
          value: "/var/etcd/datakube"
      command:
        - "/bin/sh"
        - "-c"
        - "/usr/local/bin/etcd --name etcd0 --advertise-client-urls http://$MASTERIP:2379,http://$MASTERIP:4001 --listen-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001  --initial-advertise-peer-urls http://$MASTERIP:2380 --listen-peer-urls http://0.0.0.0:2380 --initial-cluster-token etcd-cluster-1 --initial-cluster etcd0=http://$MASTERIP:2380 --initial-cluster-state new --data-dir /var/etcd/datakube 1>>/var/log/etcdkube.log/log 2>&1"
      livenessProbe:
         httpGet:
             host: "127.0.0.1"
             port: 2379
             path: "/health"
         initalDelaySeconds: 15
         timeoutSeconds: 15
      ports:
         - name: "serverport"
           containerPort: 2380
           hostPort: 2380
         - name: "clientport"
           containerPort: 2379
           hostPort: 2379
      volumeMounts:
        - name: "etcd"
          mountPath: "/var/etcd"
          readOnly: false
        - name: "logetcd"
          mountPath: "/var/log/etcdkube.log"
          readOnly: false
        - name: "etc"
          mountPath: "/srv/kubernetes"
          readOnly: false
  volumes:
    - name: "etcd"
      hostPath:
        path: "$HOME/kube/etcd"
    - name: "etc"
      hostPath:
        path: "$HOME/kube"
    - name: "logetcd"
      hostPath:
        path: "$HOME/kube/log/etckube.log"
""",
}

HOME = os.path.expanduser("~")

def main(master_ip, cluster_cidr):
    for filename, content in MANIFEST_TEMPLATES.iteritems():
        print "Generating %s ..." % filename,
        with open(filename, "w") as manifest:
            new_content = content.replace(
                "$HOME", HOME).replace(
                "$MASTERIP", master_ip).replace(
                "$CLUSTER", cluster_cidr
            )
            manifest.write(new_content)
        print "done."

if len(sys.argv) != 3:
    print "usage: generate.py [master IP address] [full cluster CIDR]"
    print "   ex: generate.py 10.123.45.67 192.168.0.0/16"
    sys.exit(1)

print "User home directory:", HOME
print "Generating manifests in local directory..."
main(*sys.argv[1:])
print "All done."
