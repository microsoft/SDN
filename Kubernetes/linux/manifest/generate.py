#!/usr/bin/python2
""" Generates a set of Kubernetes system pod manifest files.
"""

import sys
import os.path

import argparse
import re


def is_int(x):
    try:
        y = int(x)
        return True
    except ValueError:
        return False

def is_ip(x):
    return x.count('.') == 3 and all([ is_int(i) for i in x.split('.') ])

def is_cidr(x):
    if x.find('/') == -1: return False
    ip, mask = x.split('/')
    return is_ip(ip) and is_int(mask) and int(mask) in xrange(1, 33)

def replacerino(string, replacements):
    final = string
    for var, repl in replacements.iteritems():
        final = final.replace(var, repl)
    return final



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
    image: gcr.io/google_containers/kube-addon-manager-amd64:$ADDON_VERSION
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
      image: "gcr.io/google_containers/hyperkube-amd64:$API_VERSION"
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
      image: "gcr.io/google_containers/hyperkube-amd64:$CONTROLLER_VERSION"
      command:
        - "/hyperkube"
        - "controller-manager"
        - "--kubeconfig=/var/lib/kubelet/config"$WILL_ALLOCATE
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
      image: "gcr.io/google_containers/hyperkube-amd64:$SCHEDULER_VERSION"
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
      image: "gcr.io/google_containers/etcd:$ETCD_VERSION"
      env:
        - name: TARGET_STORAGE
          value: "etcd3"
        - name: TARGET_VERSION
          value: "$ETCD_VERSION"
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


def main(home, args):
    ALLOCATE = """
        - "--allocate-node-cidrs=True"
        - "--cluster-cidr=$CLUSTER" """.rstrip()

    for filename, content in MANIFEST_TEMPLATES.iteritems():
        print "Generating %s ..." % filename,
        with open(filename, "w") as manifest:
            final = replacerino(content, {
                "$API_VERSION": args.api_version,
                "$CONTROLLER_VERSION": args.controller_version,
                "$SCHEDULER_VERSION": args.scheduler_version,
                "$ADDON_VERSION": args.addon_version,
                "$ETCD_VERSION": args.etcd_version,
                "$WILL_ALLOCATE": ALLOCATE if not args.sure else "",
                "$HOME": home,
                "$MASTERIP": args.master
            })
            if args.cluster:
                final = replacerino(final, {"$CLUSTER": args.cluster})
            manifest.write(final)
        print "done."


parser = argparse.ArgumentParser(
    description="""Generates manifest files for deployment of a Kubernetes
                master node. It has options for some deployment variations.

                The generator isn't fool-proof. If you want something special,
                and you know what you're doing, just make your edits by hand
                after generating normally.""",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    epilog="""The version parameters are just suffixes injected into the
           default image name in the manifest. For example, the API server
           uses this image:

                gcr.io/google_containers/hyperkube-amd64:v1.7.3

           Thus, customizing --api-version will only change the last bit of
           string. No validation is done on these, so you may be surprised later
           if you put in a bad version and your cluster isn't coming up
           fully.""")

parser.add_argument("master",
                    help="the IP address of this node, found via ifconfig")
parser.add_argument("--etcd-version", default="3.0.17",
                    help="""specifies the image version to use for the etcd
                    manifest file.""")
parser.add_argument("--controller-version", default="v1.9.1",
                    help="""specifies the image version to use for the
                    Kubernetes controller manager manifest file.""")
parser.add_argument("--scheduler-version", default="v1.9.1",
                    help="""specifies the image version to use for the scheduler
                    manifest file.""")
parser.add_argument("--api-version", default="v1.9.1",
                    help="""specifies the image version to use for the
                    Kubernetes API server manifest file.""")
parser.add_argument("--addon-version", default="v6.4-beta.2",
                    help="""specifies the image version to use for the addon
                    manager manifest file.""")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--cluster-cidr", dest="cluster", metavar="ip/mask",
                   help="""the cluster CIDR on which all nodes exist. if this
                   is omitted, the Kubernetes controller *will not* provide
                   CIDRs to nodes for their pods. because omitting this is not
                   the typical use-case, you must pass --im-sure to do so.""")
group.add_argument("--im-sure", dest="sure", action="store_true",
                   help="""indicates that you are sure you don't wish to pass
                   a --cluster-cidr, and have the master node automatically
                   assign pod subnets to nodes.""")

args = parser.parse_args()

print "Validating master IP..."
if not is_ip(args.master):
    parser.error("The IP address of the master that you provided (%s)" % (
                 args.master) + " was not a valid IPv4 address.")

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 53))
address = s.getsockname()[0]
if address != args.master:
    print "  The detected external IP address was:", address
    print "  But you provided:", args.master
    print "  Proceeding anyway, but just so you know, this is weird."
s.close()

if args.cluster:
    print "Validating cluster CIDR..."
    if not is_cidr(args.cluster):
        parser.error("The cluster CIDR that you provided (%s) " % (
                     args.cluster) + "was not a valid CIDR. Expected " + \
                     "the format 127.0.0.0/32")

HOME = os.path.expanduser("~")
print "User home directory:", HOME
print "Output directory:", os.getcwd()
print "We're good to go. Generating manifests..."

main(HOME, args)
print "All done."
