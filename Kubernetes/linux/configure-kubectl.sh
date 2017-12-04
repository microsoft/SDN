#!/bin/bash

KUBEPATH="$HOME/kube"
KUBECERTPATH="$KUBEPATH/certs"
KUBEBIN="$KUBEPATH/bin"

CA_CERT="$KUBECERTPATH/ca.pem"
CLI_CERT="$KUBECERTPATH/apiserver.pem"
CLI_KEY="$KUBECERTPATH/apiserver-key.pem"

CLUSTER_NAME="kubernetes"
MASTER_IP=$1
CONTEXT_NAME="default"

$KUBEBIN/kubectl config set-cluster $CLUSTER_NAME \
  --certificate-authority=$CA_CERT --embed-certs=true \
  --server=https://$MASTER_IP
$KUBEBIN/kubectl config set-credentials default-admin \
  --certificate-authority=$CA_CERT --client-certificate=$CLI_CERT \
  --client-key=$CLI_KEY --embed-certs=true # --token=$TOKEN
$KUBEBIN/kubectl config set-context $CONTEXT_NAME \
  --cluster=$CLUSTER_NAME --user=default-admin
$KUBEBIN/kubectl config use-context $CONTEXT_NAME
