#!/bin/bash

cat > openssl.cnf <<EOF
[req]
  req_extensions = v3_req
  distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
  basicConstraints = CA:FALSE
  keyUsage = nonRepudiation, digitalSignature, keyEncipherment
  subjectAltName = @alt_names
[alt_names]
  DNS.1 = kubernetes
  DNS.2 = kubernetes.default
  DNS.3 = kubernetes.default.svc
  DNS.4 = kubernetes.default.svc.cluster.local
EOF

echo "IP.1 = $1" >> openssl.cnf
echo "IP.2 = 11.0.0.1" >> openssl.cnf

openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes -key ca-key.pem -days 10000 \
            -out ca.pem -subj "/CN=kube-ca"

openssl genrsa -out apiserver-key.pem 2048
openssl req -new -key apiserver-key.pem -out apiserver.csr \
            -subj "/CN=kube-apiserver" -config openssl.cnf
openssl x509 -req -in apiserver.csr -CA ca.pem -CAkey ca-key.pem \
             -CAcreateserial -out apiserver.pem -days 365 \
             -extensions v3_req -extfile openssl.cnf
