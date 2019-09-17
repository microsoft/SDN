export GOOS=windows
apt-get update
apt-get install -y mingw-w64

#cri/containerd
cd /go/src
mkdir -p github.com/containerd
cd github.com/containerd/
git clone https://github.com/jterry75/cri.git
cd cri
git checkout windows_port
cd cmd/containerd/
echo "Getting dependencies"
go get
echo "Building containerd"
go build -o /out/containerd.exe .

#ctr
cd ../ctr
git remote add upstream https://github.com/containerd/cri.git
git fetch upstream
git checkout upstream/master
echo "Getting dependencies"
go get
echo "Building ctr"
go build -o /out/ctr.exe .

#containerd-shim-runhcs-v1
cd /go/src/github.com/containerd/
git clone https://github.com/containerd/containerd.git
cd containerd/cmd/containerd-shim-runhcs-v1/
echo "Getting dependencies"
go get
echo "Building containerd-shim-runhcs-v1"
go build -o /out/containerd-shim-runhcs-v1.exe .