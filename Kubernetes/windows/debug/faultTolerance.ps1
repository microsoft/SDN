$faultToleranceYaml = @'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: faulttolerance
  labels:
    app: faulttolerance
spec:
  selector:
    matchLabels:
      name: faulttolerance
  template:
    metadata:
      labels:
        name: faulttolerance
    spec:
      securityContext:
        windowsOptions:
          hostProcess: true
          runAsUserName: "NT AUTHORITY\\SYSTEM"
      hostNetwork: true
      containers:
      - name: faulttolerance
        image: mcr.microsoft.com/windows/servercore:1809
        args:
        - powershell.exe
        - -Command
        - "$BaseDir = \"c:\\k\\debug\";while(1){Invoke-WebRequest -UseBasicParsing \"https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/detectHNSCrash.ps1\" -OutFile $BaseDir\\detectHNSCrash.ps1;c:\\k\\debug\\detectHNSCrash.ps1; start-sleep 60;}"
        imagePullPolicy: IfNotPresent
        volumeMounts:
          - name: kube-path
            mountPath: C:\k
      volumes:
      - name: kube-path
        hostPath:
          path: C:\k
      nodeSelector:
        kubernetes.azure.com/os-sku: Windows2019
'@

$faultToleranceYaml | kubectl delete -f -

$faultToleranceYaml | kubectl apply -f -
Write-Output "Sleep for a minute for fault tolerance pods to be up"
Start-Sleep 60

[System.Collections.ArrayList] $ws2019Nodes = @()
$nodes = (kubectl get nodes -o jsonpath="{.items[*].metadata.name}").Split()
foreach ($node in $nodes) {
  $nodeImage = kubectl get node $node -o jsonpath="{.status.nodeInfo.osImage}"

  if ($nodeImage.ToString().trim() -eq "Windows Server 2019 Datacenter") {
    $ws2019Nodes += $node.trim();
  }
}

$pods = (kubectl get pods -o jsonpath="{.items[*].metadata.name}").Split()
foreach ($pod in $pods) {
    if ($pod.StartsWith('faulttolerance')) {
        # if hns crashed - get the reason
        $nodeName = kubectl get pod $pod -o jsonpath="{.spec.nodeName}"
        $podLog = kubectl log $pod
        if ($podLog.Contains("HNS crash not detected")) {
            $ws2019Nodes.Remove($nodeName.ToLower())
        } else {
            # Generate Crash Report
            $errStr = "HNS Crash detected in "+$nodeName+", Report: `n"+$podLog+"`n"
        }
}
Write-Host $errStr

if ($ws2019Nodes.Count -eq 0) {
    Write-Host "No HNS crashes detected in the cluster"
}

# Sleep for 60 minutes, and delete the daemonset
Start-Sleep 3600
$faultToleranceYaml | kubectl delete -f -