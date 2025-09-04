# faultTolerance.ps1

This will analyze Host Network Service faults and provide concise summary / mitigation steps / auto-mitigate issues.

## Instructions for AKS cluster

### With powershell access to the cluster (kubectl)

1. Run **faultTolerance.ps1** script on powershell with access to the AKS cluster using this command
```
    .\faultTolerance.ps1
    daemonset.apps/faulttolerance created
    Sleep for a minute for fault tolerance pods to be up...
    **No HNS crashes detected in the cluster**
    Sleep for an hour before deleting the fault tolerance pods automatically...
    daemonset.apps "faulttolerance" deleted
```

### Without powershell access to the cluster (kubectl)

1. Apply the yaml **faulttolerance.yaml** on an AKS cluster using this command
```
    Cleanup the previous instance of the daemon set and re-apply.

    kubectl delete -f faulttolerance.yaml
    kubectl apply -f faulttolerance.yaml
```

2. Wait for 5 minutes and redirect the output of the following command to a text file and provide it to the support engineer.
```
    kubectl logs -l name=faulttolerance --all-containers=true

    Example:
    kubectl logs -l name=faulttolerance --all-containers=true >> faulttolerance.txt
    Provide the generated faulttolerance.txt
```