# Networkhealth.ps1

This will analyze VFP and HNS container networking health.
The following output modes are supported through the `-OutputMode` parameter:

| OutputMode | Tests Pass                                                                          | Tests Fail                                                                                 |
|------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| Event      | Log a concise informational event in Event logs describing container network health | 1. Log a warning event with verbose logs <br/>  2. Dump HNS data to JSON <br/> 3. Collect Windows Logs |
| Html       | 1. Create a HTML report of validated network tests <br/> 2. Dump HNS data to JSON         | 1. Create a HTML report of validated network tests and failures <br/> 2. Dump HNS data to JSON   |
| All        | All the above                                                                       | All the above                                                                              |

## Assumptions
For collecting logs during failure or using the `-CollectLogs` parameter, The script assumes you have the following script in `C:\k\debug` (the default path on AKS-Windows): [aka.ms/collect-windows-logs](http://aka.ms/collect-windows-logs)

## Running locally
You can replay the script locally by using the generated JSON files and using the `-Replay` parameter.

## Event Logs
If the `-OutputMode` is set to `Event` or `All`, the script will register a new event source provider `NetworkHealth` in the `Application` event logs, where new events will be written. Informational events will use event ID 0, whereas warnings will use event ID 1.

## Instructions for AKS cluster

1. Apply the yaml **networkhealth.yaml** on an AKS cluster using this command
```
    Cleanup the previous instance of the daemon set and re-apply.

    kubectl delete -f networkhealth.yaml
    kubectl apply -f networkhealth.yaml
```

2. Wait for 5 minutes and redirect the output of the following command to a text file and provide it to the support engineer.
```
    kubectl logs -l name=networkhealth --all-containers=true

    Example:
    kubectl logs -l name=networkhealth --all-containers=true >> networkhealth.txt
    Provide the generated networkhealth.txt
```