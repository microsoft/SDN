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