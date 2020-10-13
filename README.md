# Commands
List Event Tracing Sessions: `logman query -ets`\
Query Specific Provider: `logman query "EventLog-System" -ets`\
Show providers: `logman query providers`\

Filtering: `$p = logman query providers; $p | ? { $_ -Like "*Security*" }`\
Get Metadata: `logman query providers Microsoft-Windows-Security-Auditing`

# HELK
```
git clone https://github.com/Cyb3rWard0g/HELK.git
cd HELK/docker
sudo ./helk_install.sh
tail -f /var/log/helk-install.log
sudo docker-compose -f helk-kibana-analysis-alert-basic.yml stop
```
# Sentinel
## Attack surface reduction rules - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?ocid=wd-av-demo-asr-bottom
Search for ASR hits:
```
DeviceEvents
| where ActionType startswith 'Asr'
```
## Check Defender Healthy
```
Event
| where EventID == 1150 
| order by TimeGenerated desc
```

## Unhealthy Defender stage
```
Event
| where EventID in (5101, 5001, 5012, 5010)
| order by TimeGenerated desc
```

## Processes add FileName filter
```
 let starttime = 14d;
  let endtime = 1d;
  let ProcessCreationEvents=() {
  let processEvents=SecurityEvent
  | where EventID==4688
  | where TimeGenerated >= ago(starttime) 
  | project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, AccountDomain=SubjectDomainName, FileName=tostring(split(NewProcessName, @'')[(-1)]), ProcessCommandLine = CommandLine, InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine='',InitiatingProcessParentFileName='';
  processEvents};
  ProcessCreationEvents
  | where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
  | summarize HostCount=dcount(ComputerName) by tostring(FileName)
  | join kind=rightanti (
      ProcessCreationEvents
      | where TimeGenerated >= ago(endtime)
      | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Computers = makeset(ComputerName) , HostCount=dcount(ComputerName) by tostring(FileName)
  ) on FileName
  | where FileName !has_any("conhost.exe")
  | project StartTimeUtc, Computers, HostCount, FileName
  | extend timestamp = StartTimeUtc

## PowerShell stuff
```
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any("WebClient","DownloadFile","DownloadData","DownloadString","WebRequest","Shellcode","http","https")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, 
FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType
| top 100 by Timestamp
```
