# Commands
List Event Tracing Sessions: `logman query -ets`\
Query Specific Provider: `logman query "EventLog-System" -ets`\
Show providers: `logman query providers`\

Filtering: `$p = logman query providers; $p | ? { $_ -Like "*Security*" }`\
Get Metadata: `logman query providers Microsoft-Windows-Security-Auditing`

# HELK
`git clone https://github.com/Cyb3rWard0g/HELK.git`\
cd HELK/docker`\
sudo ./helk_install.sh`\
tail -f /var/log/helk-install.log`\
sudo docker-compose -f helk-kibana-analysis-alert-basic.yml stop`

# Sentinel
## Attack surface reduction rules - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction?ocid=wd-av-demo-asr-bottom
Search for ASR hits:\
'DeviceEvents'\
'| where ActionType startswith 'Asr''\
