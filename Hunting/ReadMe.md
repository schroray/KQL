# From Threat Report to (KQL) Hunting Query
Src: https://kqlquery.com/posts/from-threat-report-to-hunting-query/

## [Schematic Process](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#schematic-process)

Schematic Process from Threat Report to hunting results
![image](https://github.com/schroray/KQL/assets/4217443/0b334c23-6817-4132-8a44-96a4c6683ba4)

## [Knowing Your Data](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#knowing-your-data)

| Table	| Indicator | 
| --- | --- | 
| **DeviceNetworkEvents**	| IP, DNS, URL | 
| **EmailEvents**	| DNS, Emailaddresses | 
| **DeviceRegistryEvents**	| RegistryKey | 
| **DeviceFileEvents**	| FileNames, Hashes, Tools | 
| **DeviceProcessEvents**	| Commands, Tools | 

## [Hunting Atomic IOCs](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#hunting-atomic-iocs)

### [IPs](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#ips)

The array is the starting point for a hunting query. Since the Potential IOC IP Addresses for compromise or exfiltration are related to network events, the DeviceNetworkEvents table is the best one to search for matches, resulting in the query below. The query uses the [in()](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/in-cs-operator) operator, only if a RemoteIP is equal to one of the IPs from the IPList results will be returned. If those IPs would have been related to sources from where adversaries sign in to your cloud applications the AADSignInEventsBeta in MDE or the SigninLogs in Sentinel could be leveraged to hunt for those sign-ins.

```KQL
let IPList = dynamic(["84.32.188.57", "84.32.188.238", "93.115.26.251", "185.8.105.67", 
"181.231.81.239", "185.8.105.112", "186.111.136.37", "192.53.123.202", "158.69.36.149", 
"46.166.161.123", "108.62.118.190", "46.166.161.93", "185.247.71.106", "46.166.162.125", 
"5.61.37.207", "46.166.162.96", "185.8.105.103", "46.166.169.34", "5.199.162.220", "93.115.25.139"]);
DeviceNetworkEvents
| where RemoteIP in (IPList)
```

### [Domains](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#domains)
In the reports, four domains can be found, even though they are not the strongest indicators they could still be useful depending on your available data. If you do not have any process-based events it could be useful to leverage the firewall logs to hunt for sources that connect to those domains. In the case of this blog, we will again focus on the DeviceNetworkEvents. The query is slightly different than the one for IPs, in this case, the [has_any()](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/has-anyoperator) operator is used, this function is in essence a contains based on a input list.

This textual indicator can be translated to a KQL query as seen below. The DeviceFileEvents table is the best one to find files that have been created in a particular location, if the file had to be executed the DeviceProcessEvents would have been your best choice. First, we filter most of the events by only selecting filenames that end with .key. This filter is made first because it will improve the speed of the query. parse_path will longer, thus with the filtered result only a subset of the rows needs to be parsed to collect the RootPath and DirectoryPath. The rest of the query filters only on file creations in the *C:* directory.

```KQL
let Domains = dynamic(["assist.zoho.eu", "eu1-dms.zoho.eu", "fixme.it", "unattended.techinline.net"]);
DeviceNetworkEvents
| where RemoteUrl has_any (Domains)
```

## [Hunting Patterns and Behaviors](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#hunting-patterns-and-behaviors)https://kqlquery.com/posts/from-threat-report-to-hunting-query/#hunting-patterns-and-behaviors

```KQL
```

### [File Based Behaviors](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#file-based-behaviors)

Starting with the first example of behaviours that are mentioned in the reports is storing a *.key file in the root directory.

```KQL
DeviceFileEvents
| where FileName endswith ".key"
| extend FolderDetails = parse_json(parse_path(FolderPath))
| extend RootPath = tostring(FolderDetails.RootPath), 
    DirectoryPath = tostring(FolderDetails.DirectoryPath)
| where RootPath == @"C:\" and DirectoryPath == "C:"
| project-reorder Timestamp, FolderPath, PreviousFileName
```

### [Process Based Behaviours](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#process-based-behaviors)
Next up are the process-based behaviours, which are the most valuable of all the indicators mentioned in the threat reports. This is also in some essence shown in the tables containing the IOCs, the fidelity column classifies all the commands as _high_. As could already be derived from the name of this behaviour we need to have logs that relate to processes and their creation, this can come in many forms, such as DeviceProcessEvents, SecurityEvents or Syslog. 

To show the workings I have taken a subset of the commands mentioned above and put them in a dynamic list, but to improve the results I have not put the whole command in this list, only the variables. The separation between the variable and the file that initiates the command is done because the command line logs can differ for example “wevtutil.exe” cl system will not be matched if I had put all the full commands in the dynamic list. The second list is all the files that initiate the commands, they are logged in a separate field and can thereby be used as a filter, resulting in the query below.

```KQL
let Commands = dynamic(['cl system','cl security', 'cl application', @'delete shadows /all /quiet', 
    'list shadows', @'shadowcopy /nointeractive', @'shadowcopy delete']);
let IntiatingFiles = dynamic(['wevtutil.exe', 'vssadmin.exe', 'wmic.exe', 'bcdedit.exe', 'rundll32.exe']);
DeviceProcessEvents
| where ProcessCommandLine contains "wevtutil.exe"
| where FileName in~ (IntiatingFiles)
| extend ToLowerProcessCommandLine = tolower(ProcessCommandLine)
| project ProcessCommandLine, FileName, DeviceName
```

#### Wevutil.exe

```KQL
DeviceProcessEvents
| extend ProcessCommandLineToLower =  tolower(ProcessCommandLine)
| where ProcessCommandLineToLower has "wevtutil.exe" and ProcessCommandLineToLower has_any ("cl", "clear-log")
| project-reorder Timestamp, DeviceName, AccountSid, ProcessCommandLine, InitiatingProcessCommandLine 
```

#### Taskkill

```KQL
let TotalKilledThreshold = 10;
let TotalParametersThreshold = 10;
DeviceProcessEvents
| where FileName == "taskkill.exe"
| extend CommandLineParameters = split(ProcessCommandLine, " ")
| extend TotalParameters = array_length(CommandLineParameters)
// Extract allSQL related processes in the CommandLineParameters
| mv-apply KilledProcess = CommandLineParameters on (
    where KilledProcess contains "sql"
    | project KilledProcess
)
| summarize arg_max(Timestamp, *), AllKilledProcess = make_set(KilledProcess) by ReportId
| extend TotalKilledProcesses = array_length(AllKilledProcess)
| project-reorder Timestamp, ProcessCommandLine, TotalParameters, TotalKilledProcesses
| where TotalKilledProcesses >= TotalKilledThreshold and TotalParameters >= TotalParametersThreshold
```

## [Detecting Ransomware Threats](https://kqlquery.com/posts/from-threat-report-to-hunting-query/#detecting-ransomware-threats)
To strengthen your detection and/or hunting capabilities the [KQL Repository](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) contains queries that can help you develop those capabilities. This section will discuss some of those queries and what value they could bring to your environment.

| KQL Query	| Description	| MITRE Technique	| 
|	--- | --- | --- |
| [ASR Ransomware Trigger](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/ASR%20Rules/AsrRansomware.md)		| This query detects when the ASR rule AsrRansomwareBlocked or AsrRansomwareAudited is triggered. MDE uses client and cloud heuristics to determine if a file resembles ransomware. This file could for example be the script that is used to encrypt files. No alert is generated by default by Defender For Endpoint, therefore it is recommended to create a custom detection rule to alert on this ASR trigger.		| T1486	| 
| [Ransomware Note Search](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/Ransomware%20-%20APTNotesSHA1IOC.md)		| This query ingests SHA1 hashes of ransomware notes and searches in your environment if a match is found.		| 	| 
| [Shadow Copy Deletion](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/ShadowCopyDeletion.md)		| This query detects when a known ransomware command is used to delete shadow copies. A shadow copy is a backup or snapshot of a system, and often deleted by ransomware groups.		| T1490	| 
| [Anomalous amount of SMB sessions](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/AnomalousSMBSessionsCreated.md)		| This query is aimed to detect a host that performs SMB discovery by alerting if a device creates more then 100 (configurable) unique SMB sessions within 15 minutes. That is one of the characteristics of discovery/reconnaissance tools. The SMB sessions can be used to identify remote systems, which is often done to map the network.		| T1018	| 
