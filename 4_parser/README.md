## DEDALE Winlogbeat Parser for PIDSMaker
This parser takes the DEDALE winlogbeat logs (the hourly ```.jsonl.bz2``` files from ```daily_winlogbeat```) and bring them in the format which PIDSMaker expects (PostgreSQL tables like in the standard datasets, e.g. cadets_e3). There are the following files:  
>- <b>main.py</b> s  
> -> main logic, reads files and prcesses line by line and directs it to the according event handling in sysmon_events.py
>- <b>sysmon_events.py</b>   
> -> encapsulates the individual sysmon event handling
>- <b>utils.py</b>  
> --> helper functions (hashing, uuid generation, timestamps)
>- <b>create_ground_truth.py</b>  
> --> produces the labels (node csv files) needed for the evaluation in PIDSMaker


## How it Works
This script is intended for the use on a cluster. Dedale proposes labels for two windows clients ("CLIENT1", "CLIENT2") and one linux server ("internalserver"). While training in PIDSMaker is self-supervised, whereby it is also possible to train the model with other clients (e.g. "CLIENT30"). For Evaluation we of course need labels. Our parser uses only "CLIENT1" and "CLIENT2" and parses them in two distinct databases in Postgres in one run.  

<b>Keep in mind:</b> Due to the fact, directly writes in the postgres database, preexisting databases with names "CLIENT1" and "CLIENT2" will be overwritten. There is no need to use `load_dumps.sh`. No dumps are created automatically. But if you want to you can do so by:
```console
pg_dump -h localhost -p 5432 -U postgres -d "CLIENT1" -f client1.dump
pg_dump -h localhost -p 5432 -U postgres -d "CLIENT2" -f client2.dump
```  
Afterward you can just use it like for the standard datasets (put in ```data```), the `load_dumps.sh` and they will be written in your local postgres database.  


## How To Use
### <b>1.</b> Parse events and create databases
<b>Keep in mind:</b> It takes a decent amount of RAM, because all handeled events are stored in the database as a last step. For (faster) download speed refer to 3_analyse_content.

Download and unzip the winlogbeat logs of DEDALE (```system_logs_winlogbeat.zip```). You get a folder ```daily_winlogbeat``` with 672 files (28 days * 24 hours). Every `jsonl` file has in its name a <b>F number</b> in range [1, 672].  
Depending whether you use your localhost on your computer with docker or you use apptainer on a cluster, you have to adjust the Port (at start of main.py and create_ground_truth.py).
```console
python main.py --path daily_winlogbeat
```
A progress bar shows how many files are already done. You can check the succeed by looking in the postgrest database (see 1_setupHPC for usefull commands)


### <b>2.</b> Ground Truth generation
For evaluation of the models performance, we need labels. Dedale provides two files: `malicious_events_class_1` and `malicious_events_class_1_and_2`. We only use class 1 events, events that are directly associated with the attack, not are a result of. The files contain all events (in same format as for all events in daily_winlogbeat). To ensure that the <b>Guids</b> are consistent with the database, we use the same handlers like in ```main.py```. 
You get two files in the same format like the standard datasets:
```
node_client1_class_1.csv
node_client2_class_1.csv
```

## How the Parser works in detail
Winlogbeat sends events of several channels: Application, Security, System, PowerShell and Sysmon. Only the channel ```Microsoft-Windows-Sysmon/Operational``` is used. The reasons:
- Sysmon is the major part of the data (99,5 percent of all events)
- PIDSMaker uses a graph with nodes and edges. Representing subjects, Files, Netflow and Events. Sysmon events have exactly this: who did what with what. 
A PIDS Graph only represents a single machine and not a network of multiple clients and servers.


### Which Sysmon events are used
First of all sysmon provides a field ```winlog.event_id```. This determines the Sysmon Event and its fields, [see](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events). Only event ids are used, that contain a subject and an object. The edges are created in inspiration of ```rel2id_darpa_tc```. Therefore the graph is comparable to CADETS and THEIA. You can find a list of Edge types created by respective sysmon events. For more informatin, take a look at ```sysmon_events.py```

| EID | Sysmon Event | Edge | Direction |
|---|---|---|---|
| 1 | Process creation | ```EVENT_CLONE``` | parent process -> child process |
| 1 | Process creation | ```EVENT_EXECUTE``` | executable file -> child process (reversed) |
| 2 | File creation time changed | ```EVENT_WRITE``` | process -> file |
| 3 | Network connection | ```EVENT_CONNECT``` | process -> netflow |
| 7 | Image loaded (DLL) | ```EVENT_READ``` | file -> process (reversed) |
| 8 | CreateRemoteThread | ```EVENT_CLONE``` | process -> target process |
| 9 | RawAccessRead | ```EVENT_READ``` | file -> process (reversed) |
| 10 | Process accessed | ```EVENT_OPEN``` | target process -> process (reversed) |
| 11 | File created | ```EVENT_WRITE``` | process -> file |
| 15 | File stream created | ```EVENT_WRITE``` | process -> file |
| 17 | Pipe created | ```EVENT_WRITE``` | process -> pipe (file node) |
| 18 | Pipe connected | ```EVENT_OPEN``` | pipe -> process (reversed) |
| 22 | DNS query | ```EVENT_SENDMSG``` | process -> netflow |
| 26 | File delete | ```EVENT_WRITE``` | process -> file |

You can easily add new events or change their handling by writing a new method in ```SysmonHandlers``` (```sysmon_events.py```) and add it to ```SYSMON_EID_MAP```. The parser automatically will account for that too.


### One Event produces multiple nodes and edges
A sysmon event is not like a PIDSMaker edge. An event describes a situation with several entities being involved. For every entity described in an event, a node is created (provided the node does not already exist) and an edge for every relation.  
Nodes are only created once. If a later event reference the same entity again (same uuid), the exisitng node is used.


The unique node uuids come from:
>- <b>subject:</b> ```process.entity_id```, the Sysmon ProcessGuid (e.g. ```{416dd0c5-1896-6769-eb03-000000000000}```). It is unique and has not the problem of reused PIDs.
>- <b>file:</b> there is no id in the data, so it is generated: ```sha256(host + "|file|" + path)```. The host is part of it, so the same path on the two clients stays two different nodes.
>- <b>netflow:</b> also generated: ```sha256(host + "|netflow|" + dst_adr:dst_port)```. The source port is not part of it on purpose, since Windows chooses it random



Here are two examples to show this (fields are shortened, only the ones that are used):

### Example 1: EID 1 - Process Creation (3 Nodes, 2 Edges)
(Only relevant field are shown below)
```json
{
  "@timestamp": "2025-01-06T10:01:05.579Z",
  "agent": { "name": "CLIENT2" },
  "winlog": { "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "record_id": 123456 },
  "process": {
    "entity_id": "{416dd0c5-1896-6769-eb03-000000000000}",
    "executable": "C:\\Windows\\System32\\smss.exe",
    "command_line": "\\??\\C:\\Windows\\system32\\autochk.exe *",
    "parent": {
      "entity_id": "{416dd0c5-1896-6769-ea03-000000000000}",
      "executable": "C:\\Windows\\System32\\wininit.exe",
      "command_line": "\\SystemRoot\\System32\\smss.exe 00000080 00000084 "
    }
  }
}
```


So this one event contains <b>three entities</b> and therefore creates up to three nodes:

| Node | Type | uuid from | Attributes |
|---|---|---|---|
| child | subject | ```process.entity_id``` | path = ```process.executable```, cmd = ```process.command_line``` |
| parent | subject | ```process.parent.entity_id``` | path = ```process.parent.executable```, cmd = ```process.parent.command_line``` |
| image | file | generated from ```process.executable``` | path = ```process.executable``` |

And <b>two edges</b>, because there are two relations:
- parent -> child, ```EVENT_CLONE```: the parent process started the child. This is the process tree.
- image -> child, ```EVENT_EXECUTE```: the executable file was executed and became the child process. The handler adds it as child -> image, but since ```EXECUTE``` is in the reversed list, it is stored as image -> child (the information flows from the file into the process). Like in DARPA, ```EVENT_EXECUTE``` is not the parent/child relation, that is ```EVENT_CLONE```.

EID 1 is also the only event which has the command line. Every other event only knows the id and the path of the process.

### Example 2: EID 22 - DNS Query (2 Nodes, 1 Edge)
```json
{
  "@timestamp": "2025-01-06T10:03:12.117Z",
  "agent": { "name": "CLIENT2" },
  "winlog": { "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 22, "record_id": 123789 },
  "process": {
    "entity_id": "{416dd0c5-1896-6769-eb03-000000000000}",
    "executable": "C:\\Windows\\System32\\svchost.exe"
  },
  "dns": {
    "question": { "name": "example.com" },
    "resolved_ip": ["131.107.255.255", "131.107.255.254"]
  }
}
```


So the event contains <b>two entities</b>:

| Node | Type | uuid from | Attributes |
|---|---|---|---|
| process | subject | ```process.entity_id``` | path = ```process.executable```, cmd stays empty |
| resolved address | netflow | generated from ```dns.resolved_ip[0]``` | dst_adr = first resolved ip, src_adr, src_port, dst_port stay empty |

And <b>one edge</b>:
- process -> netflow, ```EVENT_SENDMSG```: the process send a message (the request) to the network. Not reversed.

For more examples refer to the `sysmon_events.py` the indiviual events are documented.


