## Strategy for analyzing Dedale's content


### Datasets are large and its costly to download them completely
Therefore we want to download parts of the datasets to get first insights.  
In order to be specify the files we want to download, we need to get a list of files. *Inria* the organization that provides the Dedale dataset, uses "Dataverse". To access files, a URL is required, which has following form: ```https://<SERVER-ADDRESS>/api/access/datafile/:persistentId?persistentId=doi:<DOI-Key>```, [see](https://guides.dataverse.org/en/latest/api/dataaccess.html#basic-file-access). The File Persistent ID (DOI) can be found in the tab *metadata*. To do so:
```console
pip install remotezip
remotezip -l "<YOUR-URL>
```
.e.g. fo the WinlogBeat files, the API URL is: "https://entrepot.recherche.data.gouv.fr/api/access/datafile/:persistentId?persistentId=doi:10.57745/ATR0QO"  
Save output as Text file: append ```> files_winlogbeat.txt``` to the command.  
**Note:** The Download Speed of the website is poorly. Therefore it is strongly recommended to download single files. (If you try to download directly in the browser, you will get download speeds up to 150KB ;-). To download the complete folders, it is best to use *Aria2* and use multiple Connections (16) (see below). The speed increases up to 1.9MB. Still not very fast, but better.
This starts 16 connections and downloads in parallel 16 files. The -c arg guarantees that the download can be resumed.
```console
aria2c -c -x 16 -s 16 -k 1M -o auditbeat_logs.zip "https://entrepot.recherche.data.gouv.fr/api/access/datafile/:persistentId?persistentId=doi:10.57745/PBS4YD"
```
```console
aria2c -c -x 16 -s 16 -k 1M -o winlogbeat_logs.zip "https://entrepot.recherche.data.gouv.fr/api/access/datafile/:persistentId?persistentId=doi:10.57745/ATR0QO"
```

### What can be found in Winbeatlog
Files format: **.jsonl.bz2**
> - **.jsonl**: newline-delimited format, each line contains a valid json value, commonly used for streaming data (not the whole dataset needs to loaded in memory)
> - **.bz2**: bzip2 compression  

One example: "daily_winlogbeat/D3_H15_2024-12-25T15_winlogbeat_F64.jsonl.bz2"  
The file contain the output of Winlogbeat, hourly for a specifc day. For our example: Day 3, Hour 15.  So now we download a file and take a look inside, to do so:
```console
URL=$"https://entrepot.recherche.data.gouv.fr/api/access/datafile/:persistentId?persistentId=doi:10.57745/ATR0QO"
FILE=$"daily_winlogbeat/D1_H9_2024-12-23T09_winlogbeat_F10.jsonl.bz2"
remotezip "$URL" "$FILE"
```

You can find the file in *Dedale/winlogbeat/daily_winlogbeat/D1_H9_2024-12-23T09_winlogbeat_F10.jsonl.bz2*.  

**Winlogbeat** is a Ingestion tool by *Elasticsearch*. It ships Windows event logs and transforms them in a Elastic Common Schema (ECS). Thereby event data gets normalized to ease further processing. Winlogbeats can capture data from any event logs, e. g. *Application, Security, System*. It can freely be configured.  
This is done in **Rescousse** (the testbed for data generation of Dedale). You can find it [here](https://gitlab.inria.fr/mlanvin/rescousse/-/blob/main/provisioning/ansible/roles/configure_intcompanyclient_win10/files/winlogbeat/winlogbeat.yml). It is configured to provide:
> - Application
> - Security
> - System
> - PowerShell
> - Sysmon  
> Sysmon events are [processed](https://www.elastic.co/docs/reference/beats/winlogbeat/filtering-enhancing-data), see the javascript of [sysmon](https://github.com/elastic/beats/blob/v7.10.2/x-pack/winlogbeat/module/sysmon/config/winlogbeat-sysmon.js#L9)
Sysmon is a Auditing tool based on kernel level. All other channels are on application level. Channel System only presents status alerts, it does represents a object or edge.  
Powershell has a 'process.entity_id' but is not identically with Sysmon's Guid. All channels expect Sysmon do not provide Node identities, like they are expected for the node tables.
A event requires both sides to have such a identifier, therefore these channels can also not provide edges.

Now we want to analyze it, to determine its content. As a first we take a look at the first json entry:
```console
bzcat D1_H9_*.jsonl.bz2 | head -n 1 | jq .
```
> - <b>bzcat</b> .bz2 --> bzcat unpacks in working memory and on the fly --> the file stays comprimissed
> - <b>Pipe |</b>: A|B, the return value of A, will be parsed to B  
> e.g. bzcat file | head -n 1 | jq.
> - <b>head -n 1</b>: return first row and finished, therefore bzcat stops and dont need to unpack the rest --> efficient
> - <b>jq</b>: formats json

We get a first impression what's inside. Top level keys are for example: 
> - @timestamp
> - agent
> - event
> - file
> - host
> - message
> - process 
> - winlog 

The question that arises is whether we find all or some information, to fill the tables of the Postgres database. We have to find out what type of information the columns contains. 
The parser filters for channel and event-id and uses the provided fields to create nodes and edges. A event can create multiple nodes and multiple edges.
You can find the table with the description [here](../README.md)


### What can be found in Auditbeat
Like for winlogbeat: folder daily/auditdbeat with files (.json.bz2) containing all event logs for respective hour.  While there are 30 windows clients, there exist 5 linux server:
> - "dmzserver",
> - "extcompanyclient",
> - "internalserver",
> - "vpnserver",
> - "webserver"  

Field:   
`event.module`: auditd, similiar to winlogbeat.channel, but its the only source provided in this auditbeat data.  
`event.action`: normalized Elastic Auditbeat values (Elastic Common Schema), that is generated of auditd raw data. Its not Auditd message types, that would be SYSCALL, EXECVE, ... . similar to event_id, has fields:
> - acquired-credentials
> - allocated-memory
> - bound-socket
> - changed-audit-configuration
> - changed-file-ownership-of
> - changed-file-permissions-of
> - changed-identity-of
> - connected-to
> - deleted
> - disposed-credentials
> - ended-session
> - executed
> - killed-pid
> - opened-file
> - refreshed-credentials
> - renamed
> - started-service
> - started-session
> - stopped-service
> - was-authorized

