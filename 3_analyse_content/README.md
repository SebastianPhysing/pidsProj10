# Create Own PostgresSQL Database
PIDSMaker database (in dedicated Docker container) uses four tables with according attributes.  
In order to be able to reference nodes we start with the three different  node types: Netflow, File, Subject/Process.
## Netflow : Node
| Attribute Name | Type | CADETS_E3 | OpTC | Dedale (Winlogbeat) |
|:-------------- |:----:|:---------:|:----:|:---------------------|
| **node_uuid**  | VARCHAR NOT NULL | `CDM.NetFlowObject.uuid` | `objectID` | Sysmon[3]: `sha256(host + "|netflow|" + dst_ip + ":" + dst_port)`<br>Sysmon[22]: `sha256(host + "|netflow|" + resolved_ip)` |
| **hash_id**    | VARCHAR NOT NULL | SHA‑256(UUID) | SHA‑256(src,dst) | SHA‑256(UUID) |
| **src_adr**    | VARCHAR | `localAddress` | `src_ip` | Sysmon[3]: `source.ip` |
| **src_port**   | VARCHAR | `localPort` | `src_port` | Sysmon[3]: `source.port` |
| **dst_adr**    | VARCHAR | `remoteAddress` | `dst_ip` | Sysmon[3]: `destination.ip`<br>Sysmon[22]: `dns.resolved_ip[]` |
| **dst_port**   | VARCHAR | `remotePort` | `dst_port` | Sysmon[3]: `destination.port`<br>Sysmon[22]: `None` |
| **index_id**   | BIGINT | ascending | ascending | ascending |




## Subject : Node
| Attribute Name | Type | CADETS_E3 | OpTC | Dedale (Winlogbeat) |
|:-------------- |:----:|:---------:|:----:|:---------------------|
| **node_uuid**  | VARCHAR NOT NULL | `CDM.ProcessObject.uuid` | `objectID` (process UUID) | Sysmon[1,2,3,7,8,9,10,11,15,17,18,22]: `process.entity_id`<br>Sysmon[26]: `winlog.event_data.ProcessGuid` |
| **hash_id**    | VARCHAR NOT NULL | SHA‑256(UUID) | SHA‑256(UUID) | SHA‑256(UUID) |
| **path**       | VARCHAR | `imageFileName` | `exe_path` | Sysmon[all EIDs]: `process.executable`<br>Sysmon[26]: `winlog.event_data.Image` |
| **cmd**        | VARCHAR | `cmdLine` | `cmd_line` | Sysmon[1]: `process.command_line`<br>Sysmon[others]: often NULL |
| **index_id**   | BIGINT | ascending | ascending | ascending |


## File : Node
| Attribute Name | Type | CADETS_E3 | OpTC | Dedale (Winlogbeat) |
|:-------------- |:----:|:---------:|:----:|:---------------------|
| **node_uuid**  | VARCHAR NOT NULL | `CDM.FileObject.uuid` | `objectID` | Sysmon[all file events]: `sha256(host + "|file|" + path)` |
| **hash_id**    | VARCHAR NOT NULL | SHA‑256(UUID) | SHA‑256(UUID) | SHA‑256(UUID) |
| **path**       | VARCHAR | `filePath` | `file_path` | Sysmon[2,7,9,11,15]: `file.path`<br>Sysmon[26]: `winlog.event_data.TargetFilename`<br>Sysmon[17,18]: built pipe path `\\\\.\\pipe\\<file.name>` |
| **index_id**   | BIGINT | ascending | ascending | ascending |


## Event Table : Edges
| Attribute Name | Type | CADETS_E3 | OpTC | Dedale (Sysmon[EID]) |
|:-------------- |:----:|:---------:|:----:|:---------------------|
| **src_node**   | VARCHAR | `src_uuid` | `src_objectID` | Sysmon[all]: subject or file or netflow node UUID |
| **src_index_id** | BIGINT | index of src node | index of src node | ascending index assigned in write phase |
| **operation**  | VARCHAR | CDM.OperationType | `edge_type` | Sysmon[EID]: mapped to {EVENT_CLONE, EVENT_EXECUTE, EVENT_READ, EVENT_WRITE, EVENT_OPEN, EVENT_CONNECT, EVENT_SENDMSG} |
| **dst_node**   | VARCHAR | `dst_uuid` | `dst_objectID` | Sysmon[all]: subject or file or netflow node UUID |
| **dst_index_id** | BIGINT | index of dst node | index of dst node | ascending index assigned in write phase |
| **event_uuid** | VARCHAR NOT NULL | unique event ID | unique event ID | Sysmon: `sha256(host + "|" + record_id + "|" + edge_count)` |
| **timestamp_rec** | BIGINT | event timestamp | event timestamp | Sysmon: nanoseconds from `@timestamp` |





# Set Own Config File
In the tables no information about the training is stored. Like information about benign or infected data. Therefore for each dataset a config file is specified, containing all the information about train_dates, val_dates, test_dates, attack_to_time_windows and more, see pdismaker/config/configy.py or in the [docs](https://ubc-provenance.github.io/PIDSMaker/datasets/#adding-custom-datasets).

## How the information of the tables was found:
There is no explicit doucmentation what the columns of tables mean or rather expect. To answer this question, I took a look at the implementation of the parsers of [OpTC](https://github.com/ubc-provenance/PIDSMaker/tree/main/dataset_preprocessing/optc) and [Cadets](https://github.com/ubc-provenance/PIDSMaker/blob/main/dataset_preprocessing/darpa_tc/create_database_e3.py) and additionaly at the [graph generation](https://github.com/ubc-provenance/PIDSMaker/blob/main/pidsmaker/preprocessing/build_graph_methods/build_default_graphs.py). If you type "Sysmon" in the searchbar of the PIDSMaker documentation website, *ATLASv2* appears. It includes Sysmon, unfortunatlly, the parser is not provided and therefore it can not be said to which degree it is used. 