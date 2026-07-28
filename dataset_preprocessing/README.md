# Create Own PostgresSQL Database
PIDSMaker database (in dedicated Docker container) uses four tables with according attributes.  
In order to be able to reference nodes we start with the three different  node types: Netflow, File, Subject/Process.
## Netflow : Node
|Attribute Name|Type|Set of Values|Desescription|
|:-------------|:--:|:---------:|:-----------:|
|*node_uuid*   |VARCHAR NOT NULL |Lorem ipsum|Lorem ipsum|
|*hash_id*   |VARCHAR NOT NULL   |Lorem ipsum|Lorem ipsum|
|src_adr   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|src_port   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|dst_adr  |VARCHAR   |Lorem ipsum|Lorem ipsum|
|dst_port  |VARCHAR NOT NULL  |Lorem ipsum|Lorem ipsum|
|index_id   |BIGINT   |[0,1, ...]|Regardless of the node type, every node gets a ascending index number.|

cylab: Security something with src_adr/port and dst_adr/port
## Subject|Process : Node
|Attribute Name|Type|Set of Values|Desescription|
|:-------------|:--:|:---------:|:-----------:|
|*node_uuid*   |VARCHAR NOT NULL |Lorem ipsum|Raw Uuid (Uuid 64 ignored??)|
|*hash_id*   |VARCHAR NOT NULL   |Lorem ipsum|Hash of Uuid?!|
|path   |VARCHAR   |["null", ...]|Lorem ipsum|
|cmd   |VARCHAR   |["null", "system_server", ...]|Lorem ipsum|
|index_id   |BIGINT   |[0,1, ...]|Regardless of the node type, every node gets a ascending index number.|
## File : Node
|Attribute Name|Type|Set of Values|Desescription|
|:-------------|:--:|:---------:|:-----------:|
|*node_uuid*   |VARCHAR NOT NULL |Lorem ipsum|Lorem ipsum|
|*hash_id*   |VARCHAR NOT NULL   |Lorem ipsum|Lorem ipsum|
|path   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|index_id   |BIGINT   |[0,1, ...]|Regardless of the node type, every node gets a ascending index number.|



## Event Table : Edges
It models system calls or events.
|Attribute Name|Type|Set of Values|Desescription|
|:-------------|:--:|:---------:|:-----------:|
|src_node   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|*src_index_id*   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|operation   |VARCHAR   |[EVENT_READ, EVENT_WRITE, EVENT_OPEN, ..](https://ubc-provenance.github.io/PIDSMaker/#edge-types)|Lorem ipsum|
|dst_node   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|*src_index_id*   |VARCHAR   |Lorem ipsum|Lorem ipsum|
|event_id   |VARCHAR NOT NULL  |Lorem ipsum|Lorem ipsum|
|timestamp_ec   |BIGINT   |Lorem ipsum|Lorem ipsum|

# Set Own Config File
In the tables no information about the training is stored. Like information about benign or infected data. Therefore for each dataset a config file is specified, containing all the information about train_dates, val_dates, test_dates, attack_to_time_windows and more, see pdismaker/config/configy.py or in the [docs](https://ubc-provenance.github.io/PIDSMaker/datasets/#adding-custom-datasets).