# This file contains the parser for the daily_winlogbeat .jsonl.bz2 files. Every file contains the Elastic Stack (ELK) of Winlogbeat (Elasticsearch).
# Every file contains all entries of one hour. Every jsonl (json line) contains one event send by Winlogbeat Channels [Application, Security, System, PowerShell, Sysmon].
# Every Channel has unique event ids (winlog.event_id). By which the set of fields of a certian event type are mostly identically.
# This Parser only uses Sysmon events. They represent the major part of events (99,5 percent). You can find a list of all unique event types in analyse_content.
# Daily Winlogbeat contains all Host clients of internal Windows Clients (in total 30). But only labels for Client 1 and Client 2 are given.
# While Training in PIDSMaker is self-supervised  and therefore does not require labels, Evaluation expects Labels (found in Ground_Truth). 
# Therefore this parser generates two Postgres dumps (for client 1 & 2). It parses all events, starting from the two weeks with benign activity, going over
# days of attack (starting from 06/01/2025 Email infection of client2) to the last week of normal activity.
# 
# This file is structured in the following way:
#   - enums
#   - helper functions
#   - generation of empty databases
#   - processing of folder with list of files
#   - parser class
#   - main function with Case discrimination

# The code is partilly written with the help of AI.

import argparse
import bz2
import json
import os
from sysmon_events import SYSMON_EID_MAP
import psycopg2
from psycopg2 import extras
from tqdm import tqdm
import subprocess

POSTGRES_CONFIGURATION = {
    "db_host": "localhost",
    "db_port": 5432,
    "db_user": "postgres",
    "db_password": "postgres"
}

# We only take a look at Sysmon Events
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Only these two hosts have labels, so only these two get a database
CLIENTS = ["CLIENT1", "CLIENT2"]


def connect_to_db(name):
    return psycopg2.connect(**POSTGRES_CONFIGURATION, dbname=name)


def generate_two_pgsql_dbs():
    # Arguments are standard of PIDSMaker Setup Tutorial
    # This function generates two empty databases with  empty tables and their respective columns.
    # It uses one connection to PostgresSql, and makes two databases client1 and client2. For each, the empty tables are set.
    # Their dumps are then generated with produce_dumps()

    # Connect to standard existing Postgres Database
    postgres_con = psycopg2.connect(**POSTGRES_CONFIGURATION, dbname="postgres")

    postgres_con.autocommit = True
    postgres_cur = postgres_con.cursor()

    # Remove old Sub-Databases CLIENT1 and CLIENT2 if exisitng
    postgres_cur.execute(f"DROP DATABASE IF EXISTS \"CLIENT1\";")
    postgres_cur.execute(f"DROP DATABASE IF EXISTS \"CLIENT2\";")

    # Create Sub-Databases CLIENT1 and CLIENT2
    postgres_cur.execute(f"CREATE DATABASE \"CLIENT1\";")
    postgres_cur.execute(f"CREATE DATABASE \"CLIENT2\";")

    postgres_cur.close()
    postgres_con.close()

    def create_empty_tables(name):
        db_con = psycopg2.connect(**POSTGRES_CONFIGURATION, dbname=name)
        db_cur = db_con.cursor()
        db_cur.execute("""
                drop table if exists event_table;
                drop table if exists subject_node_table;
                drop table if exists file_node_table;
                drop table if exists netflow_node_table;
        
                create table subject_node_table (
                    node_uuid varchar not null,
                    hash_id   varchar not null,
                    path      varchar,
                    cmd       varchar,
                    index_id  bigint
                );
                create table file_node_table (
                    node_uuid varchar not null,
                    hash_id   varchar not null,
                    path      varchar,
                    index_id  bigint
                );
                create table netflow_node_table (
                    node_uuid varchar not null,
                    hash_id   varchar not null,
                    src_adr   varchar,
                    src_port  varchar,
                    dst_adr   varchar,
                    dst_port  varchar,
                    index_id  bigint
                );
                create table event_table (
                    src_node      varchar,
                    src_index_id  varchar,
                    operation     varchar,
                    dst_node      varchar,
                    dst_index_id  varchar,
                    event_uuid    varchar not null,
                    timestamp_rec bigint,
                    _id           bigserial
                );
                create index event_time_idx on event_table (timestamp_rec);
            """)
        db_con.commit()

        db_cur.close()
        db_con.close()

    # create tables in both databases
    create_empty_tables("CLIENT1")
    create_empty_tables("CLIENT2")
        
    

class Files:
    def __init__(self, path):
        self.folder_path = path 
        self.file_paths = self.get_file_paths() # key: F number, value: path to file
        self.current_F_number = 1 # F number starts at 1 F element [1, 672], it can be seen as an ID (Day 1, Hour 0: F1), Days: 28, Hours: 24: 672 files
        self.current_file = self.open_next_file()

    def get_file_paths(self):
        # All files in self.folder_path that contain F[Number]
        file_dict = {}
        for file_name in os.listdir(self.folder_path):
            if "_F" not in file_name:
                continue
            file_name_ending = file_name.split("_F")[1]
            file_num = int(file_name_ending.split(".")[0])
            file_dict[file_num] = os.path.join(self.folder_path, file_name)
        return file_dict
        
    def open_next_file(self):
        # skip F numbers that are missing, so a subset of the files can be parsed
        while self.file_paths and self.current_F_number not in self.file_paths:
            if self.current_F_number > max(self.file_paths):
                return False
            self.current_F_number += 1

        if self.current_F_number not in self.file_paths:
            # stop after F672
            return False

        path = self.file_paths[self.current_F_number]

        return bz2.open(path, "rt", encoding="utf-8", errors="replace" )
    """def open_next_file(self):
        if self.current_F_number not in self.file_paths.keys():
            # stop after F672
            return False

        path = self.file_paths[self.current_F_number]

        return bz2.open(path, "rt", encoding="utf-8", errors="replace" ) # rt: read text, instead of binaries, replace invalid chars (of UTF-8 encoding) (U+FFFD)"""
        

    def get_next_json_line(self):
    
        if not self.current_file:
            return False
        line = self.current_file.readline()
        # file end:
        if not line:
            self.current_file.close()
            self.current_F_number += 1
            self.current_file = self.open_next_file()
            return self.get_next_json_line()
        return line.strip() # remove spaces, tabs, newlines, at the beginning or at the end
        

class Parser:
    # One Parser per host. The four create_ methods take every field as an argument and
    # know nothing about Sysmon, all of that logic sits in sysmon_events.py.
    # Everything is collected in memory first, because the index_id can only be handed
    # out once all nodes are known. write_to_db() does the writing at the end.

    def __init__(self, host, connection: psycopg2.extensions.connection):
        self.host = host
        
        self.connection = connection
        self.cursor = connection.cursor()

        self.subjects = {} 
        self.files = {}    
        self.netflows = {}
        self.events = []   
                

        self.uuid_to_index = {}

    def num_events(self):
        # for uuid
        return len(self.events)

    def create_subject_node(self, node_uuid, hash_id, path = None, cmd = None):
        # UUid (and hash_id) is mandatory for Subject Node
        if node_uuid not in self.subjects:
            self.subjects[node_uuid] = [hash_id, None, None]

        # possibility to set path/cmd in later events, referencing the same entity (uuid).
        # cmd for example is only written by EID 1, every other event id leaves it empty
        if path:
            self.subjects[node_uuid][1] = path
        if cmd:
            self.subjects[node_uuid][2] = cmd

    def create_file_node(self, node_uuid, hash_id, path):
        # Path is mandatory for File Node (since it is used for uuid)
        self.files[node_uuid] = [hash_id, path]

    def create_netflow_node(self, node_uuid, hash_id, src_adr, src_port, dst_adr, dst_port):
        self.netflows[node_uuid] = [hash_id, src_adr, src_port, dst_adr, dst_port]

    def create_event_edge(self, src_node, operation, dst_node, event_uuid, timestamp):
        self.events.append([src_node, operation, dst_node, event_uuid, timestamp])

    def assign_index_ids(self):
        # creates one index number over all nodes
        index_id = 0
        for node_uuid in list(self.subjects) + list(self.files) + list(self.netflows):
            self.uuid_to_index[node_uuid] = index_id
            index_id += 1

    def write_to_db(self):
        self.assign_index_ids()

        rows = [[u, v[0], v[1], v[2], self.uuid_to_index[u]] for u, v in self.subjects.items()]
        extras.execute_values(self.cursor, "insert into subject_node_table values %s", rows, page_size=10000)

        rows = [[u, v[0], v[1], self.uuid_to_index[u]] for u, v in self.files.items()]
        extras.execute_values(self.cursor, "insert into file_node_table values %s", rows, page_size=10000)

        rows = [[u, v[0], v[1], str(v[2]) if v[2] is not None else None,v[3], str(v[4]) if v[4] is not None else None, self.uuid_to_index[u]]for u, v in self.netflows.items()]
        extras.execute_values(self.cursor, "insert into netflow_node_table values %s", rows, page_size=10000)

        rows = [[src, self.uuid_to_index[src], operation, dst, self.uuid_to_index[dst], event_uuid, timestamp]for src, operation, dst, event_uuid, timestamp in self.events]
        extras.execute_values(self.cursor, "insert into event_table (src_node, src_index_id, operation, ""dst_node, dst_index_id, event_uuid, timestamp_rec) values %s",rows, page_size=50000)

        self.connection.commit()
        print(self.host, ":", len(self.subjects), "subjects,", len(self.files), "files,",
              len(self.netflows), "netflows,", len(self.events), "edges")


def produce_dumps():
    # In order to be fully integratable in the pipeline of PIDSMaker, two dumps that can be loaded with load_dumps.sh (as in the tutorial) are generated.
    for host in CLIENTS:
        subprocess.run(["pg_dump", "-h", POSTGRES_CONFIGURATION["db_host"],"-p", str(POSTGRES_CONFIGURATION["db_port"]),"-U", POSTGRES_CONFIGURATION["db_user"],"-d", host, "-f", host.lower() + ".dump"], check=True)
        
def main():
    # argparser
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=".",help="Path to daily_winlogbeat folder, containing all the .jsonl.bz2 files")
    
    args = parser.parse_args()
    print("Start generation")

    num_skipped_events = 0

    generate_two_pgsql_dbs()

    dedale_winlogbeat = Files(args.path)
    # to visualize the progress
    bar = tqdm(total=len(dedale_winlogbeat.file_paths), desc="Dedale: Wnlogbeat")
    last_file = dedale_winlogbeat.current_F_number

    con_client1 = connect_to_db("CLIENT1")
    con_client2 = connect_to_db("CLIENT2")

    parser_client1 = Parser("CLIENT1", con_client1)
    parser_client2 = Parser("CLIENT2", con_client2)

    json_line = dedale_winlogbeat.get_next_json_line()
    while json_line:
        # tqdm
        if dedale_winlogbeat.current_F_number != last_file:
            bar.update(1)
            last_file = dedale_winlogbeat.current_F_number


        
        event = json.loads(json_line)

        # TODO: possibilty to optimize, no need to check channel and event, check host in advance

        # Extract Channel und Event ID
        channel = event.get("winlog",{}).get("channel") # if key winlog does not exist, return empty dict, if not channel exits, return None
        if channel != SYSMON_CHANNEL:
            json_line = dedale_winlogbeat.get_next_json_line()
            num_skipped_events += 1
            continue

        eid = event.get("winlog",{}).get("event_id") # if key winlog does not exist, return empty dict, if not event_id exits, return None
        if eid is None:
            json_line = dedale_winlogbeat.get_next_json_line()
            num_skipped_events += 1
            continue

        # Filter for Host
        host = event.get("agent",{}).get("name")
        if host == "CLIENT1":
            host_parser = parser_client1
        elif host == "CLIENT2":
            host_parser = parser_client2
        else: 
            json_line = dedale_winlogbeat.get_next_json_line()
            num_skipped_events += 1
            continue

        # Lookup Case and what to parse
        # Event ids without an object (5 terminate, 25 tampering, 255 error) have no
        # handler, they are skipped
        handler = SYSMON_EID_MAP.get(eid)
        if handler is None:
            json_line = dedale_winlogbeat.get_next_json_line()
            num_skipped_events += 1
            continue

        handler(host_parser, event)

        # Next Json Line
        json_line = dedale_winlogbeat.get_next_json_line()

    parser_client1.write_to_db()
    parser_client2.write_to_db()

    con_client1.close()
    con_client2.close()

    bar.close()
    

    produce_dumps()

    print("skipped events:", num_skipped_events)
    print("Finished.")


if __name__ == "__main__":
    main()