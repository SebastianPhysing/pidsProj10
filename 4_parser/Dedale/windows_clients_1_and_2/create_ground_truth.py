# This file produces the groundtruth labeling, required for evaluation in PIDSMaker.
# All node types (subject, file, netflow) that appear in Dedale's malicious events are labeled,
# no additional filtering is done on our side.
#
# The node uuids of files and netflows are not part of the raw data, they are constructed by
# the parser in sysmon_events.py. To guarantee that the uuids here are identical to the ones
# in the database, the malicious events are fed through the very same handlers instead of
# rebuilding the uuid logic a second time.

# The code is partilly written with the help of AI.

import argparse
import csv
import json
import psycopg2

from main import Parser, connect_to_db, SYSMON_CHANNEL
from sysmon_events import SYSMON_EID_MAP

CLIENTS = ["CLIENT1", "CLIENT2"]


def collect_malicious_nodes(path, parsers):
    # same filter chain as in main.py
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue

        event = json.loads(line)

        if event.get("winlog", {}).get("channel") != SYSMON_CHANNEL:
            continue

        eid = event.get("winlog", {}).get("event_id")
        if eid is None:
            continue

        host = event.get("agent", {}).get("name")
        if host not in parsers:
            continue

        handler = SYSMON_EID_MAP.get(eid)
        if handler is None:
            continue

        handler(parsers[host], event)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default="labels_clients_1_and_2/malicious_events_class_1.jsonl",
                        help="Path to the malicious events class 1, provided.")
    args = parser.parse_args()

    connections = {host: connect_to_db(host) for host in CLIENTS}
    # the parsers are only used in memory, write_to_db() is never called
    parsers = {host: Parser(host, connections[host]) for host in CLIENTS}

    collect_malicious_nodes(args.path, parsers)

    for host in CLIENTS:
        mal_subjects = set(parsers[host].subjects)
        mal_files = set(parsers[host].files)
        mal_netflows = set(parsers[host].netflows)

        cur = connections[host].cursor()
        rows = []

        # subjects
        cur.execute("select node_uuid, path, cmd, index_id from subject_node_table;")
        for node_uuid, node_path, cmd, index_id in cur.fetchall():
            if node_uuid in mal_subjects:
                rows.append([node_uuid, "{'subject': '%s %s'}" % (node_path, cmd), index_id])

        # files
        cur.execute("select node_uuid, path, index_id from file_node_table;")
        for node_uuid, node_path, index_id in cur.fetchall():
            if node_uuid in mal_files:
                rows.append([node_uuid, "{'file': '%s'}" % node_path, index_id])

        # netflows
        cur.execute("select node_uuid, src_addr, src_port, dst_addr, dst_port, index_id from netflow_node_table;")
        for node_uuid, src_adr, src_port, dst_adr, dst_port, index_id in cur.fetchall():
            if node_uuid in mal_netflows:
                rows.append([node_uuid, "{'netflow': '%s:%s->%s:%s'}" % (src_adr, src_port, dst_adr, dst_port), index_id])

        cur.close()

        # nodes that are in the label file but not in the database (e.g. because only a
        # subset of the days was parsed) are reported, so the difference is not silent
        found = {r[0] for r in rows}
        missing = (mal_subjects | mal_files | mal_netflows) - found

        out_file = "node_" + host.lower() + "_class_1.csv"  # naming as in the standard datasets
        with open(out_file, "w", newline="", encoding="utf-8") as f:
            csv.writer(f, lineterminator="\n").writerows(rows)

        print(host, ":",
              len([r for r in rows if "'subject'" in r[1]]), "subjects,",
              len([r for r in rows if "'file'" in r[1]]), "files,",
              len([r for r in rows if "'netflow'" in r[1]]), "netflows",
              "->", out_file)
        if missing:
            print("   ", len(missing), "labeled nodes not found in the database")

    for con in connections.values():
        con.close()

    print("Finished.")


if __name__ == "__main__":
    main()

