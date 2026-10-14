# Helper functions for parser (main.py) and ground_truth generation function

# The code is partilly written with the help of AI.

import hashlib
from datetime import datetime, timezone


def get_hash_id(node_uuid):
    # Same hashing as stringtomd5() in PIDSMaker, which is sha256 despite its name
    return hashlib.sha256(str(node_uuid).encode("utf-8")).hexdigest()


def generate_uuid(host, kind, key):
    # File and netflow nodes need a generated one. The host is part of the input,
    # so the same path on two machines stays two different nodes.
    return hashlib.sha256((host + "|" + kind + "|" + key).encode("utf-8")).hexdigest()


def to_nanoseconds(timestamp):
    # based on OpTc parser
    # '2025-01-06T10:01:05.579Z', the graph builder computes in nanoseconds
    date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return int(date.timestamp() * 1_000_000_000)


def get(event, *keys):
    # Most fields are optional, only winlog is always there
    value = event
    for key in keys:
        if not isinstance(value, dict): # whether subfields exist
            return None
        value = value.get(key)
        if value is None:
            return None
    return value