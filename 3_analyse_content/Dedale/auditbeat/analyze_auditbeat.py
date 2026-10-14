"""
Analyze all auditbeat files of the DEDALE dataset.

Same idea as analyze_dedale.py, but auditbeat has no winlog.channel and no
winlog.event_id. So the script first looks for fields that could play the role
of an event type (few different values, present in most events) and then groups
everything by the key you choose.

It reads every .jsonl.bz2 file one after another and collects:
  - how many events there are
  - which hosts appear (counted over ALL hosts, not only the filtered one)
  - which event types occur and how often
  - which fields are used by which event type, and how often they are filled
  - up to 5 different example values for every field

Everything except the host count is computed for one host only (--host).

The result is written to a json file. That file is rewritten after every input
file, so you can look at the current state while it is still running.

Usage:
    python3 analyze_auditbeat.py /path/to/daily_auditbeat
    python3 analyze_auditbeat.py /path/to/daily_auditbeat --limit 3
    python3 analyze_auditbeat.py /path/to/daily_auditbeat --key event.module,event.action
    python3 analyze_auditbeat.py /path/to/daily_auditbeat --key auditd.message_type
"""
#  python3 analyze_auditbeat.py ../../../4_parser/Dedale/internal_server_linux/daily_auditbeat 
import argparse
import bz2
import json
import os
import re

from collections import Counter

# File names look like the winlogbeat ones:
#   D14_H18_2025-01-05T18_auditbeat_F331.jsonl.bz2
FILENAME_PATTERN = re.compile(r"D(\d+)_H(\d+)_(\d{4}-\d{2}-\d{2})T\d+_\w+_F(\d+)")

# Only this host has labels (system_labels/internal_server), so it is the default
DEFAULT_HOST = "internalserver"

# Fields that are checked first when looking for the event type. They are tried in
# this order, the first one that exists in the data is used.
KEY_CANDIDATES = [
    "event.module,event.action",
    "event.module,event.category",
    "auditd.message_type",
    "event.action",
    "event.dataset",
]

# how many different example values we keep per field
MAX_EXAMPLES = 5

# a field with few different values is a category, one with many is an identifier.
# only the first group is useful as an event type.
MAX_CARDINALITY_FOR_KEY = 200


def get_file_info(path):
    """Read day, hour and file number out of the file name."""
    match = FILENAME_PATTERN.search(os.path.basename(path))
    if match is None:
        return None
    return {
        "day": int(match.group(1)),
        "hour": int(match.group(2)),
        "date": match.group(3),
        "file_number": int(match.group(4)),
    }


def collect_files(directory):
    """Find all .bz2 files. Sort by file number if the names contain one."""
    files = []
    for name in os.listdir(directory):
        if not name.endswith(".bz2"):
            continue
        full_path = os.path.join(directory, name)
        info = get_file_info(full_path)
        number = info["file_number"] if info else 0
        files.append((number, name, full_path))
    files.sort()
    return [path for _, _, path in files]


def walk_fields(value, prefix=""):
    """
    Go through a json object and yield (field_name, value) for every value that
    is not a dict or a list.

    List indices are collapsed, so auditd.paths.0.name and auditd.paths.1.name
    both become auditd.paths[].name. Auditbeat puts a lot into lists, without
    this the field list would explode.
    """
    if isinstance(value, dict):
        for key in value:
            if prefix == "":
                new_prefix = key
            else:
                new_prefix = prefix + "." + key
            for item in walk_fields(value[key], new_prefix):
                yield item
    elif isinstance(value, list):
        for entry in value:
            for item in walk_fields(entry, prefix + "[]"):
                yield item
    else:
        yield (prefix, value)


def get_field(event, name):
    """Read a dotted field name like 'event.module' out of an event."""
    value = event
    for key in name.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
        if value is None:
            return None
    # some auditbeat fields are lists, e.g. event.category
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return value


class Analysis:
    """Holds all the counters and knows how to write them as json."""

    def __init__(self, host, key_fields):
        self.host = host
        self.key_fields = key_fields # list of dotted field names

        self.total_events = 0   # only the events of self.host
        self.all_events = 0     # events of every host
        self.files_done = 0
        self.broken_lines = 0
        self.empty_files = 0

        self.host_counts = Counter()
        self.event_counts = Counter()  # event type key -> count

        # event type key -> Counter of field -> how often it was filled
        self.fields_per_event = {}

        self.field_totals = Counter()
        self.field_examples = {}
        self.field_events = {}

        # used to find out which fields could serve as an event type
        self.field_values = {} # field -> set of values, stops collecting at the limit

    def build_key(self, event):
        parts = []
        for name in self.key_fields:
            value = get_field(event, name)
            parts.append(str(value) if value is not None else "-")
        return ":".join(parts)

    def add_event(self, event):
        self.total_events += 1
        key = self.build_key(event)
        self.event_counts[key] += 1

        if key not in self.fields_per_event:
            self.fields_per_event[key] = Counter()

        # a field name can show up more than once in one event (lists), so every
        # name is counted only once per event
        seen_fields = set()

        for field, value in walk_fields(event):
            if field not in seen_fields:
                seen_fields.add(field)
                self.fields_per_event[key][field] += 1
                self.field_totals[field] += 1

                if field not in self.field_events:
                    self.field_events[field] = set()
                self.field_events[field].add(key)

            self.remember_example(field, value)
            self.remember_value(field, value)

    def remember_example(self, field, value):
        if field not in self.field_examples:
            self.field_examples[field] = []
        examples = self.field_examples[field]
        if len(examples) >= MAX_EXAMPLES:
            return
        if value not in examples:
            examples.append(value)

    def remember_value(self, field, value):
        """Count the different values, but stop once a field is clearly an identifier."""
        if field not in self.field_values:
            self.field_values[field] = set()
        values = self.field_values[field]
        if len(values) <= MAX_CARDINALITY_FOR_KEY:
            values.add(str(value)[:200])

    def candidate_keys(self):
        """
        Fields that could be used as an event type: few different values and
        present in nearly every event. This is how the winlogbeat equivalent of
        (channel, event_id) is found without knowing the format beforehand.
        """
        candidates = []
        for field, values in self.field_values.items():
            count = self.field_totals[field]
            if len(values) > MAX_CARDINALITY_FOR_KEY:
                continue
            if count < self.total_events * 0.5:
                continue
            if len(values) < 2:
                continue # a constant tells us nothing
            candidates.append({
                "field": field,
                "distinct_values": len(values),
                "percent_of_events": round(count / self.total_events * 100, 2),
                "values": sorted(values)[:30],
            })
        candidates.sort(key=lambda c: c["distinct_values"])
        return candidates

    def to_dict(self):
        if self.total_events == 0:
            return {
                "host": self.host,
                "files_done": self.files_done,
                "empty_files": self.empty_files,
                "total_events": 0,
                "all_events_all_hosts": self.all_events,
                "broken_lines": self.broken_lines,
                "unique_hosts": sorted(self.host_counts),
                "hosts": [],
                "key_fields": self.key_fields,
                "candidate_key_fields": [],
                "event_types": [],
                "always_present": [],
                "field_coverage": {},
                "field_to_events": {},
            }

        def percent(count):
            return round(count / self.total_events * 100, 4)

        hosts = []
        for host, count in self.host_counts.most_common():
            hosts.append({
                "host": host,
                "count": count,
                "percent": round(count / self.all_events * 100, 4),
            })

        event_types = []
        for key, count in self.event_counts.most_common():
            event_types.append({"event_type": key, "count": count, "percent": percent(count)})

        field_coverage = {}
        for key, field_counter in self.fields_per_event.items():
            events_of_this_key = self.event_counts[key]
            fields = {}
            for field, count in field_counter.most_common():
                fields[field] = round(count / events_of_this_key * 100, 2)
            field_coverage[key] = {"count": events_of_this_key, "fields": fields}

        always_present = []
        for field in self.field_totals:
            if self.field_totals[field] == self.total_events:
                always_present.append(field)
        always_present.sort()

        field_to_events = {}
        for field in sorted(self.field_totals):
            field_to_events[field] = {
                "event_types": sorted(self.field_events.get(field, [])),
                "total_count": self.field_totals[field],
                "percent_of_all_events": percent(self.field_totals[field]),
                "examples": self.field_examples.get(field, []),
            }

        return {
            "host": self.host,
            "files_done": self.files_done,
            "empty_files": self.empty_files,
            "total_events": self.total_events,
            "all_events_all_hosts": self.all_events,
            "broken_lines": self.broken_lines,
            "unique_hosts": sorted(self.host_counts),
            "hosts": hosts,
            "key_fields": self.key_fields,
            "candidate_key_fields": self.candidate_keys(),
            "event_types": event_types,
            "always_present": always_present,
            "field_coverage": field_coverage,
            "field_to_events": field_to_events,
        }

    def write_json(self, path):
        """Write the current state, the file is overwritten every time."""
        temp_path = path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        os.replace(temp_path, path)


def get_host(event):
    """auditbeat writes agent.hostname, agent.name and host.name."""
    for name in ["agent.hostname", "agent.name", "host.name"]:
        value = get_field(event, name)
        if value:
            return value
    return "unknown"


def find_key_fields(path, host):
    """
    Read the first file and check which of the candidate keys actually exist.
    This is what replaces the fixed (channel, event_id) of winlogbeat.
    """
    with bz2.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if get_host(event) != host:
                continue

            for candidate in KEY_CANDIDATES:
                fields = candidate.split(",")
                if all(get_field(event, name) is not None for name in fields):
                    return fields
            # nothing matched, fall back to the module
            return ["event.module"]
    return ["event.module"]


def read_file(path, analysis):
    """Read one .bz2 file and add everything to the analysis."""
    events_in_this_file = 0

    with bz2.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                analysis.broken_lines += 1
                continue

            analysis.all_events += 1
            events_in_this_file += 1

            # the host count is done over all hosts, everything else only for one
            host = get_host(event)
            analysis.host_counts[host] += 1
            if host != analysis.host:
                continue

            analysis.add_event(event)

    analysis.files_done += 1
    if events_in_this_file == 0:
        analysis.empty_files += 1

    return events_in_this_file


def print_summary(analysis):
    line = "=" * 70
    result = analysis.to_dict()

    print()
    print(line)
    print("SUMMARY")
    print(line)
    print("files read        :", result["files_done"])
    print("empty files       :", result["empty_files"])
    print("events all hosts  :", format(result["all_events_all_hosts"], ","))
    print("events of", result["host"], ":", format(result["total_events"], ","))
    if result["broken_lines"] > 0:
        print("broken lines      :", result["broken_lines"])

    print()
    print("HOSTS (all of them)")
    for entry in result["hosts"]:
        print("  %-28s %14s  (%6.2f %%)"
              % (entry["host"], format(entry["count"], ","), entry["percent"]))

    print()
    print("CANDIDATE KEY FIELDS")
    print("  fields with few different values, one of them is the event type")
    print("  %-38s %9s %9s" % ("field", "distinct", "coverage"))
    for entry in result["candidate_key_fields"][:20]:
        print("  %-38s %9d %8.2f %%"
              % (entry["field"], entry["distinct_values"], entry["percent_of_events"]))

    print()
    print("EVENT TYPES  (grouped by %s)" % ",".join(result["key_fields"]))
    print("  %-46s %14s %11s" % ("event type", "count", "percent"))
    for entry in result["event_types"][:40]:
        print("  %-46s %14s %9.2f %%"
              % (entry["event_type"][:46], format(entry["count"], ","), entry["percent"]))
    if len(result["event_types"]) > 40:
        print("  ... %d more" % (len(result["event_types"]) - 40))

    print()
    print("FIELDS PRESENT IN EVERY EVENT")
    for field in result["always_present"]:
        print("  " + field)

    print()
    print("different fields found:", len(result["field_to_events"]))


def main():
    parser = argparse.ArgumentParser(
        description="Analyze the DEDALE auditbeat files.")
    parser.add_argument("directory", help="folder with the .jsonl.bz2 files")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="which host to analyze (default: %s)" % DEFAULT_HOST)
    parser.add_argument("--key", default=None,
                        help="comma separated fields used as event type, "
                             "e.g. event.module,event.action. Detected automatically "
                             "if not given.")
    parser.add_argument("--json", default="dedale_auditbeat_analysis.json",
                        help="where to write the result")
    parser.add_argument("--limit", type=int,
                        help="only read the first N files (for testing)")
    args = parser.parse_args()

    files = collect_files(args.directory)
    if args.limit:
        files = files[:args.limit]

    if len(files) == 0:
        print("no matching .bz2 files found in", args.directory)
        return

    if args.key:
        key_fields = [name.strip() for name in args.key.split(",")]
    else:
        key_fields = find_key_fields(files[0], args.host)
        print("event type detected as:", ",".join(key_fields))

    print("found %d files" % len(files))
    print("host filter: %s" % args.host)
    print("writing results to %s after every file" % args.json)
    print()

    analysis = Analysis(args.host, key_fields)

    for number, path in enumerate(files, start=1):
        name = os.path.basename(path)
        events = read_file(path, analysis)

        analysis.write_json(args.json)

        print("[%d/%d] %-52s %12s events  (%s of %s)"
              % (number, len(files), name, format(events, ","),
                 args.host, format(analysis.total_events, ",")))

    print_summary(analysis)
    print()
    print("result written to", args.json)


if __name__ == "__main__":
    main()