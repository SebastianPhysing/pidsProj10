# This file analyses the daily_winlogbeat .jsonl.bz2 files of the DEDALE dataset. It was used to find out which events
# and fields are in the data, before the parser (main.py) was written.
# It reads all files one after the other and counts:
#   - how many events there are
#   - which event ids exist and how often (per channel, like sysmon, powershell, security, ...)
#   - which hosts are in the data
#   - which fields are used by which event id and how often they are filled
#   - up to 5 different example values for every field
# The result is written to a json file. The json is written again after every file, so you can already look at it
# while it is still running and nothing is lost if it stops before the end.
#

#
# This file is structured in the following way:
#   - constants
#   - helper functions
#   - processing of folder with list of files
#   - analysis class
#   - main function

# The code is partilly written with the help of AI.

import argparse
import bz2
import json
import os

# The channel names are very long, so they get shortend for the output
SHORT_CHANNEL_NAMES = {
    "Microsoft-Windows-Sysmon/Operational": "sysmon",
    "Microsoft-Windows-PowerShell/Operational": "powershell-op",
    "Windows PowerShell": "powershell",
    "Security": "security",
    "System": "system",
    "Application": "application",
}

# how many different example values are kept per field
MAX_EXAMPLES = 5


def count_up(dictionary, key):
    # adds one to the counter of key, starts with 0 if key is not there yet
    dictionary[key] = dictionary.get(key, 0) + 1


def sort_by_count(dictionary):
    # returns the keys, the one with the highest count first
    return sorted(dictionary, key=lambda key: dictionary[key], reverse=True)


def get_all_fields(value, prefix, result):
    # Goes through the json object recursive and adds (field name, value) to result for every value that is no dict or list.
    # The index of lists is left out, so process.args.0 and process.args.1 are both process.args[].
    # Otherwise we would get hundreds of field names that are actually the same field.
    if isinstance(value, dict):
        for key in value:
            if prefix == "":
                get_all_fields(value[key], key, result)
            else:
                get_all_fields(value[key], prefix + "." + key, result)
    elif isinstance(value, list):
        for entry in value:
            get_all_fields(entry, prefix + "[]", result)
    else:
        result.append((prefix, value))
    return result


def get_file_paths(folder_path):
    # All .bz2 files in folder_path that contain F[Number] ), sorted by the F number
    file_dict = {}
    for file_name in os.listdir(folder_path):
        if "_F" not in file_name or not file_name.endswith(".bz2"):
            continue
        file_name_ending = file_name.split("_F")[1]
        file_num = int(file_name_ending.split(".")[0])
        file_dict[file_num] = os.path.join(folder_path, file_name)

    file_paths = []
    for file_num in sorted(file_dict):
        file_paths.append(file_dict[file_num])
    return file_paths


def read_file(path, analysis):
    # Reads one .bz2 file and gives every event to the analysis. Returns the number of events in this file
    events_in_file = 0

    # rt: read text instead of binaries, replace invalid chars (of UTF-8 encoding)
    with bz2.open(path, "rt", encoding="utf-8", errors="replace") as file:
        for line in file:
            line = line.strip()
            if line == "":
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                analysis.broken_lines += 1
                continue

            analysis.add_event(event)
            events_in_file += 1

    analysis.files_done += 1
    if events_in_file == 0:
        analysis.empty_files += 1

    return events_in_file


class Analysis:
    # Holds all counters. add_event() counts one event, to_dict() builds the result for the json file.

    def __init__(self):
        self.total_events = 0
        self.files_done = 0
        self.broken_lines = 0
        self.empty_files = 0

        self.host_counts = {}       
        self.channel_counts = {}    
        self.event_counts = {}      

        
        self.fields_per_event = {}

        self.field_totals = {}      # field -> count over all events
        self.field_examples = {}    # field -> list of different values
        self.field_events = {}      # field -> set of "channel:event_id"

    def add_event(self, event):
        self.total_events += 1

        # if key winlog does not exist, return empty dict
        channel = event.get("winlog", {}).get("channel", "unknown")
        channel = SHORT_CHANNEL_NAMES.get(channel, channel)
        event_id = event.get("winlog", {}).get("event_id", "unknown")
        host = event.get("agent", {}).get("name", "unknown")

        key = (channel, event_id)
        key_as_text = channel + ":" + str(event_id)

        count_up(self.event_counts, key)
        count_up(self.channel_counts, channel)
        count_up(self.host_counts, host)

        if key not in self.fields_per_event:
            self.fields_per_event[key] = {}

        # a field name can be more than once in one event (because of lists),
        # so every name is only counted once per event
        seen_fields = set()

        for field, value in get_all_fields(event, "", []):
            if field not in seen_fields:
                seen_fields.add(field)
                count_up(self.fields_per_event[key], field)
                count_up(self.field_totals, field)

                if field not in self.field_events:
                    self.field_events[field] = set()
                self.field_events[field].add(key_as_text)

            self.add_example(field, value)

    def add_example(self, field, value):
        # keeps up to MAX_EXAMPLES different values per field
        if field not in self.field_examples:
            self.field_examples[field] = []

        examples = self.field_examples[field]
        if len(examples) < MAX_EXAMPLES and value not in examples:
            examples.append(value)

    def percent(self, count):
        # no events read yet, so we would divide by zero
        if self.total_events == 0:
            return 0
        return round(count / self.total_events * 100, 4)

    def to_dict(self):
        # one entry per (channel, event id)
        events = []
        for key in sort_by_count(self.event_counts):
            count = self.event_counts[key]
            events.append({"channel": key[0], "event_id": key[1], "count": count, "percent": self.percent(count)})

        hosts = []
        for host in sort_by_count(self.host_counts):
            count = self.host_counts[host]
            hosts.append({"host": host, "count": count, "percent": self.percent(count)})

        channels = []
        for channel in sort_by_count(self.channel_counts):
            count = self.channel_counts[channel]
            channels.append({"channel": channel, "count": count, "percent": self.percent(count)})

        # for every event id: how often each field is filled (in percent of the events with this id)
        field_coverage = {}
        for key in self.fields_per_event:
            field_counts = self.fields_per_event[key]
            events_of_this_id = self.event_counts[key]

            fields = {}
            for field in sort_by_count(field_counts):
                fields[field] = round(field_counts[field] / events_of_this_id * 100, 2)

            field_coverage[key[0] + ":" + str(key[1])] = {"count": events_of_this_id, "fields": fields}

        # fields that are in every single event
        always_present = []
        for field in sorted(self.field_totals):
            if self.field_totals[field] == self.total_events:
                always_present.append(field)

        # field -> which event ids use it, and some example values
        field_to_events = {}
        for field in sorted(self.field_totals):
            field_to_events[field] = {
                "event_ids": sorted(self.field_events.get(field, [])),
                "total_count": self.field_totals[field],
                "percent_of_all_events": self.percent(self.field_totals[field]),
                "examples": self.field_examples.get(field, []),
            }

        return {
            "files_done": self.files_done,
            "empty_files": self.empty_files,
            "total_events": self.total_events,
            "broken_lines": self.broken_lines,
            "unique_hosts": sorted(self.host_counts),
            "hosts": hosts,
            "channels": channels,
            "events": events,
            "always_present": always_present,
            "field_coverage": field_coverage,
            "field_to_events": field_to_events,
        }

    def write_json(self, path):
        # The file is overwritten every time. It is first written to a temp file and then renamed,
        # so the json on disk is never half finished when you look at it.
        # default=str: values json does not know are written as text
        temp_path = path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(self.to_dict(), file, indent=2, ensure_ascii=False, default=str)
        os.replace(temp_path, path)


def main():
    # argparser
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=".", help="Path to daily_winlogbeat folder, containing all the .jsonl.bz2 files")
    

    args = parser.parse_args()

    file_paths = get_file_paths(args.path)
    

    if len(file_paths) == 0:
        print("no .bz2 files found in", args.path)
        return

    print("found", len(file_paths), "files")
    print("result is written to", args.json, "after every file")
    print()

    analysis = Analysis()

    for number, path in enumerate(file_paths, start=1):
        events_in_file = read_file(path, analysis)

        # save the current state, so nothing is lost if it stops here
        analysis.write_json("dedale_analysis.json")

        print("[" + str(number) + "/" + str(len(file_paths)) + "]", os.path.basename(path), ":",
              events_in_file, "events (total:", analysis.total_events, ")")

    print()
    print("Finished.")


if __name__ == "__main__":
    main()