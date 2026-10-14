# This file containes all the exact parsing logic based on the analysation of the data. You can find regarding information in the comments for each Event ID.
# Which fields are guaranteed to exit and to be able to parse.
# It can be easily extended or changed. The main.py searches over all SysmonHandlers added in the SYSMON_EID_MAP.

# The code is partilly written with the help of AI.

from enum import Enum

from utils import get, get_hash_id, generate_uuid, to_nanoseconds


class Operation(Enum):
    # Edge Types of PIDSMaker
    # only the one that have been used
    CLONE = "EVENT_CLONE" 
    CONNECT = "EVENT_CONNECT"
    EXECUTE = "EVENT_EXECUTE" 
    OPEN = "EVENT_OPEN"
    READ = "EVENT_READ"
    SENDMSG = "EVENT_SENDMSG"
    WRITE = "EVENT_WRITE"


# Information flows from the object into the subject, so these edges are stored
# the other way around. Same list as edge_reversed in pidsmaker/utils/dataset_utils.py.
REVERSED = [Operation.EXECUTE, Operation.OPEN, Operation.READ]


class SysmonHandlers:
    # all handlings of sysmon events, i. e. which fields should be read and processed
    # event is json.loads(json_line)
    

    @staticmethod
    def add_subject(parser, uuid, path=None, cmd=None):
        if uuid is None:
            return None
        parser.create_subject_node(uuid, get_hash_id(uuid), path, cmd)
        return uuid

    @staticmethod
    def add_file(parser, path):
        if not path:
            return None
        uuid = generate_uuid(parser.host, "file", path)
        parser.create_file_node(uuid, get_hash_id(uuid), path)
        return uuid

    @staticmethod
    def add_netflow(parser, src_adr, src_port, dst_adr, dst_port):
        if not dst_adr:
            return None
        # windows choices the source port randomly (range 49152-65535)
        uuid = generate_uuid(parser.host, "netflow", str(dst_adr) + ":" + str(dst_port))
        parser.create_netflow_node(uuid, get_hash_id(uuid), src_adr, src_port, dst_adr, dst_port)
        return uuid

    @staticmethod
    def add_edge(parser, event, src, dst, operation):
        if src is None or dst is None:
            return
        if operation in REVERSED:
            src, dst = dst, src

        # record_id is a unique sysmon intern Event-ID, that references individual events
        record_id = get(event, "winlog", "record_id")
        event_uuid = get_hash_id(parser.host + "|" + str(record_id) + "|" + str(parser.num_events()))

        parser.create_event_edge(src, operation.value, dst, event_uuid,to_nanoseconds(event["@timestamp"]))

    # -- one method per event id ------------------------------------------------

    @staticmethod
    def eid_1(parser, event):
        # EID 1 - Process_creation
        # -- Nodes --
        # Contains Fields like: 
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe"), process.command_line (e.g "\\??\\C:\\Windows\\system32\\autochk.exe *")
        #   > CHILD subject node: uuid, path, cmd
        #   - process.parent.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.parent.executable (e.g. "C:\\Windows\\System32\\wininit.exe"), process.parent.command_line (e.g. "\\SystemRoot\\System32\\smss.exe 00000080 00000084 ")
        #   > PARENT subject node: uuid, path, cmd
        #   - process.executable (e.g."C:\\Windows\\System32\\smss.exe") [why not "winlog.event_data.OriginalFileName"]
        #   > FILE node: uuid needs to be generated, path is provided process.executable
        # -- Edges --
        #   - PARENT -> CHILD --> EVENT_CLONE Edge Type; Parent process start child process
        #   - FILE -> CHILD --> EVENT_EXECUTE Edge Type; The executable is executed and produces CHILD process
        child = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"),get(event, "process", "command_line"))
        parent = SysmonHandlers.add_subject(parser,get(event, "process", "parent", "entity_id"),get(event, "process", "parent", "executable"),get(event, "process", "parent", "command_line"))
        image = SysmonHandlers.add_file(parser, get(event, "process", "executable"))

        SysmonHandlers.add_edge(parser, event, parent, child, Operation.CLONE)
        SysmonHandlers.add_edge(parser, event, child, image, Operation.EXECUTE)

    @staticmethod
    def eid_2(parser, event):
        # EID 2 - A process changed a file creation time
        #       > a process created a file or changed its creation time (file-write-event)
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set
        #   - file.path (e.g. "C:\\Windows\\System32\\drivers\\crashdmp.sys")
        #   > FILE node: uuid needs to be generated (depending on path), path
        # -- Edges --
        #  - SUBJECT -> FILE --> EVENT_WRITE Edge Type
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        target = SysmonHandlers.add_file(parser, get(event, "file", "path"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.WRITE)

    @staticmethod
    def eid_3(parser, event):
        # EID 3 - Network connection (only 28 cases)
        #       > TCP/UDP connections.
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - source.ip (e.g "172.16.1.30"), source.port (e.g. 65028), destination.ip (e.g. "172.16.1.255"), destination.port (e.g. 389)
        #   > NETFLOW node: uuid generated with Host & Destination adr and port, src_adr, src_port, dst_adr, dst_port
        # -- Edges --
        #   - SUBJECT -> NETFLOW --> EVENT_CONNECT Edge type
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        target = SysmonHandlers.add_netflow(parser,get(event, "source", "ip"),get(event, "source", "port"),get(event, "destination", "ip"),get(event, "destination", "port"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.CONNECT)

    @staticmethod
    def eid_7(parser, event):
        # EID 7 - Image loaded
        #       > a process loaded a DLL or an executable into its memory (file-read-event)
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - file.path (e.g. "C:\\Windows\\System32\\drivers\\crashdmp.sys") 
        #   > FILE node: uuid needs to be generated (depending on path), path
        # -- Edges --
        #   - FILE -> SUBJECT --> EVENT_READ Edge Type; reversed, the information flows from the image into the process         
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        target = SysmonHandlers.add_file(parser, get(event, "file", "path"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.READ)

    @staticmethod
    def eid_8(parser, event):
        # EID 8 - CreateRemoteThread
        #       > a process started a thread inside another process (classic code injection)
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SOURCE subject node: uuid, path, cmd is not set (not provided)
        #   - winlog.event_data.TargetProcessGuid (e.g. "{416dd0c5-3436-6769-3002-000000000700}"), winlog.event_data.TargetImage (e.g. "C:\\Windows\\system32\\csrss.exe")
        #   > TARGET subject node: uuid, path, cmd is not set
        # -- Edges --
        #   - SOURCE -> TARGET --> EVENT_CLONE Edge Type; a new thread is created in the target
        source = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        # here it is Guid, while for eid 10 it is GUID
        target = SysmonHandlers.add_subject(parser,get(event, "winlog", "event_data", "TargetProcessGuid"),get(event, "winlog", "event_data", "TargetImage"))
        SysmonHandlers.add_edge(parser, event, source, target, Operation.CLONE)

    @staticmethod
    def eid_9(parser, event):
        # EID 9 - RawAccessRead
        #       > a process read a drive directly, bypassing the file system (used to copy locked files)
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - file.path (e.g. "C:\\DumpStack.log.tmp") 
        #   > FILE node: uuid needs to be generated (depending on path), path
        # -- Edges --
        #   - FILE -> SUBJECT --> EVENT_READ Edge Type; reversed
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        target = SysmonHandlers.add_file(parser, get(event, "file", "path"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.READ)

    @staticmethod
    def eid_10(parser, event):
        # EID 10 - Process accessed
        #       > a process opened a handle on another process. Very noisy (17 percent of all events),
        #         most of it comes from antivirus software scanning every running process
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SOURCE subject node: uuid, path, cmd is not set (not provided)
        #   - winlog.event_data.TargetProcessGUID (e.g. "{416dd0c5-1898-6769-0400-000000000700}"), winlog.event_data.TargetImage (e.g. "C:\\Windows\\system32\\csrss.exe")
        #     [upper case "GUID", EID 8 writes "Guid"]
        #   > TARGET subject node: uuid, path, cmd is not set
        # -- Edges --
        #   - TARGET -> SOURCE --> EVENT_OPEN Edge Type; reversed, the information flows out of the opened process
        source = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        # here it is GUID (different to eid 8)
        target = SysmonHandlers.add_subject(parser,get(event, "winlog", "event_data", "TargetProcessGUID"),get(event, "winlog", "event_data", "TargetImage"))
        SysmonHandlers.add_edge(parser, event, source, target, Operation.OPEN)

    @staticmethod
    def eid_11(parser, event):
        # EID 11 - File created
        #       > a process created or overwrote a file (file-write-event)
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - file.path (e.g. "C:\\DumpStack.log.tmp")
        #   > FILE node: uuid needs to be generated (depending on path), path
        # -- Edges --
        #   - SUBJECT -> FILE --> EVENT_WRITE Edge Type
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        target = SysmonHandlers.add_file(parser, get(event, "file", "path"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.WRITE)

    @staticmethod
    def eid_15(parser, event):
        # EID 15 - File stream created
        #       > a process wrote an alternate data stream, e.g. the mark-of-the-web that a browser
        #         attaches to a downloaded file. Only 2142 events in the whole dataset
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - file.path (e.g. "C:\\DumpStack.log.tmp") 
        #   > FILE node: uuid needs to be generated (depending on path), path
        # -- Edges --
        #   - SUBJECT -> FILE --> EVENT_WRITE Edge Type
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        target = SysmonHandlers.add_file(parser, get(event, "file", "path"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.WRITE)

    @staticmethod
    def eid_17(parser, event):
        # EID 17 - Pipe created
        #       > a process created a named pipe. Pipes are the usual transport for post exploitation
        #         frameworks, so they are worth keeping even though they are not real files
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - file.name
        #   > FILE node: uuid needs to be generated (depending on the built path), path
        # -- Edges --
        #   - SUBJECT -> FILE --> EVENT_WRITE Edge Type; creating a pipe is treated like creating a file
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        # Winlogbeat maps PipeName to file.name and not to file.path --> build
        name = get(event, "file", "name")
        target = SysmonHandlers.add_file(parser, "\\\\.\\pipe" + name) if name else None
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.WRITE)

    @staticmethod
    def eid_18(parser, event):
        # EID 18 - Pipe connected
        #       > a process connected to an existing named pipe (the other end of EID 17)
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - file.name [only the pipe name, see EID 17]
        #   > FILE node: uuid needs to be generated (depending on the built path), path
        # -- Edges --
        #   - FILE -> SUBJECT --> EVENT_OPEN Edge Type; reversed
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        name = get(event, "file", "name")
        target = SysmonHandlers.add_file(parser, "\\\\.\\pipe" + name) if name else None
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.OPEN)

    @staticmethod
    def eid_22(parser, event):
        # EID 22 - Dns query
        #       > a process resolved a host name. Since EID 3 is nearly absent, this is the only
        #         event that connects a process to something on the network
        # -- Nodes --
        # Contains Fields like:
        #   - process.entity_id (e.g. "{416dd0c5-1896-6769-eb03-000000000000}"), process.executable (e.g."C:\\Windows\\System32\\smss.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - dns.resolved_ip (e.g. "131.107.255.255")
        #     [dns.resolved_ip is only set in 87 percent of the events, the rest are failed lookups]
        #   > NETFLOW node: uuid generated with Host & Destination adr, dst_adr, the ports stay empty
        # -- Edges --
        #   - SUBJECT -> NETFLOW --> EVENT_SENDMSG Edge Type
        subject = SysmonHandlers.add_subject(parser,get(event, "process", "entity_id"),get(event, "process", "executable"))
        # only the first resolved ip is used, a CDN answer can contain eight of them
        ips = get(event, "dns", "resolved_ip")
        target = SysmonHandlers.add_netflow(parser, None, None, ips[0], None) if ips else None
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.SENDMSG)

    @staticmethod
    def eid_26(parser, event):
        # EID 26 - File delete detected
        #       > a process deleted a file.
        #  
        # -- Nodes --
        # Contains Fields like:
        #   - winlog.event_data.ProcessGuid (e.g. "{416dd0c5-189d-6769-3f00-000000000700}"), winlog.event_data.Image (e.g. "C:\\Windows\\System32\\svchost.exe")
        #   > SUBJECT node: uuid, path, cmd is not set (not provided)
        #   - winlog.event_data.TargetFilename (e.g. "C:\\ProgramData\\Microsoft\\Diagnosis\\parse.dat")
        #   > FILE node: uuid needs to be generated (depending on path), path
        # -- Edges --
        #   - SUBJECT -> FILE --> EVENT_WRITE Edge Type;
        # not normalized (winlog.event_data)
        subject = SysmonHandlers.add_subject(parser,get(event, "winlog", "event_data", "ProcessGuid"),  get(event, "winlog", "event_data", "Image"))
        target = SysmonHandlers.add_file(parser, get(event, "winlog", "event_data", "TargetFilename"))
        SysmonHandlers.add_edge(parser, event, subject, target, Operation.WRITE)

    ## Possiblity to extend with more event handling





# all sysmon eid events reference
# can be easily extended
SYSMON_EID_MAP = {
    1: SysmonHandlers.eid_1,
    2: SysmonHandlers.eid_2,
    3: SysmonHandlers.eid_3,
    7: SysmonHandlers.eid_7,
    8: SysmonHandlers.eid_8,
    9: SysmonHandlers.eid_9,
    10: SysmonHandlers.eid_10,
    11: SysmonHandlers.eid_11,
    15: SysmonHandlers.eid_15,
    17: SysmonHandlers.eid_17,
    18: SysmonHandlers.eid_18,
    22: SysmonHandlers.eid_22,
    26: SysmonHandlers.eid_26,
}