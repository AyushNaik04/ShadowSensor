"""Field name mappings from dataclass attributes to Sysmon XML Data Name values."""

PROCESS_CREATE_FIELDS: dict[str, str] = {
    "process_guid": "ProcessGuid",
    "process_id": "ProcessId",
    "image": "Image",
    "command_line": "CommandLine",
    "current_directory": "CurrentDirectory",
    "user": "User",
    "parent_process_id": "ParentProcessId",
    "parent_image": "ParentImage",
    "parent_command_line": "ParentCommandLine",
    "integrity_level": "IntegrityLevel",
    "hashes": "Hashes",
}

NETWORK_CONNECT_FIELDS: dict[str, str] = {
    "process_guid": "ProcessGuid",
    "process_id": "ProcessId",
    "image": "Image",
    "user": "User",
    "protocol": "Protocol",
    "initiated": "Initiated",
    "source_ip": "SourceIp",
    "source_port": "SourcePort",
    "destination_ip": "DestinationIp",
    "destination_hostname": "DestinationHostname",
    "destination_port": "DestinationPort",
}

IMAGE_LOAD_FIELDS: dict[str, str] = {
    "process_guid": "ProcessGuid",
    "process_id": "ProcessId",
    "image": "Image",
    "image_loaded": "ImageLoaded",
    "signed": "Signed",
    "signature": "Signature",
    "signature_status": "SignatureStatus",
    "hashes": "Hashes",
}

CREATE_REMOTE_THREAD_FIELDS: dict[str, str] = {
    "source_process_id": "SourceProcessId",
    "source_image": "SourceImage",
    "target_process_id": "TargetProcessId",
    "target_image": "TargetImage",
    "new_thread_id": "NewThreadId",
    "start_address": "StartAddress",
    "start_module": "StartModule",
    "start_function": "StartFunction",
}

OPEN_PROCESS_FIELDS: dict[str, str] = {
    "source_process_id": "SourceProcessId",
    "source_image": "SourceImage",
    "target_process_id": "TargetProcessId",
    "target_image": "TargetImage",
    "granted_access": "GrantedAccess",
    "call_trace": "CallTrace",
}

DNS_QUERY_FIELDS: dict[str, str] = {
    "process_id": "ProcessId",
    "image": "Image",
    "query_name": "QueryName",
    "query_status": "QueryStatus",
    "query_results": "QueryResults",
}

FIELD_MAPS: dict[int, dict[str, str]] = {
    1: PROCESS_CREATE_FIELDS,
    3: NETWORK_CONNECT_FIELDS,
    7: IMAGE_LOAD_FIELDS,
    8: CREATE_REMOTE_THREAD_FIELDS,
    10: OPEN_PROCESS_FIELDS,
    22: DNS_QUERY_FIELDS,
}
