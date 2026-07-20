"""
ShadowSensor Phase 5 — Feature Specification

Defines the authoritative 30-feature registry and constant sets used across
the feature extraction pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FeatureDef:
    name: str           # Exact CSV column header
    dtype: type         # Python type: int or float
    default: Any        # Value when feature cannot be computed
    source_eids: tuple  # Which Sysmon EIDs contribute to this feature
    description: str    # One-line human-readable description


FEATURE_REGISTRY: list[FeatureDef] = [
    # --- Category A: Process ---
    FeatureDef("cmd_length",            int,   0,    (1,),       "Length of CommandLine string"),
    FeatureDef("cmd_entropy",           float, 0.0,  (1,),       "Shannon entropy of CommandLine"),
    FeatureDef("has_encoded_command",   int,   0,    (1,),       "EncodedCommand flag present in CommandLine"),
    FeatureDef("has_download_keyword",  int,   0,    (1,),       "Download-related keyword in CommandLine"),
    FeatureDef("is_signed",             int,   0,    (1,),       "Process binary is signed"),
    FeatureDef("hour_of_day",           int,   -1,   (1,),       "Hour of event timestamp (0-23)"),
    FeatureDef("is_off_hours",          int,   0,    (1,),       "Event occurred outside 08:00-18:00"),
    FeatureDef("is_lolbin",             int,   0,    (1,),       "Image filename is a known LOLBin"),
    FeatureDef("is_suspicious_parent",  int,   0,    (1,),       "Parent image is a known suspicious launcher"),
    FeatureDef("parent_cmd_length",     int,   0,    (1,),       "Length of parent CommandLine string"),
    # --- Category B: Process-Relationship ---
    FeatureDef("is_known_suspicious_chain", int, 0,  (1,),       "Parent-child pair is in SUSPICIOUS_CHAINS"),
    FeatureDef("parent_is_same_image",      int, 0,  (1,),       "Parent image filename == child image filename"),
    # --- Category C: Network ---
    FeatureDef("dns_query_length",      int,   0,    (22,),      "Length of DNS query hostname (EID 22)"),
    FeatureDef("dest_port",             int,   0,    (3,),       "Destination port (EID 3)"),
    FeatureDef("is_suspicious_port",    int,   0,    (3,),       "Destination port is in SUSPICIOUS_PORTS"),
    FeatureDef("is_external_ip",        int,   0,    (3,),       "Destination IP is non-RFC1918, non-loopback"),
    FeatureDef("network_event_count",   int,   0,    (3, 22),    "Total EID 3 + EID 22 events for this process"),
    # --- Category D: API / Memory ---
    FeatureDef("image_load_count",              int, 0, (7,),    "Number of DLLs loaded by this process"),
    FeatureDef("unsigned_image_loaded",         int, 0, (7,),    "Any unsigned image loaded by this process"),
    FeatureDef("create_remote_thread_count",    int, 0, (8,),    "Number of CreateRemoteThread events from this process"),
    FeatureDef("open_process_count",            int, 0, (10,),   "Number of OpenProcess events from this process"),
    FeatureDef("open_process_lsass_target",     int, 0, (10,),   "Any OpenProcess targeting lsass.exe"),
    FeatureDef("open_process_suspicious_access",int, 0, (10,),   "Any OpenProcess with VM_READ/VM_WRITE/ALL_ACCESS mask"),
    # --- Category E: Behavioral / Rule-Hit ---
    FeatureDef("rule_hit_count",         int,  0,    (),         "Total rule hits for this process window"),
    FeatureDef("unique_rules_fired",     int,  0,    (),         "Distinct rule_id values fired for this process window"),
    FeatureDef("has_powershell_rule_hit",int,  0,    (),         "Any PS_ rule fired for this process"),
    FeatureDef("has_lolbin_rule_hit",    int,  0,    (),         "Any LOLBIN_ rule fired for this process"),
    FeatureDef("has_network_rule_hit",   int,  0,    (),         "Any NET_ rule fired for this process"),
    FeatureDef("has_api_rule_hit",       int,  0,    (),         "Any API_ rule fired for this process"),
    FeatureDef("has_chain_rule_hit",     int,  0,    (),         "Any CHAIN_ rule fired for this process"),
]

FEATURE_NAMES: list[str] = [f.name for f in FEATURE_REGISTRY]


def default_feature_vector() -> dict:
    """Return a dict of all features set to their default values."""
    return {f.name: f.default for f in FEATURE_REGISTRY}


# --- Constant sets ---

LOLBIN_NAMES: set[str] = {
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "wscript.exe", "cscript.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "odbcconf.exe", "ieexec.exe",
    "msconfig.exe", "schtasks.exe", "at.exe", "bitsadmin.exe",
    "forfiles.exe", "pcalua.exe", "syncappvpublishingserver.exe",
    "appsyncpublishingserver.exe", "expand.exe", "extrac32.exe",
    "findstr.exe", "hh.exe", "makecab.exe", "msdeploy.exe",
    "msdt.exe", "mspub.exe", "wmic.exe", "xwizard.exe",
}

SUSPICIOUS_PARENT_IMAGES: set[str] = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "mspub.exe", "visio.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "explorer.exe",
}

SUSPICIOUS_CHAINS: set[tuple[str, str]] = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "wscript.exe"),
    ("excel.exe", "cscript.exe"),
    ("powerpnt.exe", "powershell.exe"),
    ("powerpnt.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("wscript.exe", "powershell.exe"),
    ("wscript.exe", "cmd.exe"),
    ("cscript.exe", "powershell.exe"),
    ("cscript.exe", "cmd.exe"),
    ("mshta.exe", "powershell.exe"),
    ("mshta.exe", "cmd.exe"),
}

SUSPICIOUS_PORTS: set[int] = {
    4444, 1234, 8443, 8888, 9001, 9002, 31337, 1337, 6666, 6667,
    4445, 5555, 2222, 3333, 7777, 9999, 12345, 54321, 65535,
}
