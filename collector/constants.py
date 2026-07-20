"""Constants for the ShadowSensor event collector."""

from pathlib import Path

# Sysmon event log channel name
SYSMON_CHANNEL: str = "Microsoft-Windows-Sysmon/Operational"

# The six behavioral telemetry event IDs ShadowSensor monitors
TARGET_EVENT_IDS: frozenset[int] = frozenset({1, 3, 7, 8, 10, 22})

# Seconds between poll cycles
POLL_INTERVAL_SECONDS: float = 2.0

# Bookmark file persists log position across collector restarts
BOOKMARK_FILE: Path = Path(".shadowsensor_bookmark.xml")

# Events to request per EvtNext call
BATCH_SIZE: int = 100

# XPath filter passed to EvtQuery — selects only the 6 target event IDs
EVT_XPATH_FILTER: str = (
    "*[System[EventID=1 or EventID=3 or EventID=7 or EventID=8 or EventID=10 or EventID=22]]"
)
