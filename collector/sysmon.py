"""Sysmon event collector for Phase 1.

Provides SysmonCollector which can operate in two modes:
- directory: scan a directory of Sysmon XML files (good for offline testing)
- wevtutil: invoke Windows wevtutil to export recent Sysmon events (requires
  Windows and wevtutil available)

The collector returns parsed event dictionaries with keys like:
  event_id, time_created, provider, computer, event_data (dict)

Note: Live Windows validation is pending; this implementation is per spec and
must be validated in the lab VM before being marked operational.
"""

from __future__ import annotations

import os
import subprocess
import sys

from lxml import etree


def _parse_sysmon_event(xml_text: str) -> dict:
    """Parse a single Sysmon Event XML string into a dict."""
    try:
        root = etree.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return {"raw": xml_text}

    event = {}
    system = root.find("System")
    if system is not None:
        eventid = system.find("EventID")
        provider = system.find("Provider")
        timecreated = system.find("TimeCreated")
        computer = system.find("Computer")
        event["event_id"] = (
            int(eventid.text)
            if eventid is not None and eventid.text and eventid.text.isdigit()
            else None
        )
        event["provider"] = provider.get("Name") if provider is not None else None
        event["time_created"] = timecreated.get("SystemTime") if timecreated is not None else None
        event["computer"] = computer.text if computer is not None else None

    eventdata = {}
    ed = root.find("EventData")
    if ed is not None:
        for data in ed.findall("Data"):
            name = data.get("Name")
            text = data.text
            if name:
                eventdata[name] = text
    event["event_data"] = eventdata

    return event


class SysmonCollector:
    """Collect Sysmon events from either a directory of XML files or wevtutil.

    Typical usage:
        c = SysmonCollector(mode="directory", path="/path/to/xmls")
        events = c.collect_once()
    """

    def __init__(self, mode: str = "auto", path: str | None = None, poll_interval: float = 1.0):
        # mode: 'auto'|'directory'|'wevtutil'
        self.mode = mode
        self.path = path
        self.poll_interval = poll_interval
        self._seen_files: set[str] = set()

        if self.mode == "auto":
            if sys.platform == "win32":
                self.mode = "wevtutil"
            else:
                self.mode = "directory"

    def collect_once(self, max_events: int = 100) -> list[dict]:
        """Collect up to max_events events and return a list of parsed dicts."""
        if self.mode == "directory":
            return self._collect_from_directory(max_events)
        elif self.mode == "wevtutil":
            return self._collect_from_wevtutil(max_events)
        else:
            raise ValueError(f"unknown mode: {self.mode}")

    def _collect_from_directory(self, max_events: int) -> list[dict]:
        if not self.path:
            raise ValueError("path must be provided for directory mode")
        if not os.path.isdir(self.path):
            raise FileNotFoundError(f"directory not found: {self.path}")

        candidates = [
            os.path.join(self.path, fn)
            for fn in os.listdir(self.path)
            if fn.lower().endswith(".xml")
        ]
        candidates.sort(key=lambda p: os.path.getmtime(p))

        events: list[dict] = []
        for p in candidates:
            if p in self._seen_files:
                continue
            try:
                with open(p, encoding="utf-8") as fh:
                    xml = fh.read()
            except Exception:
                continue
            parsed = _parse_sysmon_event(xml)
            events.append(parsed)
            self._seen_files.add(p)
            if len(events) >= max_events:
                break

        return events

    def _collect_from_wevtutil(self, max_events: int) -> list[dict]:
        channel = "Microsoft-Windows-Sysmon/Operational"
        cmd = ["wevtutil", "qe", channel, "/f:xml", f"/c:{max_events}"]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError as err:
            raise OSError(
                "wevtutil not found on PATH; cannot collect from Windows event log"
            ) from err
        except subprocess.CalledProcessError:
            return []

        wrapped = f"<Events>{out}</Events>"
        try:
            root = etree.fromstring(wrapped.encode("utf-8"))
        except Exception:
            return [{"raw_wevtutil": out}]

        events: list[dict] = []
        for ev in root.findall("Event"):
            xml_str = etree.tostring(ev, encoding="utf-8").decode("utf-8")
            parsed = _parse_sysmon_event(xml_str)
            events.append(parsed)

        return events


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Sysmon Collector manual test")
    ap.add_argument("--mode", choices=["directory", "wevtutil", "auto"], default="auto")
    ap.add_argument("--path", help="Directory path for directory mode")
    ap.add_argument("--max", type=int, default=20)
    args = ap.parse_args()

    c = SysmonCollector(mode=args.mode, path=args.path)
    evs = c.collect_once(max_events=args.max)
    for e in evs:
        print(e)
