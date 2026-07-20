#!/usr/bin/env python3
"""Live ShadowSensor pipeline: Sysmon collector -> normalizer -> rule engine."""

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collector.runner import run_collector
from rules.corroboration import CorroborationResult, corroborate_event, log_corroboration
from rules.engine import RuleEngine
from rules.schema import RuleHit
from storage.database import init_db
from storage.storage_writer import StorageWriter
from alerting.alert_manager import AlertManager

import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
_corr_logger = logging.getLogger("shadowsensor.corroboration")


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _format_hit(hit: RuleHit, event: Any) -> str:
    """Build a rich, self-contained log line for a single rule hit.

    Includes: timestamp, rule_name, rule_id, ATT&CK technique+tactic, severity,
    process image, full image path, command line, parent process, and where
    applicable: access mask (OpenProcess) or destination info (network).
    Every field is present so a reader never needs to cross-reference the event.
    """
    ts = _timestamp()

    # Process identity
    image      = getattr(event, "image", None) or getattr(event, "source_image", None) or "N/A"
    image_path = image  # image is always the full path from Sysmon

    # Command line (ProcessCreate events)
    cmd_line   = getattr(event, "command_line", None)

    # Parent (ProcessCreate events)
    parent     = getattr(event, "parent_image", None)

    # OpenProcess fields
    source_img = getattr(event, "source_image", None)
    target_img = getattr(event, "target_image", None)
    access     = getattr(event, "granted_access", None)

    # Network fields
    dest_host  = getattr(event, "destination_hostname", None)
    dest_ip    = getattr(event, "destination_ip", None)
    dest_port  = getattr(event, "destination_port", None)

    parts = [
        f"[{ts}] RULE_HIT",
        f"rule={hit.rule_name!r}",
        f"id={hit.rule_id}",
        f"technique={hit.mitre_technique}",
        f"tactic={hit.mitre_tactic}",
        f"severity={hit.severity}",
        f"image={image_path!r}",
    ]

    if cmd_line is not None:
        parts.append(f"cmdline={cmd_line!r}")
    if parent is not None:
        parts.append(f"parent={parent!r}")
    if source_img is not None and source_img != image:
        parts.append(f"source={source_img!r}")
    if target_img is not None:
        parts.append(f"target={target_img!r}")
    if access is not None:
        parts.append(f"access={access}")
    if dest_host is not None or dest_ip is not None:
        dest = dest_host or dest_ip or "?"
        if dest_port is not None:
            dest = f"{dest}:{dest_port}"
        parts.append(f"dest={dest!r}")

    return " | ".join(parts)


def main() -> int:
    print("=" * 60)
    print("ShadowSensor Pipeline — Live Mode")
    print("Polling Microsoft-Windows-Sysmon/Operational every 2s")
    print("Rule hits -> stdout + logs/rule_hits.log")
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    Path("logs").mkdir(parents=True, exist_ok=True)
    log_file = open("logs/rule_hits.log", "a", encoding="utf-8")
    log_file.write(f"[{_timestamp()}] === SESSION START ===\n")
    log_file.flush()

    try:
        engine = RuleEngine(rules_dir=Path("rules"))
        engine.load()
    except Exception as exc:
        print(f"[ERROR] Failed to load rules: {exc}")
        log_file.close()
        return 1

    rule_count = engine.rule_count
    if rule_count == 0:
        print("[ERROR] No rules loaded from rules/definitions/")
        log_file.close()
        return 1

    print(f"[INFO] Loaded {rule_count} rules from rules/definitions/")

    init_db()
    _storage_writer = StorageWriter()
    _alert_manager = AlertManager(_storage_writer)

    def on_event(event: Any) -> None:
        hits = engine.evaluate(event)

        # Secondary corroboration (hash + decoded-content) — never produces rule_hit
        corr: CorroborationResult = corroborate_event(event)
        if corr.has_findings:
            log_corroboration(event, hits, corr, log=_corr_logger)

        if not hits:
            return

        for hit in hits:
            line = _format_hit(hit, event)
            print(line)
            log_file.write(line + "\n")
            log_file.flush()

        # Phase 3 — persist to SQLite (additive; does not affect pipeline behaviour)
        try:
            _event_db_id = _storage_writer.write_event(event)
            for _hit in hits:
                _hit_db_id = _storage_writer.write_rule_hit(_hit, _event_db_id)
                _alert_manager.process_hit(_hit, _hit_db_id, _event_db_id, event)
        except Exception as _exc:
            logger.warning("SQLite persistence failed (non-fatal): %s", _exc)

    poller = None
    try:
        poller = run_collector(
            callback=on_event,
            poll_interval=2,
            bookmark_path=Path("logs/.shadowsensor_bookmark.xml"),
        )
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if poller is not None:
            poller.stop()
        log_file.write(f"[{_timestamp()}] === SESSION END ===\n")
        log_file.close()
        print("[INFO] Pipeline stopped. Rule hits written to logs/rule_hits.log")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
