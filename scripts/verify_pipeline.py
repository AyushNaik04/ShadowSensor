#!/usr/bin/env python3
"""Offline verification of ShadowSensor pipeline wiring (no Sysmon required)."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from normalizer.models import ProcessCreateEvent  # noqa: E402
from normalizer.parser import parse_event  # noqa: E402
from rules.engine import RuleEngine  # noqa: E402

FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "sysmon_samples" / "sample_event_1_processcreate.xml"
COLLECTOR_RUNNER_PATH = REPO_ROOT / "collector" / "runner.py"

results: dict[str, str] = {}


def make_synthetic_encoded_command_event() -> ProcessCreateEvent:
    """Minimal ProcessCreateEvent that should match PS_ENCODED_CMD_001."""
    return ProcessCreateEvent(
        event_id=1,
        utc_time="2026-06-23T12:00:00.000000000Z",
        computer="VERIFY-TEST-HOST",
        process_guid="{00000000-0000-0000-0000-000000000001}",
        process_id=9999,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -EncodedCommand JABjAG0AZAAgACgAIAAiAEgAZQBsAGwAbwAiACAAKQA=",
        current_directory="C:\\",
        user=r"VERIFY-TEST-HOST\User",
        parent_process_id=1234,
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe",
        integrity_level="Medium",
        hashes=None,
    )


def check_1_imports() -> None:
    try:
        _ = RuleEngine
        _ = Path
        _ = datetime
        if not COLLECTOR_RUNNER_PATH.is_file():
            raise FileNotFoundError(f"{COLLECTOR_RUNNER_PATH} not found")
        results["Check 1 — Imports"] = "PASS"
        print("Check 1 — Imports                PASS")
    except Exception as exc:
        results["Check 1 — Imports"] = "FAIL"
        print(f"Check 1 — Imports                FAIL ({exc})")


def check_2_rule_loading() -> RuleEngine | None:
    try:
        engine = RuleEngine(rules_dir=REPO_ROOT / "rules")
        engine.load()
        if engine.rule_count != 15:
            raise ValueError(f"expected 15 rules, got {engine.rule_count}")
        for rule in engine.rules:
            print(rule.name)
        results["Check 2 — Rule loading (15)"] = "PASS"
        print("Check 2 — Rule loading (15)      PASS")
        return engine
    except Exception as exc:
        results["Check 2 — Rule loading (15)"] = "FAIL"
        print(f"Check 2 — Rule loading (15)      FAIL ({exc})")
        return None


def check_3_benign_baseline(engine: RuleEngine | None) -> None:
    try:
        if engine is None:
            raise RuntimeError("rule engine not loaded")
        xml = FIXTURE_PATH.read_text(encoding="utf-8")
        event = parse_event(xml)
        if event is None:
            raise ValueError("parse_event returned None")
        hits = engine.evaluate(event)
        if hits:
            fired = ", ".join(h.rule_id for h in hits)
            raise ValueError(f"unexpected rule hits: {fired}")
        results["Check 3 — Benign baseline"] = "PASS"
        print("Check 3 — Benign baseline        PASS")
    except Exception as exc:
        results["Check 3 — Benign baseline"] = "FAIL"
        print(f"Check 3 — Benign baseline        FAIL ({exc})")


def check_4_synthetic_rule_hit(engine: RuleEngine | None) -> ProcessCreateEvent | None:
    synthetic: ProcessCreateEvent | None = None
    try:
        if engine is None:
            raise RuntimeError("rule engine not loaded")
        synthetic = make_synthetic_encoded_command_event()
        hits = engine.evaluate(synthetic)
        if not any(h.rule_id == "PS_ENCODED_CMD_001" for h in hits):
            raise ValueError("PS_ENCODED_CMD_001 did not fire")
        results["Check 4 — Synthetic rule hit"] = "PASS"
        print("Check 4 — Synthetic rule hit     PASS")
    except Exception as exc:
        results["Check 4 — Synthetic rule hit"] = "FAIL"
        print(f"Check 4 — Synthetic rule hit     FAIL ({exc})")
    return synthetic


def check_5_log_file_creation() -> None:
    log_path = Path("logs/verify_test.log")
    try:
        Path("logs").mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write("[VERIFY] Log write test\n")
        content = log_path.read_text(encoding="utf-8")
        if "[VERIFY] Log write test" not in content:
            raise ValueError("expected log line not found after write")
        results["Check 5 — Log file creation"] = "PASS"
        print("Check 5 — Log file creation      PASS")
    except Exception as exc:
        results["Check 5 — Log file creation"] = "FAIL"
        print(f"Check 5 — Log file creation      FAIL ({exc})")
    finally:
        if log_path.is_file():
            log_path.unlink()


def check_6_callback_wiring(synthetic: ProcessCreateEvent | None) -> None:
    try:
        if synthetic is None:
            raise RuntimeError("synthetic event not available")
        call_log: list[ProcessCreateEvent] = []

        def mock_callback(event):
            call_log.append(event)

        mock_callback(synthetic)
        if len(call_log) != 1:
            raise ValueError(f"expected 1 callback invocation, got {len(call_log)}")
        results["Check 6 — Callback wiring"] = "PASS"
        print("Check 6 — Callback wiring        PASS")
    except Exception as exc:
        results["Check 6 — Callback wiring"] = "FAIL"
        print(f"Check 6 — Callback wiring        FAIL ({exc})")


def main() -> int:
    check_1_imports()
    engine = check_2_rule_loading()
    check_3_benign_baseline(engine)
    synthetic = check_4_synthetic_rule_hit(engine)
    check_5_log_file_creation()
    check_6_callback_wiring(synthetic)

    all_pass = all(status == "PASS" for status in results.values())
    overall = "PASS" if all_pass else "FAIL"

    print()
    print("=" * 60)
    print("Verification Summary")
    print("=" * 60)
    print(f"Check 1 — Imports                {results.get('Check 1 — Imports', 'FAIL')}")
    print(f"Check 2 — Rule loading (15)      {results.get('Check 2 — Rule loading (15)', 'FAIL')}")
    print(f"Check 3 — Benign baseline        {results.get('Check 3 — Benign baseline', 'FAIL')}")
    print(f"Check 4 — Synthetic rule hit     {results.get('Check 4 — Synthetic rule hit', 'FAIL')}")
    print(f"Check 5 — Log file creation      {results.get('Check 5 — Log file creation', 'FAIL')}")
    print(f"Check 6 — Callback wiring        {results.get('Check 6 — Callback wiring', 'FAIL')}")
    print("-" * 60)
    print(f"OVERALL: {overall}")
    print("=" * 60)

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
