#!/usr/bin/env python3
"""End-to-end smoke test: Normalizer -> Rule Engine pipeline.

Standalone runner (not part of pytest). Reads a Phase 0A Event ID 1 XML sample,
normalizes it, evaluates rules, then repeats with a synthetic encoded-command event.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Repo root on sys.path when invoked as `python scripts/smoke_test_pipeline.py`
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from normalizer.models import ProcessCreateEvent  # noqa: E402
from normalizer.parser import parse_event  # noqa: E402
from rules.engine import RuleEngine  # noqa: E402

LAB_SAMPLES_DIR = Path(r"C:\sysmon")
FIXTURE_SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "sysmon_samples"
EVENT1_CANDIDATE_NAMES = (
    "sample_event_1_processcreate.xml",
    "event_1_processcreate.xml",
    "processcreate.xml",
    "event1.xml",
)
EXPECTED_SYNTHETIC_RULE_ID = "PS_ENCODED_CMD_001"
EXPECTED_SYNTHETIC_RULE_NAME = "PowerShell Encoded Command"


def find_event1_xml() -> Path | None:
    """Locate an Event ID 1 ProcessCreate XML sample from lab or repo fixtures."""
    search_dirs = [LAB_SAMPLES_DIR, FIXTURE_SAMPLES_DIR]
    for directory in search_dirs:
        if not directory.is_dir():
            continue
        for name in EVENT1_CANDIDATE_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        for path in sorted(directory.glob("*.xml")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "<EventID>1</EventID>" in text:
                return path
    return None


def make_synthetic_encoded_command_event() -> ProcessCreateEvent:
    """Minimal ProcessCreateEvent that should match PS_ENCODED_CMD_001."""
    return ProcessCreateEvent(
        event_id=1,
        utc_time="2026-06-23T12:00:00.000000000Z",
        computer="SMOKE-TEST-HOST",
        process_guid="{00000000-0000-0000-0000-000000000001}",
        process_id=9999,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -EncodedCommand JABjAG0AZAAgACgAIAAiAEgAZQBsAGwAbwAiACAAKQA=",
        current_directory="C:\\",
        user=r"SMOKE-TEST-HOST\User",
        parent_process_id=1234,
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe",
        integrity_level="Medium",
        hashes=None,
    )


def main() -> int:
    print("=" * 60)
    print("ShadowSensor Pipeline Smoke Test")
    print("=" * 60)

    xml_path = find_event1_xml()
    if xml_path is None:
        print("FAIL: No Event ID 1 XML sample found.")
        print(f"  Checked: {LAB_SAMPLES_DIR}")
        print(f"  Checked: {FIXTURE_SAMPLES_DIR}")
        return 1

    print(f"XML sample: {xml_path}")
    print()

    step_results: dict[str, str] = {}
    exit_code = 0

    # Step 1 + 2: Read XML -> Normalizer
    try:
        xml = xml_path.read_text(encoding="utf-8")
        event = parse_event(xml)
        if event is None:
            step_results["Step 1-2 (XML -> Normalizer)"] = "FAIL — parse_event returned None"
            exit_code = 1
        elif not isinstance(event, ProcessCreateEvent):
            step_results["Step 1-2 (XML -> Normalizer)"] = (
                f"FAIL — expected ProcessCreateEvent, got {type(event).__name__}"
            )
            exit_code = 1
        else:
            step_results["Step 1-2 (XML -> Normalizer)"] = (
                f"PASS — ProcessCreateEvent (image={event.image!r})"
            )
    except Exception as exc:
        step_results["Step 1-2 (XML -> Normalizer)"] = f"FAIL — {type(exc).__name__}: {exc}"
        exit_code = 1
        event = None

    # Step 3: Benign event -> Rule Engine
    try:
        engine = RuleEngine(rules_dir=REPO_ROOT / "rules")
        engine.load()
        print(f"Rule engine loaded: {engine.rule_count} rules")
        print()

        if event is not None:
            benign_hits = engine.evaluate(event)
            hit_summary = (
                ", ".join(f"{h.rule_id} ({h.rule_name})" for h in benign_hits)
                or "(none — expected for benign sample)"
            )
            step_results["Step 3 (Benign -> Rule Engine)"] = f"PASS — rule_hits: {hit_summary}"
        else:
            step_results["Step 3 (Benign -> Rule Engine)"] = "SKIP — no normalized event"
            exit_code = 1
    except Exception as exc:
        step_results["Step 3 (Benign -> Rule Engine)"] = f"FAIL — {type(exc).__name__}: {exc}"
        exit_code = 1
        engine = None

    # Step 4: Synthetic encoded-command -> Rule Engine
    try:
        if engine is None:
            step_results["Step 4 (Synthetic -EncodedCommand)"] = "SKIP — rule engine not loaded"
            exit_code = 1
        else:
            synthetic = make_synthetic_encoded_command_event()
            synthetic_hits = engine.evaluate(synthetic)
            matching = [h for h in synthetic_hits if h.rule_id == EXPECTED_SYNTHETIC_RULE_ID]
            if matching:
                hit = matching[0]
                step_results["Step 4 (Synthetic -EncodedCommand)"] = (
                    f"PASS — rule_hit: {hit.rule_id} ({hit.rule_name})"
                )
            elif synthetic_hits:
                names = ", ".join(f"{h.rule_id} ({h.rule_name})" for h in synthetic_hits)
                step_results["Step 4 (Synthetic -EncodedCommand)"] = (
                    f"FAIL — hits fired but not {EXPECTED_SYNTHETIC_RULE_ID}: {names}"
                )
                exit_code = 1
            else:
                step_results["Step 4 (Synthetic -EncodedCommand)"] = (
                    f"FAIL — no rule_hit (expected {EXPECTED_SYNTHETIC_RULE_ID} "
                    f"/ {EXPECTED_SYNTHETIC_RULE_NAME!r})"
                )
                exit_code = 1
    except Exception as exc:
        step_results["Step 4 (Synthetic -EncodedCommand)"] = f"FAIL — {type(exc).__name__}: {exc}"
        exit_code = 1

    print("Results")
    print("-" * 60)
    for step, result in step_results.items():
        print(f"  {step}: {result}")
    print("-" * 60)
    print("OVERALL:", "PASS" if exit_code == 0 else "FAIL")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
