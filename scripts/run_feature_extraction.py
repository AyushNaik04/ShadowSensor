#!/usr/bin/env python3
"""Run Phase 5 feature extraction and export to CSV."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.features.exporter import default_output_path, export_to_csv
from ml.features.feature_spec import FEATURE_NAMES
from ml.features.pipeline import FeatureExtractionPipeline, parse_time_bound
from storage.database import DB_PATH


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract process-window features from SQLite.")
    parser.add_argument("--label", type=int, default=None, help="Optional label to append to every row.")
    parser.add_argument(
        "--output",
        type=str,
        default=str(default_output_path()),
        help="Output CSV path.",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=str(DB_PATH),
        help="SQLite database path.",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help="Optional inclusive lower bound on event/rule_hit timestamp "
        "(YYYY-MM-DD HH:MM:SS[.ffffff] or ISO-8601 with T).",
    )
    parser.add_argument(
        "--until",
        type=str,
        default=None,
        help="Optional inclusive upper bound on event/rule_hit timestamp "
        "(YYYY-MM-DD HH:MM:SS[.ffffff] or ISO-8601 with T). "
        "Whole-second values are padded to .999999 so the entire second is included; "
        "explicit fractional values are used as given with no padding.",
    )
    args = parser.parse_args()

    try:
        time_from = (
            parse_time_bound(args.since, bound_name="--since") if args.since is not None else None
        )
        time_to = (
            parse_time_bound(args.until, bound_name="--until") if args.until is not None else None
        )
        if time_from is not None and time_to is not None and time_from > time_to:
            raise ValueError(
                f"--since ({args.since!r} → {time_from!r}) is after "
                f"--until ({args.until!r} → {time_to!r})"
            )
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    db_path = Path(args.db)
    output_path = Path(args.output)

    print(f"[INFO] Reading from: {db_path}")
    if str(db_path) != ":memory:" and not db_path.exists():
        print(f"[WARN] Database not found: {db_path} — no events to extract")
        vectors: list[dict] = []
    else:
        vectors = FeatureExtractionPipeline(db_path).run(
            label=args.label,
            time_from=time_from,
            time_to=time_to,
        )

    print(f"[INFO] Extracted {len(vectors)} process windows")
    exported_path = export_to_csv(vectors, output_path, label=args.label)
    print(f"[INFO] Exported to: {exported_path}")
    print(f"[INFO] Features per row: {len(FEATURE_NAMES) + (1 if args.label is not None else 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
