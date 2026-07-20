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
from ml.features.pipeline import FeatureExtractionPipeline
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
    args = parser.parse_args()

    db_path = Path(args.db)
    output_path = Path(args.output)

    print(f"[INFO] Reading from: {db_path}")
    if str(db_path) != ":memory:" and not db_path.exists():
        print(f"[WARN] Database not found: {db_path} — no events to extract")
        vectors: list[dict] = []
    else:
        vectors = FeatureExtractionPipeline(db_path).run(label=args.label)

    print(f"[INFO] Extracted {len(vectors)} process windows")
    exported_path = export_to_csv(vectors, output_path, label=args.label)
    print(f"[INFO] Exported to: {exported_path}")
    print(f"[INFO] Features per row: {len(FEATURE_NAMES) + (1 if args.label is not None else 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
