"""CSV exporter for Phase 5 feature vectors."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from ml.features.feature_spec import FEATURE_NAMES


def export_to_csv(
    feature_vectors: list[dict],
    output_path: Path,
    label: int | None = None,
) -> Path:
    """Write feature vectors to CSV and return resolved output path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(FEATURE_NAMES)
    if label is not None:
        fieldnames.append("label")

    with output_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()
        for vector in feature_vectors:
            row = {name: vector.get(name) for name in fieldnames}
            writer.writerow(row)

    return output_path.resolve()


def default_output_path() -> Path:
    """Generate a timestamped output path for exported features."""
    return Path("data/features") / f"features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
