"""Launch the ShadowSensor dashboard server on port 8080."""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from storage.database import init_db


if __name__ == "__main__":
    init_db()
    uvicorn.run("dashboard.app:app", host="0.0.0.0", port=8080, reload=False, log_level="info")
