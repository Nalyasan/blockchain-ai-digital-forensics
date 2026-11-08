#!/usr/bin/env python3
"""Launcher for FastAPI Forensic Dashboard (scripts/run_dashboard.py).

Binds by default to 127.0.0.1:8000.
CLI Usage:
    python scripts/run_dashboard.py --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from forensics.paths import get_host, get_port

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("run_dashboard")


def main() -> int:
    parser = argparse.ArgumentParser(description="Blockchain + AI Digital Forensics FastAPI Dashboard")
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", get_host()),
        help="Host interface to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", get_port())),
        help="Port to bind (default: 8000)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload for development",
    )

    args = parser.parse_args()

    logger.info("=" * 70)
    logger.info("Starting Blockchain + AI Digital Forensics Dashboard")
    logger.info("Host: %s | Port: %d", args.host, args.port)
    logger.info("URL:  http://%s:%d", args.host, args.port)
    logger.info("=" * 70)

    import uvicorn
    uvicorn.run(
        "dashboard.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
