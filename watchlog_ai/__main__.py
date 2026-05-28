from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .config import Config
from .runner import run_forever, run_once


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-powered access/error log watcher.")
    parser.add_argument("--env-file", default=".env", help="Path to .env file")
    parser.add_argument("--once", action="store_true", help="Check once and exit")
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = Config.from_env(Path(args.env_file))
    if args.once:
        result = run_once(config)
        print(
            f"checked={','.join(result.checked_files) or '-'} "
            f"severity={result.severity.value} notified={result.notified}"
        )
        return
    run_forever(config)


if __name__ == "__main__":
    main()

