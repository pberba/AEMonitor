"""Allow running as python -m aemonitor."""

from aemonitor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
