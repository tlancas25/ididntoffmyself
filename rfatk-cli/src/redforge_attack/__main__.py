"""Allow `python -m redforge_attack ...` as an alternative to the `rfatk` entry point."""

from redforge_attack.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
