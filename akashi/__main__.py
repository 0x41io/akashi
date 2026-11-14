"""Lets `python -m akashi ...` run the command line."""

import sys

from akashi.cli import main

if __name__ == "__main__":
    sys.exit(main())
