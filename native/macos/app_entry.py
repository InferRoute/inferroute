"""App-owned entry point. Python, dependencies and client all live in the bundle."""

import os

os.environ["IR_ATTESTED_CONFINE"] = "require"
os.environ["PYTHONNOUSERSITE"] = "1"
os.environ["PYTHONSAFEPATH"] = "1"
from inferroute_cli.probant import main

raise SystemExit(main(["home"]))
