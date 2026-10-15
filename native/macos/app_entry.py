"""App-owned entry point. Python, dependencies and client all live in the bundle."""

import os

os.environ["IR_ATTESTED_CONFINE"] = "require"
os.environ["PYTHONNOUSERSITE"] = "1"
os.environ["PYTHONSAFEPATH"] = "1"
# Sessions are started as `python -m inferroute_cli ...` with this environment: none of them may write
# bytecode inside the signed bundle (a new file there breaks the bundle's signature seal).
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
from inferroute_cli.probant import main

raise SystemExit(main(["home"]))
