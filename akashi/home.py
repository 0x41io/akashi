"""
Where Akashi keeps its data (the proof history).

Same rule as Monomi's home.py:
  1. the AKASHI_HOME environment variable, if set
  2. else the repo folder, when Akashi runs from a copy of the repo
  3. else ~/.akashi (a plain pip install), so nothing is written inside the
     installed package folder.
"""

import os
import tomllib

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(PACKAGE_DIR)
ENV_VAR = "AKASHI_HOME"


def running_from_repo(folder=REPO_DIR) -> bool:
    """True if the folder above the akashi/ package is a copy of the repo
    (its pyproject.toml names akashi). A plain install lives in site-packages,
    where that file isn't present."""
    try:
        with open(os.path.join(folder, "pyproject.toml"), "rb") as f:
            return tomllib.load(f).get("project", {}).get("name") == "akashi"
    except (OSError, tomllib.TOMLDecodeError):
        return False


def data_home() -> str:
    chosen = os.environ.get(ENV_VAR, "").strip()
    if chosen:
        return os.path.abspath(os.path.expanduser(chosen))
    if running_from_repo():
        return REPO_DIR
    return os.path.join(os.path.expanduser("~"), ".akashi")


def data_dir(*parts) -> str:
    return os.path.join(data_home(), *parts)
