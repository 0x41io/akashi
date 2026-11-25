"""The Monomi pin lives in two files (pyproject.toml for installs,
requirements.txt for `pip install -r`). They drifted once (v1.24.0 vs
v1.21.0), which made a development install fail with conflicting URLs.
This keeps them identical."""

import os
import re
import tomllib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN = re.compile(r"monomi @ (git\+https://github\.com/0x41io/monomi@v\d+\.\d+\.\d+)")


def test_pyproject_and_requirements_pin_the_same_monomi():
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
        deps = tomllib.load(f)["project"]["dependencies"]
    from_pyproject = [m.group(1) for d in deps if (m := PIN.fullmatch(d.strip()))]
    with open(os.path.join(REPO, "requirements.txt")) as f:
        from_requirements = [m.group(1) for line in f if (m := PIN.fullmatch(line.strip()))]
    assert len(from_pyproject) == 1 and from_pyproject == from_requirements


def test_monomi_is_new_enough_for_the_url_checks():
    # v1.25.0 is where scope.request_host / named_host come from
    from monomi.common import parse_version, VERSION
    assert parse_version(VERSION) >= (1, 25, 0)


def test_monomi_is_new_enough_for_exposed_files():
    # v1.27.0 builds exposed_file paths and has content.recheck_file
    from monomi import content
    from monomi.common import parse_version, VERSION
    assert parse_version(VERSION) >= (1, 27, 0) and callable(content.recheck_file)
