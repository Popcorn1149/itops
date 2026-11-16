"""The README must document the running version: every release bumps VERSION and adds a changelog entry."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_readme_matches_app_version():
    src = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    version = re.search(r'^VERSION = "([^"]+)"', src, re.M).group(1)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"**{version}**" in readme, f"README header table must show version {version}"
    assert re.search(rf"^### {re.escape(version)} · \d{{4}}-\d{{2}}-\d{{2}}", readme, re.M), \
        f"README changelog needs an entry '### {version} · YYYY-MM-DD · …'"
    agent = (ROOT / "backend" / "agent_dist" / "VERSION").read_text(encoding="utf-8").strip()
    assert f"| {agent} |" in readme, f"README header table must show agent version {agent}"
