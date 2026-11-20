"""The proxy image installs only the third-party distributions its code imports."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile.proxy"

# Import name -> requirements.txt distribution name.
_DISTRIBUTION_FOR_IMPORT = {
    "flask": "flask",
    "werkzeug": "werkzeug",
    "gunicorn": "gunicorn",
    "pymysql": "pymysql",
    "cryptography": "cryptography",
    # Flask's own dependency, always present when Flask is installed.
    "markupsafe": "flask",
}


def _proxy_distributions() -> set[str]:
    text = DOCKERFILE.read_text(encoding="utf-8")
    match = re.search(r"grep -iE '\^\((?P<names>[a-z|]+)\)==' requirements\.txt", text)
    assert match is not None
    return set(match.group("names").split("|"))


def _packaged_python_files() -> list[Path]:
    text = DOCKERFILE.read_text(encoding="utf-8")
    files = [
        REPO_ROOT / path
        for path in re.findall(r"\b(web/(?:services|tools)/\w+\.py)\b", text)
    ]
    files.extend(sorted((REPO_ROOT / "proxy").glob("*.py")))
    files.extend(
        REPO_ROOT / "docker" / name
        for name in ("cicap_av_runner.py", "icap_readiness.py")
    )
    return files


def _third_party_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    # apply_common is a sibling module imported by the /app/tools helpers.
    # publicsuffix2 is an optional, uninstalled import with a built-in fallback.
    local = {"services", "tools", "proxy", "apply_common", "publicsuffix2"}
    return {
        name
        for name in names
        if name not in local and name not in sys.stdlib_module_names
    }


def test_proxy_image_installs_every_imported_distribution_and_nothing_else() -> None:
    distributions = _proxy_distributions()
    requirements = (REPO_ROOT / "web" / "requirements.txt").read_text(encoding="utf-8")
    pinned = {
        line.split("==", 1)[0].strip().lower()
        for line in requirements.splitlines()
        if "==" in line and not line.lstrip().startswith("#")
    }
    assert distributions <= pinned

    imported: dict[str, set[str]] = {}
    for path in _packaged_python_files():
        for name in _third_party_imports(path):
            imported.setdefault(name, set()).add(path.name)

    unknown = sorted(set(imported) - set(_DISTRIBUTION_FOR_IMPORT))
    assert not unknown, f"unmapped third-party imports in proxy image: {unknown}"
    needed = {_DISTRIBUTION_FOR_IMPORT[name] for name in imported}
    supervisord = (REPO_ROOT / "docker" / "supervisord.proxy.conf").read_text(
        encoding="utf-8"
    )
    if "python3 -m gunicorn" in supervisord:
        needed.add("gunicorn")
    assert needed == distributions


def test_proxy_image_ships_precompiled_bytecode() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert "--no-compile" not in text
    assert "RUN python3 -m compileall -q /app" in text
