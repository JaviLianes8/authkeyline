"""The README examples run and print what their comments say; docs and versions agree."""

from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

import authkeyline

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _python_blocks() -> list[str]:
    return re.findall(r"```python\n(.*?)```", README, flags=re.DOTALL)


def _expected_output(block: str) -> list[str]:
    """Comment lines in the README examples hold exactly what the block prints, in order."""
    return [line[2:] for line in block.splitlines() if line.startswith("# ")]


def test_every_readme_example_runs_and_prints_its_comments() -> None:
    blocks = _python_blocks()
    assert len(blocks) == 5
    checked = 0
    for block in blocks:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(compile(block, "README.md", "exec"), {"__name__": "readme"})
        expected = _expected_output(block)
        assert expected, block
        assert out.getvalue().splitlines() == expected
        checked += len(expected)
    assert checked == 14


def test_the_api_table_lists_every_public_name() -> None:
    table = README.split("## API", 1)[1].split("\n## ", 1)[0]
    for name in authkeyline.__all__:
        assert f"`{name}" in table, name


def test_version_matches_pyproject() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, flags=re.MULTILINE)
    assert match is not None
    assert match.group(1) == authkeyline.__version__


def test_changelog_has_an_entry_for_this_version() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{authkeyline.__version__}]" in text


def test_no_em_dash_anywhere_in_the_tree() -> None:
    suffixes = {".py", ".md", ".toml", ".ps1", ".txt", ".yml", ".json"}
    for path in ROOT.rglob("*"):
        parts = path.relative_to(ROOT).parts
        if not path.is_file() or path.suffix not in suffixes or parts[:2] == ("tests", "upstream"):
            continue
        if any(
            (part.startswith(".") and part != ".github") or part == "__pycache__" for part in parts
        ):
            continue
        assert chr(0x2014) not in path.read_text(encoding="utf-8"), path


def test_source_files_stay_under_two_hundred_lines() -> None:
    for path in [*ROOT.joinpath("src").rglob("*.py"), *ROOT.joinpath("tests").rglob("*.py")]:
        assert len(path.read_text(encoding="utf-8").splitlines()) <= 200, path
