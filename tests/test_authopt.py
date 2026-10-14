"""OpenSSH's own sshauthopt_parse cases (regress/unittests/authopt/tests.c) run through the parser.

The file is fetched by scripts/fetch_upstream.py; the cases are read from it at test time.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from authkeyline import AuthKeyError, AuthorizedKey
from authkeyline._options import read_options

UPSTREAM = Path(__file__).parent / "upstream" / "authopt-tests.c"
C_STRING = r'"((?:[^"\\]|\\.)*)"'


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def _cases() -> tuple[list[str], list[str], list[tuple[str, str]]]:
    if not UPSTREAM.is_file():
        pytest.skip("authopt-tests.c not fetched; run scripts/fetch_upstream.py")
    text = UPSTREAM.read_text(encoding="utf-8")
    body = text.split("test_authkeys_parse(void)", 1)[1].split("\ntest_cert_parse", 1)[0]
    good = [_unescape(s) for s in re.findall(rf"sshauthopt_parse\({C_STRING}, &errstr\)", body)]
    bad = [_unescape(pair[1]) for pair in re.findall(rf"FAIL_TEST\({C_STRING}, {C_STRING}\)", body)]
    for keyword in re.findall(rf"\tFLAG_TEST\({C_STRING},", body):
        good += [keyword, "restrict," + keyword]
    for keyword, value in re.findall(rf"\tSTRING_TEST\({C_STRING}, \w+, {C_STRING}\)", body):
        option = f'{keyword}="{value}"'
        good += [option, f"restrict,{option},restrict"]
    arrays = re.findall(rf"\tARRAY_TEST\({C_STRING}, {C_STRING},\s+\w+, \w+, {C_STRING}\)", body)
    expected = [(_unescape(kws), value) for _, kws, value in arrays]
    for keywords, _ in expected:
        good += [keywords, f"restrict,{keywords},restrict"]
    return good, bad, expected


def test_the_upstream_corpus_is_complete() -> None:
    good, bad, arrays = _cases()
    assert (len(good), len(bad), len(arrays)) == (39, 15, 3)


def test_upstream_accepted_fields_parse() -> None:
    good, _, _ = _cases()
    for field in good:
        options, end = read_options(field)
        assert end == len(field.rstrip()), field
        unquoted = re.sub(r'"[^"]*"', "", field)
        assert len(options) == (unquoted.count(",") + 1 if field.strip() else 0), field


def test_upstream_rejected_fields_raise() -> None:
    _, bad, _ = _cases()
    for field in bad:
        with pytest.raises(AuthKeyError):
            read_options(field)


def test_upstream_array_values() -> None:
    _, _, arrays = _cases()
    for keywords, value in arrays:
        key = AuthorizedKey("ssh-ed25519", "", read_options(keywords)[0])
        name = keywords.split("=", 1)[0]
        if name == "environment":
            got = [f"{k}={v}" for k, v in key.environment().items()]
        else:
            got = list(key.values(name))
        assert got == value.split(","), keywords
