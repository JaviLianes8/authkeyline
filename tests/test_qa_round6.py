"""Round 6 QA contracts: the reason for an unknown key type without options, and plain hashes."""

from __future__ import annotations

import pytest

from authkeyline import AuthKeyError, AuthorizedKey, LineProblem, check_file, parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
# Hand-written: a DSA blob prefix (string "ssh-dss" then a length), not a real key.
DSS_BLOB = "AAAAB3NzaC1kc3MAAACBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq"


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (f"ssh-dss {DSS_BLOB} old", "unsupported key type 'ssh-dss'"),
        (f"ssh-dss {DSS_BLOB}", "unsupported key type 'ssh-dss'"),
        (f"ssh-ed2551 {BLOB} typo", "unsupported key type 'ssh-ed2551'"),
        (f"  ssh-dss\t{DSS_BLOB}", "unsupported key type 'ssh-dss'"),
        (f"{'k' * 60} {BLOB}", f"unsupported key type {'k' * 40!r}... (60 characters)"),
        (f"no-pty ssh-dss {DSS_BLOB} old", "unsupported key type 'ssh-dss'"),
    ],
)
def test_an_unknown_key_type_before_a_blob_is_named_as_a_key_type(line: str, reason: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line)
    assert caught.value.reason == reason
    assert check_file(f"# keys\n{line}\n") == [LineProblem(2, reason)]


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (f"bogus ssh-ed25519 {BLOB}", "unknown option 'bogus'"),
        ("bogus", "unknown option 'bogus'"),
        (f"bogus ssh-ed25519-x {BLOB}", "unknown option 'bogus'"),
        (f"no-pty,bogus {BLOB}", "unknown option 'bogus'"),
        (f"bogus=1 {BLOB}", "unknown option 'bogus'"),
        (f"command=x {BLOB}", "value of 'command' must be in double quotes"),
    ],
)
def test_an_unknown_option_is_still_named_as_an_option(line: str, reason: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line)
    assert caught.value.reason == reason


def test_a_known_flag_before_a_blob_still_names_the_blob_field() -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"restrict {BLOB}")
    assert caught.value.reason.startswith("unsupported key type 'AAAAC3")


class _AlwaysEqual(str):
    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize("record", ["public", "authorized"])
def test_fingerprint_compares_a_plain_copy_of_the_hash(record: str) -> None:
    key = AuthorizedKey("ssh-ed25519", BLOB)
    target = key.public_key() if record == "public" else key
    with pytest.raises(AuthKeyError) as caught:
        target.fingerprint(_AlwaysEqual("sha1"))  # type: ignore[arg-type]
    assert caught.value.reason == "unknown fingerprint hash 'sha1', use 'sha256' or 'md5'"
    md5 = target.fingerprint(_AlwaysEqual("md5"))  # type: ignore[arg-type]
    assert md5 == "MD5:0f:a2:0a:d7:38:3e:65:45:08:6b:63:84:1c:ff:dc:ba"
