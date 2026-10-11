import base64

import pytest

from authkeyline import (
    AuthKeyError,
    AuthorizedKey,
    KeyOption,
    build_line,
    parse_file,
    parse_line,
)

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAICdummyblobvalue0000000000000000000000000"


def test_key_with_no_options() -> None:
    key = parse_line(f"ssh-ed25519 {BLOB} alice@host")
    assert key.options == ()
    assert key.key_type == "ssh-ed25519"
    assert key.key_base64 == BLOB
    assert key.comment == "alice@host"


def test_key_with_flag_options() -> None:
    key = parse_line(f"no-pty,no-port-forwarding ssh-rsa {BLOB}")
    assert key.options == (KeyOption("no-pty"), KeyOption("no-port-forwarding"))
    assert key.comment == ""


def test_key_with_valued_quoted_options() -> None:
    line = f'command="/bin/echo hi, there",from="10.0.0.1,10.0.0.2" ssh-rsa {BLOB} op'
    key = parse_line(line)
    assert key.options == (
        KeyOption("command", "/bin/echo hi, there"),
        KeyOption("from", "10.0.0.1,10.0.0.2"),
    )
    assert key.comment == "op"


def test_quoted_value_keeps_escaped_quote_and_backslash() -> None:
    (option,) = parse_line(f'command="say \\"hi\\" c:\\\\x" ssh-rsa {BLOB}').options
    assert option == KeyOption("command", 'say "hi" c:\\x')


def test_comment_with_spaces_is_preserved() -> None:
    key = parse_line(f"ssh-ed25519 {BLOB} a long comment here")
    assert key.comment == "a long comment here"


def test_parse_file_skips_blanks_and_comments() -> None:
    text = f"\n# a comment\nssh-rsa {BLOB} one\n\n  # indented comment\nssh-rsa {BLOB} two\n"
    keys = parse_file(text)
    assert [k.comment for k in keys] == ["one", "two"]


def test_build_round_trip() -> None:
    line = f'command="/bin/x",no-pty,from="10.0.0.1" ssh-ed25519 {BLOB} user@host'
    assert build_line(parse_line(line)) == line


def test_build_without_options_or_comment() -> None:
    key = AuthorizedKey(key_type="ssh-rsa", key_base64=BLOB)
    assert build_line(key) == f"ssh-rsa {BLOB}"


def test_key_bytes_decodes_the_blob() -> None:
    blob = base64.b64encode(b"hello").decode()
    assert parse_line(f"ssh-ed25519 {blob}").key_bytes() == b"hello"


@pytest.mark.parametrize("line", ["", "   ", "# comment", "ssh-rsa", "no-pty ssh-rsa"])
def test_malformed_lines_raise(line: str) -> None:
    with pytest.raises(AuthKeyError):
        parse_line(line)


def test_non_base64_blob_raises() -> None:
    with pytest.raises(AuthKeyError):
        parse_line("ssh-rsa not+valid!!! comment")
