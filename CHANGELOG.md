# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-19

The first release on PyPI. The public API (the names in `__all__`, their parameters, the
fields of the records and the error types) is now stable and follows semantic
versioning. Every line is read the way OpenSSH's own C code reads it, which the test
suite checks by running that code on 12,000 seeded lines.

### Changed

- `expiry-time` accepts a seconds field of 61, as `strptime` in sshd does; 0.2.0 refused
  it.
- `build_line` raises `TypeError` for fields of the wrong type (`options` must be a tuple
  of `KeyOption`, names and values text) instead of an `AttributeError` or a misleading
  `AuthKeyError`. It now lives in its own private module; import it from `authkeyline`
  as before.
- `AuthorizedKey.values`, `AuthorizedKey.has_flag` and both `fingerprint` methods raise
  `TypeError` for an argument that is not a `str`.
- Error messages quote at most 40 characters of any value from the input, with its full
  length when cut, and never the value of an `environment` option.
- Text fields inside a key blob (type and curve names, the security key application,
  certificate key id and principals) are read as `sshbuf_get_cstring` reads them: one
  final NUL is allowed and dropped, a NUL before the end is refused.
- A blob longer than OpenSSH's 128 MiB buffer is refused before it is decoded.
- The methods of `AuthorizedKey` (`public_key`, `fingerprint`, `key_bytes`, `values`,
  `has_flag`, `environment`) check the fields of a hand-built record as `build_line`
  does and raise `TypeError` for one of the wrong type, instead of an `AttributeError`,
  an unrelated `TypeError` or an `AuthKeyError`. `str` subclasses in any field or
  argument are read as plain text, and `build_line` checks and returns plain text.
- An unknown key type of a hand-built record is quoted to 40 characters like every other
  value. A key type holding `=` or `"`, which is what a blank after a comma leaves where
  the key type goes (`no-pty, environment="..."`), is not quoted at all, so the value of
  that option cannot reach the message.
- The public names report `authkeyline` as their module, so pickles and reprs never name
  a private module.
- Command line: the listing shows the comment column as portable `ssh-keygen -l` does in
  a UTF-8 locale. The options field stands in for a missing comment, a comment starting
  with `#` is not shown, trailing blanks are kept, and control characters and bytes that
  are not UTF-8 are written as `\ooo` octal escapes instead of raw bytes, so a comment
  cannot send escape sequences to a terminal.
- Command line: `--json` writes valid Unicode. A byte that is not UTF-8 becomes U+FFFD,
  and such an entry also carries `line_base64`, the exact bytes of the line.
- Command line: when the reader closes the pipe early (`| head`), the command ends
  quietly with the status it had instead of a traceback.

### Added

- Runnable examples in the docstring of every public name, run as doctests.
- `GUIDE.md`, the rules in detail.
- Help text for `-E`, and the exit statuses in `--help`; status 2 also covers usage errors.
- `scripts/sshd-oracle/`: OpenSSH's own reading code behind a small harness, and a test
  that compares the library with it when `AUTHKEYLINE_SSHD_HARNESS` is set.

## [0.2.0] - 2026-10-14

### Fixed

- Option values are dequoted as sshd does it: only `\"` is an escape, other backslashes
  are kept. 0.1.0 dropped them, so a parsed and rebuilt `command=` could change.
- `build_line` could be steered into extra options, lines or keys through option names,
  values ending in a backslash, line breaks in values or comments, or a key type with
  spaces. It now refuses them and checks that the line reads back as the same record.
- Key types are recognised by name from OpenSSH's table instead of by prefix, so
  `rsa-sha2-256` lines parse and option fields such as `ssh-x` are not taken for keys.

### Added

- Options are checked like sshd: known names only (case-insensitive), quoted values,
  single `command`, `principals` and `from`, `environment`, `permitopen`,
  `permitlisten`, `tunnel` and `expiry-time` formats, and sshd's count limits.
- The key blob is decoded and checked: embedded type and curve agree with the line,
  Ed25519 and ML-DSA-44 key sizes, ECDSA points on the curve, security key application,
  RSA moduli of at least 1024 bits, certificates (OpenSSH format, signature not verified).
- `AuthorizedKey.public_key()`, `fingerprint()` (SHA256 and MD5 as `ssh-keygen -l` prints
  them), `values()`, `has_flag()` and `environment()`; `PublicKey` and `Certificate`.
- `check_file` lists every broken line; `AuthKeyError` carries `reason` and `line`.
- `KEY_TYPES`, the key type names sshd accepts.
- Lines are read as sshd reads them: a NUL ends the line, CR and other C whitespace are
  ignored inside the blob and allowed in the comment, the base64 must be canonical (no
  set spare bits), numbers in `tunnel` and ports may carry a sign or leading blanks, and
  an `expiry-time` at the UTC epoch is refused.
- Certificate signature types must fit the CA key; the signature itself is not verified.
- The `authkeyline` command (and `python -m authkeyline`): an `ssh-keygen -l` style
  listing that keeps comment bytes as they are, `--json`, `--check`, `-E md5`; exit
  status 1 for broken lines and 2 for unreadable files.


## [0.1.0] - 2026-10-11

- Parse one `authorized_keys` line into an `AuthorizedKey` with `parse_line`.
- Build a line back from a record with `build_line`.
- Read a whole file, skipping blanks and comments, with `parse_file`.
- Typed records: `AuthorizedKey`, `KeyOption`, and `key_bytes()` to decode the blob.
- `AuthKeyError` for lines that are not valid entries.
