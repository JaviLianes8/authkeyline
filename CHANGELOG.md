# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

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
- The `authkeyline` command (and `python -m authkeyline`): an `ssh-keygen -l` style
  listing, `--json`, `--check`, `-E md5`.


## [0.1.0]

- Parse one `authorized_keys` line into an `AuthorizedKey` with `parse_line`.
- Build a line back from a record with `build_line`.
- Read a whole file, skipping blanks and comments, with `parse_file`.
- Typed records: `AuthorizedKey`, `KeyOption`, and `key_bytes()` to decode the blob.
- `AuthKeyError` for lines that are not valid entries.
