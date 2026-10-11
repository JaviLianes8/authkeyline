# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

- Parse one `authorized_keys` line into an `AuthorizedKey` with `parse_line`.
- Build a line back from a record with `build_line`.
- Read a whole file, skipping blanks and comments, with `parse_file`.
- Typed records: `AuthorizedKey`, `KeyOption`, and `key_bytes()` to decode the blob.
- `AuthKeyError` for lines that are not valid entries.
