# authkeyline 1.0.0 certification report

The 1.0.0 certification bar applied to authkeyline. PyPI has no release of the name
(`https://pypi.org/pypi/authkeyline/json` answered 404 on 2026-10-18 and again on
2026-10-19), so 1.0.0 is the first published version; changes are listed against 0.2.0,
the state of `main` at 220dd19.

Progress:
- [x] Branch `release/1.0.0` created from `main` (220dd19, version 0.2.0, never on PyPI)
- [x] Baseline gates (at 8b5aff7, where an interrupted run had stopped)
- [x] Ground truth: OpenSSH sources and test data fetched again, ssh-keygen and OpenSSH itself run as oracles (item 7)
- [x] API review and 1.0.0 changes (item 1)
- [x] Errors, typing, docstrings and doctests (items 2 to 5)
- [x] Contract, fuzz and author mutation round (items 6, 9, 18)
- [x] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [x] Packaging, e2e and every Python (items 8, 10, 13, 14)
- [x] Gates (item 15)
- [ ] Five QA lenses (item 19) and independent reviewer (item 16): rounds 1 to 5 findings fixed, awaiting re-verification
- [x] PR #3 and trace guard CLEAN (item 17); merge and publish left to the maintainer

## Scorecard

| # | Item | Result |
| --- | --- | --- |
| 1 | Public API reviewed for stability | PASS: 11 names kept from 0.2.0, signatures and record fields pinned by `tests/test_contract_api.py`; every change in the CHANGELOG |
| 2 | `__all__` exact, no private imports in docs | PASS |
| 3 | Docstrings with runnable examples, doctests | PASS: 18 doctests, every public name and method; README (14 outputs) and GUIDE (11) examples run as tests |
| 4 | Typed end to end | PASS: `mypy --strict src tests`, `py.typed` shipped, a consumer script checked with `mypy --strict` against the installed wheel |
| 5 | Typed, documented, bounded errors | PASS: `AuthKeyError` (a `ValueError`) with `reason` and `line`, `TypeError` for wrong argument types, messages quote at most 40 characters and never an `environment` value |
| 6 | Contract tests of every public name | PASS |
| 7 | Real ground truth | PASS: 26 fetched sources with a hash manifest, OpenSSH's own C code as an oracle on 12,000 seeded lines, `ssh-keygen -l` on fresh keys and certificates |
| 8 | Real e2e from the wheel | PASS: wheel installed in a fresh venv and driven from an empty folder, the command by subprocess; no PyPI release to upgrade from |
| 9 | Seeded fuzz, no crash, hang or blowup | PASS |
| 10 | Supported Pythons | PASS: CPython 3.10.19, 3.11.5, 3.12.12, 3.13.2, 3.14.2 and 3.14.2t, 350 passed each |
| 11 | README and `twine check` | PASS: `twine check --strict`, absolute links, badge, verified comparison |
| 12 | Dated CHANGELOG section | PASS: 1.0.0, 2026-10-19 |
| 13 | pyproject 1.0.0, Production/Stable | PASS |
| 14 | sdist and wheel contents | PASS |
| 15 | Gates each exit 0 | PASS: see Gates |
| 16 | Independent reviewer | pending |
| 17 | PR and trace guard | PR #3 from `release/1.0.0`, trace guard CLEAN; merge and publish left to the maintainer |
| 18 | Contracts bite (mutations) | PASS: 32 author mutants, all killed (2 after new contracts), table in [CERT-1.0-MUTANTS.md](https://github.com/JaviLianes8/authkeyline/blob/main/CERT-1.0-MUTANTS.md) |
| 19 | Five independent QA lenses | pending |

## Baseline

An earlier run created the branch, started this report and committed 8b5aff7 (bounded
error messages, a cap on the blob size, text fields read as `sshbuf_get_cstring` reads
them) before it was cut off. Resumed on 2026-10-19 from a fresh clone at 8b5aff7 on
another machine, CPython 3.14: `ruff format --check .`, `ruff check .` and
`mypy --strict src tests` exit 0, `pytest` 274 passed and 1 skipped (the opt-in wheel
test). No doctests ran then: `--doctest-modules` was not configured and four public
classes had no example.

## API review (item 1)

Kept: the eleven public names of 0.2.0 with their parameters and defaults, the fields of
the five records, and `AuthKeyError` as a `ValueError` with `reason` and `line`. Changed,
all in the CHANGELOG: `build_line` checks the types of the record's fields and raises
`TypeError` (0.2.0 raised `AttributeError`, or a misleading "does not read back" error for
a list of options); `values`, `has_flag` and both `fingerprint` methods raise `TypeError`
for a non-text argument (0.2.0 raised `AttributeError`, and quoted a whole unknown hash
name); `expiry-time` accepts second 61, found by the OpenSSH oracle. Internal:
`build_line` moved to its own module to keep files under 200 lines. Names such as the
`hash` parameter (it mirrors `ssh-keygen -E`) were kept.

## Ground truth (item 7)

- `scripts/fetch_upstream.py` fetched the 26 files of `tests/upstream/MANIFEST.json` on
  2026-10-19 (OpenSSH portable at 773771be, RFC 4253, 5656, 5903, 8332, 8709,
  draft-miller-ssh-cert-06); every size and sha256 matched. OpenSSH `master` was at
  26b1363 that day; of the files the library follows only `misc.c` changed since the
  pin, in `mkdir_path`, which authorized_keys reading does not use.
- OpenSSH itself (`tests/test_sshd_oracle.py`): `scripts/sshd-oracle/build.sh` built
  `harness.c` against `sshkey_read`, `sshkey_advance_past_options` and
  `sshauthopt_parse` of the pinned commit (Ubuntu 26.04 under WSL, gcc 15.2.0, OpenSSL
  3.5 headers). The harness reads lines as sshd's authorized_keys loop does and prints the
  key name, type, bits, both fingerprints, the comment and every recorded option. Three
  seeds of 4,000 generated lines (hostile options, every key type, damaged blobs and
  base64, odd comments), the 54 option fields of OpenSSH's own `authopt` tests and six
  certificates signed by `ssh-keygen` were compared: per seed about 1,720 lines accepted
  by both with identical fields, about 2,120 refused by both, and the two documented gaps
  (about 135 certificates with unverifiable signatures, about 30 ports given by service
  name). The comparison found one difference: sshd accepts `expiry-time` with second 61
  (`strptime` allows 0 to 61 in glibc and OpenBSD), fixed in e7a83bc.
- `ssh-keygen -l` (`tests/test_oracle.py`, OpenSSH 10.3p1 here) on fresh keys of every
  size, certificates, padded integers, spare base64 bits, odd comments and broken blobs.
- RFC 5903 curve constants and the OpenSSH limits and tables are compared with the fetched
  text in `tests/test_sources.py`; OpenSSH's `authopt` cases run in `tests/test_authopt.py`.
- README comparison: sshpubkeys 3.3.1 and asyncssh 2.24.1 installed from PyPI on
  2026-10-19 and run on the lines quoted in the README.

## Fuzz and hostile input (item 9)

`tests/test_fuzz.py`, three seeds each: 20,000 hostile strings per seed raise nothing but
`AuthKeyError` with messages under 300 characters; 6,000 damaged blobs per seed likewise;
random files read the same through `parse_file`, `check_file` and line by line; every
accepted line of the oracle corpus rebuilds to the same record or is refused only for a
CR or NUL `build_line` will not write; 3,000 `environment` options holding a marker never
show it in a message; eight input shapes timed at 20,000 and 80,000 units grow linearly;
random certificate principals survive decoding.

## Author mutation round (item 18)

32 mutants over every module, run as described in
[CERT-1.0-MUTANTS.md](https://github.com/JaviLianes8/authkeyline/blob/main/CERT-1.0-MUTANTS.md).
30 were killed at once. Two survived and showed missing contracts: an x coordinate equal
to the prime (OpenSSL refuses coordinates not below it) and the kinds of whitespace that
start a comment (sshd skips only spaces and tabs). `tests/test_contract_edges.py` pins
both, the OpenSSH oracle confirmed sshd's reading of each case, and both mutants were then
killed.

## Packaging, e2e and Pythons (items 8, 10, 13, 14)

At ba24013 on this PC, from a fresh clone, one process at a time:

- `python -m build` gave `authkeyline-1.0.0-py3-none-any.whl` (sha256 26c99c61...) and the
  sdist; a second build gave the same wheel hash. `twine check --strict` passed both.
- Wheel: the package modules, `py.typed`, `__main__.py`, LICENSE, the console entry
  point; no tests or scripts. Sdist: sources, tests, scripts (fetch and sshd oracle),
  README, GUIDE, CHANGELOG, CONTRIBUTING, LICENSE and the manifest of `tests/upstream`;
  none of the fetched third-party files, no report or round notes.
- Every interpreter here from `requires-python` up: a fresh venv with the wheel, the
  sdist's own suite run with its `src` folder removed, fetched sources, `ssh-keygen` and
  the sshd oracle present: CPython 3.10.19, 3.11.5, 3.12.12, 3.13.2, 3.14.2 and 3.14.2
  free-threaded, 350 passed and 1 skipped each (the wheel e2e test, which needs the
  source tree and ran separately). 3.8 and 3.9 are below `requires-python`.
- `AUTHKEYLINE_E2E=1 pytest tests/test_e2e_wheel.py`: builds both archives, checks their
  contents and metadata, installs the wheel in a fresh venv, runs a consumer program from
  an empty folder with `-I`, and drives `authkeyline` and `python -m authkeyline` by
  subprocess (listing, `--check` with exit 1, `--json -E md5` on a certificate): passed.
- A consumer script using every public name passed `mypy --strict` against the installed
  wheel and ran.

## Gates (item 15)

At 0373b42 on another machine from a fresh clone (CPython 3.14, fetched sources), each
command on its own: `ruff format --check .`, `ruff check .`, `mypy --strict src`,
`mypy --strict src tests` and `pytest` (363 passed, 6 skipped: the sshd oracle, not
built there, and the opt-in wheel test) all exit 0. On this PC from a fresh clone at
0373b42 with the sshd oracle and `AUTHKEYLINE_E2E=1`: 369 passed, nothing skipped.

## QA lenses (item 19)

Five fresh reviewers, one per lens, ran against `release/1.0.0` at 2f246bb. Lens a also
confirmed 18 doctests, every README and GUIDE example, the gates, a typed consumer, every
documented refusal and the "why" claims; lens b replayed sshd's own checks on about 76,000
seeded lines and found every field sshd keeps in agreement.

### Round 1 findings

| Lens | Id | Finding | Fix |
| --- | --- | --- | --- |
| a | A1 | Hand-built record: unknown key type quoted in full by `public_key()`, `fingerprint()` | `shown()` in the type check; `test_qa_records.py` |
| a, b | A2, B3 | Listing printed `no comment` where `ssh-keygen -l` shows the options field, and differed in other comment cases | Comment column worked out as `do_fingerprint` does (`_listing.py`); `test_qa_cli.py`, `test_oracle_listing.py` |
| a, c, d | A3, F3, F1 | Listing wrote control bytes and bytes that are not UTF-8 raw; `ssh-keygen` escapes them | Octal escapes as `mprintf` writes them; same tests; README and GUIDE reworded |
| a, c | A4, F5 | Wrong field types gave `AttributeError` or misleading errors | Every method checks the record like `build_line` and raises `TypeError`; `test_qa_records.py` |
| a | A5 | `PublicKey.blob` and `plain_blob` undocumented | README table, docstring, GUIDE |
| a | A6 | Certificate example command missed `-V` | Docstring names the `-V` used and pins the validity in a doctest |
| a | A7 | Public names reported private modules, so pickles named them | Names published as `authkeyline.*`; pickle round trip test |
| a | A8 | `-E` had no help; status 2 also means a usage error | Help text, epilog, README and GUIDE |
| a | A9 | Old CHANGELOG versions undated | 0.2.0 dated 2026-10-14, 0.1.0 2026-10-11 |
| b | B1 | glibc sshd skips blanks before an `expiry-time` field | Listed as a deliberate difference in README and GUIDE (the library follows OpenBSD) |
| b | B2 | A local `expiry-time` on the epoch in the server's zone is refused by that sshd | Listed as a deliberate difference in README and GUIDE (the zone is unknown) |
| c | F1 | Same as A1 | As A1 |
| c | F2 | `no-pty, environment="..."` leaked the value through "unsupported key type" | A key type holding `=` or `"` is not quoted; `test_qa_records.py` |
| c, d | F4, F2 | `| head` gave a traceback and status 120 | Broken pipe ends quietly with the status so far; subprocess test |
| c | F6 | `str` subclasses could steer `build_line`'s checks | Records copied to plain `str` before any check |
| d | F3 | The sdist `.c` check could never fail | Names read with `tarfile`, exact set asserted |
| d | F4 | `--json` wrote lone surrogates | Valid Unicode with U+FFFD, plus `line_base64` when a byte was replaced |
| e | F1 to F13 | 13 mutants survived (M15, M24, M53, M78, M08, M42, M50, M74, M73, M84, M87, M39, M71) | One contract each in `test_qa_contracts.py`, `test_qa_cli.py`, `test_qa_records.py` |

Every behaviour test was first run against 2f246bb and failed there (36 cases). The
lens e contracts pin behaviour that was already right, so each of the 13 mutants was
rebuilt on a copy of the fixed tree and its new contract run against it: all 13 killed.
The listing oracle passed against OpenSSH_10.3p1 (portable, escaping branch on) and
OpenSSH_for_Windows_9.5p2. No finding was disputed. Lens a's note on `requires-python`
(3.10 while the house template says 3.9) was left to lens d, which raised nothing: 3.9 is
past its end of life and every supported version from 3.10 up was run.

Fix commit: 882f4e0. Gates there, from a fresh clone on another machine (CPython 3.14,
fetched sources, `AUTHKEYLINE_E2E=1`), each on its own: `ruff format --check .`,
`ruff check .`, `mypy --strict src`, `mypy --strict src tests` and `pytest` (425 passed,
5 skipped: the sshd oracle, not built there) all exit 0. Next: each lens re-verifies.

### Round 2 findings

The same five lenses re-ran against 585a5b6. Every round 1 finding was confirmed fixed
(lens e: all 13 mutants killed). New findings:

| Lens | Id | Finding | Fix |
| --- | --- | --- | --- |
| a, b, c, d | A10, B4, N4, N1 | The listing takes "unassigned" from the running Python's Unicode database, so it varies across Pythons and differs from some `ssh-keygen` builds; the docs claimed only two differences | Docs: README and GUIDE name glibc `ssh-keygen` as the reference, say the Unicode tables follow the running Python, and list the Cygwin/MSYS2 build (U+2028, U+2029 raw; characters outside the BMP escaped). Contract: `test_unassigned_code_points_follow_the_running_unicode_database` |
| c | N3 | "key blob is not valid base64" quoted an `environment` option written where the blob goes | A blob field holding `"` or an `=` before the padding is described, not quoted (both base64 messages); `test_qa_round2.py` |
| c, d | N1, N2 | `2>&1 \| head` exited 0 with broken lines: the status was set after the report was written | Status set before the report; in-process and subprocess tests in `test_qa_cli_round2.py` |
| c | N2 | A stream closed before the start (`>&-`) gave a traceback | `_write` skips a missing stream; the status is kept; `test_qa_cli_round2.py` |
| e | G1 (N27) | Unreadable then broken file: status 2 not pinned | `test_an_unreadable_file_then_a_broken_one_exits_2` |
| e | G2, G4 (N30, N29) | Option-like key type with `=` only or `"` only not pinned | `test_an_option_like_key_type_is_never_quoted` |
| e | G3 (N06) | Tab as a listing field separator not pinned | `test_the_listing_splits_fields_at_tabs`, and tab-separated lines added to the `ssh-keygen` oracle |
| e | G5, G6 (N32, N33) | Both type names of a type mismatch not pinned to 40 characters | Two exact-message tests in `test_qa_round2.py` |
| e | G7 (N11) | U+0378 (unassigned) escaping not pinned | Exact octal escape asserted |
| e | G8 (N20) | A JSON file name that is not UTF-8 not pinned | `test_json_file_names_are_valid_unicode` |
| e | G9 (N34) | Plain `str` option values from `values()` not pinned | `test_option_values_come_back_as_plain_str` |
| e | G10 (N40) | `public_key` with a subclassed key type not pinned | `test_public_key_checks_a_plain_copy_of_the_key_type` |
| e | G11 (N42) | `__module__` of methods not pinned | `test_methods_of_public_classes_name_the_public_module` (an unbound method pickles without a private module) |

The behaviour tests for N3, N1/N2 and N2 failed on 585a5b6 (9 cases) and pass after the
fix. Each lens e mutant (G1 to G11) and the reverted N1 and N3 fixes were rebuilt on a copy
of the fixed tree and run against the new tests: all 13 killed. No finding was disputed.
Behaviour changes are in the CHANGELOG (blob messages, exit status and closed streams).

Fix commit: 552ab56. Gates there, from a fresh clone on another machine (CPython 3.14,
fetched sources, `AUTHKEYLINE_E2E=1`), each on its own: `ruff format --check .`,
`ruff check .`, `mypy --strict src`, `mypy --strict src tests` and `pytest` (452 passed,
5 skipped: the sshd oracle, not built there) all exit 0. The `ssh-keygen` listing oracle
also passed on this PC against OpenSSH_10.3p1 (MSYS2). Next: each lens re-verifies.

### Round 3 findings

The same five lenses re-ran against fa2b326. Every round 2 finding was confirmed fixed
(lens a: A10; lens b: B4; lens c: N1 to N4; lens d: N1, N2; lens e: G1 to G11 all killed).
Lens b replayed 25 escaping cases against three `ssh-keygen` builds and found 0
accept/refuse flips between 585a5b6 and fa2b326 on its 31,052-line corpus. New findings:

| Lens | Id | Finding | Fix |
| --- | --- | --- | --- |
| a, b, c, d | A11, B5, N5, N4 | Standard input closed before the start (`<&-`) gave an `AttributeError` traceback and status 1 | `_read("-")` raises `OSError(EBADF, "standard input is closed")`, so the file is reported as unreadable (`authkeyline: -: standard input is closed`, status 2) and the files before it are still listed. In-process and subprocess tests in `test_qa_round3.py` (the POSIX one closes fd 0 before exec) |
| d | N4 (second part) | Python 3.10: a usage error with standard error closed exited 1 | Help and usage go through the same writer as the rest of the output, which skips a missing stream; `test_a_usage_error_with_stderr_closed_exits_2`, run on 3.10 to 3.14 |
| c | N6 | A usage error or `--help` into a closed pipe exited 120 (and printed "Exception ignored on flushing sys.stdout") | `_Parser._print_message` writes and flushes under the same broken-pipe handling as the listing, so the final flush cannot fail; subprocess tests for `--bogus 2>&1`, `--bogus` and `--help` into a closed pipe (status 2, 2, 0, no traceback) |
| d | N3 | On Python 3.10 and 3.11 excess padding (`AAAAC3Nz=`, `AAAA=`, a valid blob plus `=`) gave "not canonical base64" where 3.12 and later say "not valid base64", so the suite failed there | `_whole_quanta` refuses padding that is too long or not at the end before `b64decode`, so every Python gives "not valid base64". An exhaustive check of every string up to 10 characters over `AQ/=!` showed the check plus each Python's `b64decode` (3.10, 3.11, 3.14) accepts exactly what 3.12 and later accept, so which lines are refused does not change. `test_misplaced_padding_gives_the_same_message_on_every_python` |
| e | H1 (P05) | `rstrip("=")` to `strip("=")` survived | `=s3cr3t` and `==s3cr3t` cases in `test_an_option_read_as_key_blob_does_not_leak_its_value` |
| e | H2 (P04), H3 (P11) | Dropping the C-space strip before `rstrip("=")`, or quoting the stripped text, survived | `AAB=\f` and `AAB=\v` cases with the exact reason from `parse_line` and from a hand-built record, and `test_a_hand_built_blob_keeps_its_trailing_blank_in_the_message` (`AAB= `) |
| e | H4 (P14) | Dropping the "it looks like an option" description survived | The leak test asserts the full reason |

The closed stdin and closed pipe tests failed on fa2b326 (9 cases) and pass after the fix;
the padding test fails on 3.10 and 3.11 with the pre-check removed (5 cases each) and
passes with it. The lens e mutants H1 to H4 were rebuilt on a copy of the fixed tree and
run against the new tests: all 4 killed. The regex form of the pre-check was replaced by
a linear one after timing (40 million characters: 0.08 s to refuse, 0.19 s to decode). No
finding was disputed. Behaviour changes are in the CHANGELOG (closed stdin, help and
usage into a closed pipe, padding messages) and the GUIDE.

Fix commit: db76465. On Elena's PC from a bundle of that commit, CPython 3.10.22,
3.11.17, 3.12.15, 3.13.2 and 3.14.2: `pytest` 464 passed, 18 skipped on each (the sshd
oracle, the opt-in wheel test and the tests of fetched sources, absent there); on 3.14
`ruff format --check .`, `ruff check .`, `mypy --strict src` and `mypy --strict src tests`
each exit 0. Next: each lens re-verifies.

### Round 4 findings

The same five lenses re-ran against 6857da6. Every round 3 finding was confirmed fixed
(lens a: A10 docs and A11; lens b: B5, with ssh-keygen and the library agreeing on 119 of
124 padding variants, the other 5 being `\r=` where the library follows sshd as the GUIDE
says, and identical `--check` messages on every Python from 3.10 to 3.14; lens d: N3, N4,
wheel and sdist on five Pythons, 464 passed). New findings:

| Lens | Id | Finding | Fix |
| --- | --- | --- | --- |
| a, b, c | A12, B6, N7 | With standard error closed, a usage error wrote its usage line to standard output: argparse's `error()` calls `print_usage(sys.stderr)`, which falls back to stdout when stderr is `None` | `_Parser.error` writes the usage to stderr only, through the writer that skips a closed stream; `test_a_usage_error_with_stderr_closed_leaves_stdout_empty` and a subprocess test (stdout empty, status 2) |
| c, d, e | N8, F1, F2, F8 | An argument or file name holding a lone surrogate outside U+DC80..U+DCFF (a Windows name can) ended in a `UnicodeEncodeError` traceback with status 1: usage errors, the unreadable and broken file reports, and `--json` | `_streams.encode` writes such a surrogate as `\udXXX` and still turns an escaped byte back into that byte; `--json` uses it too. A name no file can have (a NUL, or such a surrogate on POSIX, where `open` raises `ValueError`) is reported as `invalid file name`, status 2. In-process tests on every platform, broken-file, `--check`, `--json` and subprocess tests on Windows |
| e | Q17 | Usage errors written to stdout survived | `test_a_usage_error_goes_to_stderr_only_and_ends_with_a_newline` asserts the exact stderr bytes and an empty stdout |
| e | Q23 | `raise` to `pass` in the closed-reader handler survived (ENOSPC swallowed, status 0) | `test_an_output_error_that_is_not_a_closed_reader_is_raised` (ENOSPC, EIO) |
| e | Q19 | `message.rstrip()` in `_print_message` survived | Exact usage error bytes, and the help ends with one newline |
| e | Q35 | `surrogateescape` to `replace` survived | Missing and broken files named with byte 0xFF: stderr holds that exact byte |
| e | Q31 | Dropping the flush of a text-only stream survived | `test_a_text_only_stream_is_flushed_under_the_reader_check` (a text-only stream whose flush finds the reader gone: flushed once, status 0) |
| e | Q36 | U+FFFD on a text-only stream survived | `test_a_text_only_stream_gets_the_name_as_it_came` |
| e | Q32 | Dropping the flush before the raw write survived | `test_text_already_waiting_on_stdout_comes_first` |

The stream helpers moved from `_cli.py` to a private `_streams.py` to keep both files
under 200 lines. The behaviour tests for A12 and N8 failed on 6857da6 (10 cases) and pass
after the fix. The lens e mutants Q17, Q19, Q23, Q31, Q32, Q35 and Q36, and the removed
`error` override, were rebuilt on a copy of the fixed tree and run against the new tests
in `test_qa_round4.py` and `test_qa_round4_writer.py`: all 8 killed. No finding was
disputed. Behaviour changes are in the CHANGELOG and the GUIDE.

Fix commit: 2488944. On Elena's PC from a bundle of that commit, CPython 3.14:
`ruff format --check .`, `ruff check .`, `mypy --strict src`, `mypy --strict src tests`
and `pytest` (483 passed, 18 skipped: the sshd oracle, the opt-in wheel test and the
tests of fetched sources, absent there) each exit 0. Next: each lens re-verifies.

### Round 5 findings

The lenses re-ran against 08c1915. Lens a confirmed A10, A11 and A12 fixed. New findings:

| Lens | Id | Finding | Fix |
| --- | --- | --- | --- |
| a | A13 | On Windows a name or argument holding U+DC80..U+DCFF was written as the raw byte 0x80..0xFF (U+FFFD in `--json`), so `ok\udc80` and `ok\udc81` got the same JSON `file`, against the GUIDE and CHANGELOG | New `_streams.native`: on Windows every lone surrogate of a file name or argument (the names in reports and `--json`, and argparse messages) is escaped as `\udXXX`; on POSIX the name is left for `encode`, so a name byte still comes back as that byte. Windows contracts for broken files, `--json` and a real process (`bad\udc80`, `nofile\udc80`, two files that stay distinct); GUIDE and CHANGELOG say which surrogates are bytes where |
| e | E1-N01 | `_UNPAIRED` without the U+DD00..U+DFFF range survived | `encode` boundary table (U+D800, U+DBFF, U+DC00, U+DC7F, U+DD00, U+DFFF), plus missing-file and usage-error tables through `main`, and broken-file and `--json` tables on Windows |
| e | E2-N05 | Upper bound U+DFFF moved to U+DFFE survived | The same table (U+DFFF) |
| e | E3-N02 | Gap bound U+DC7F moved to U+DC80 survived | `encode` and a POSIX-mode `main` echo byte 0x80 as well as 0xFF; `--json` `line_base64` keeps 0x80 and 0xFF |
| e | E4-N29 | `sub(..., count=1)` survived | Two unpaired surrogates in one string, one name and one argument |

Run on a copy of 08c1915 given an identity `native`, 15 round 5 cases failed: the 5
end-to-end A13 cases (broken file and `--json` named with U+DC80 and U+DCFF, and the real
process) and 10 unit cases of the new helper. All pass after the fix. The three round 4 tests and the round 2 `--json` test
that pinned the byte echo of a name now run in POSIX mode (`native(..., windows=False)`),
since that rule is POSIX only. The four lens e mutants were rebuilt on copies of the fixed
tree and run against `test_qa_round5.py`: all 4 killed. No finding was disputed.
Behaviour changes are in the CHANGELOG and the GUIDE.

Fix commit: 624cbd5. On Elena's PC from a bundle of that commit, CPython 3.14:
`ruff format --check .`, `ruff check .`, `mypy --strict src`, `mypy --strict src tests`
and `pytest` (542 passed, 18 skipped: the sshd oracle, the opt-in wheel test and the
tests of fetched sources, absent there) each exit 0. Next: each lens re-verifies.

## Independent review (item 16)

Pending.
