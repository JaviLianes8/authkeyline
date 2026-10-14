# authkeyline improvement round

Progress:
- [x] Brainstorm ranked improvements (this file)
- [x] Pin the ground truth: sshd(8), OpenSSH option and key parsers, RFC 4253, RFC 5656, RFC 5903, RFC 8709, RFC 8332, draft-miller-ssh-cert-06
- [x] Option grammar and rules as sshd applies them (dequoting, flags, valued options)
- [x] Key blob decoding: embedded type, per-type fields, curve points, RSA size, certificates
- [x] Fingerprints (SHA256, MD5) and bits as ssh-keygen prints them
- [x] Safe builder that cannot inject options, lines or keys
- [x] File checking with line numbers, command line
- [x] Contracts: pinned sources, upstream authopt cases, ssh-keygen oracle, README examples, installed wheel
- [x] Docs and packaging
- [x] Gates: ruff format, ruff check, mypy --strict, pytest
- [ ] Mutation run: removing guarded logic makes the suite fail
- [x] Independent review findings fixed with regression tests
- [ ] Pull request opened, guard clean

## Starting point

`0.1.0` gives `parse_line`, `parse_file`, `build_line` and two frozen dataclasses. Probed
against the sources below:

- `command="c:\\x"` parses to `c:\x`. sshd only treats a backslash followed by a double
  quote as an escape; every other backslash is kept, so sshd runs `c:\\x`. The builder
  doubles backslashes, so a parse and rebuild changes the forced command.
- The builder can be steered into writing other options, lines and keys:
  `KeyOption('no-pty,command="evil"')` writes a second option, a comment holding a newline
  writes a second key line, and a value ending in a backslash (`a\`) becomes `"a\\"`,
  whose closing quote sshd reads as escaped, so the rest of the line is swallowed into the
  value.
- The key type is guessed by prefix (`ssh-`, `ecdsa-`, `sk-`): `rsa-sha2-256 AAAA` is read
  as an options field, `ssh-foo` is a key type, and an option field such as `ssh-x` is
  taken for a key.
- The blob is only matched against a base64 pattern. `AAAA` is accepted, a blob whose
  length is not a multiple of four passes and fails later in `key_bytes()`, and the type
  inside the blob is never compared with the type in front of it.
- Options are not checked at all: unknown names, `command=oops` without quotes, a second
  `command`, a malformed `environment`, `permitopen="host"` without a port and
  `expiry-time="soon"` all parse, while sshd ignores every one of those lines.
- `parse_file` errors do not say which line failed; there is no way to lint a whole file.
- No fingerprints, no key size, no view of certificates.
- README: the example blob is not a key, `open("~/.ssh/authorized_keys")` does not expand
  the home folder.

## Sources (fetched 2026-10-14)

OpenSSH portable at commit `773771be4ae241380e5f2b65059c441f7eef2da7` (2026-10-11), from
`https://raw.githubusercontent.com/openssh/openssh-portable/<commit>/<file>`:

- `sshd.8`, section AUTHORIZED_KEYS FILE FORMAT: the fields, the supported key types, the
  option list and its example file.
- `auth-options.c` (`sshauthopt_parse`, `handle_permit`) and `misc.c` (`opt_flag`,
  `opt_match`, `opt_dequote`, `hpdelim2`, `a2port`, `a2tun`, `parse_absolute_time`,
  `valid_env_name`): the actual grammar. Option names are case-insensitive; a value must be
  quoted; only `\"` is an escape; `command`, `principals` and `from` may appear once;
  `environment` keeps the first value of a name; `no-` negates only the forwarding, pty,
  user-rc, touch-required and verify-required flags; a trailing comma is an error.
- `authfile.c` (`sshkey_advance_past_options`) and `auth2-pubkeyfile.c`: how a line is
  split into options and key, and which lines are comments.
- `sshkey.c`, `sshkey.h`, `crypto_api.h`, `ssh-ed25519.c`, `ssh-ed25519-sk.c`,
  `ssh-ecdsa.c`, `ssh-ecdsa-sk.c`, `ssh-rsa.c`, `ssh-mldsa-eddsa.c`,
  `sshbuf-getput-basic.c`: the key type table (names, short names, certificate variants,
  the RSA signature names that map to RSA keys), the blob layouts, the 1024 bit RSA
  floor, the mpint rules, the certificate body and its limits.
- `regress/unittests/authopt/tests.c`: OpenSSH's own accept and reject cases for the
  options field.
- `PROTOCOL.u2f`: the security key public key layout (key fields plus application).

Specifications:

- RFC 4253, https://www.rfc-editor.org/rfc/rfc4253.txt, section 6.6 (public key blob:
  string type, then type specific fields) and RFC 4251 data types as used there.
- RFC 5656, https://www.rfc-editor.org/rfc/rfc5656.txt, section 3.1 (ECDSA blob: type,
  curve identifier, point).
- RFC 5903, https://www.rfc-editor.org/rfc/rfc5903.txt, section 3: the P-256, P-384 and
  P-521 prime and curve coefficient used for the point check.
- RFC 8709, https://www.rfc-editor.org/rfc/rfc8709.txt, section 4 (Ed25519 blob).
- RFC 8332, https://www.rfc-editor.org/rfc/rfc8332.txt (rsa-sha2-256 and rsa-sha2-512).
- draft-miller-ssh-cert-06, https://www.ietf.org/archive/id/draft-miller-ssh-cert-06.txt:
  the certificate format that replaced OpenSSH's PROTOCOL.certkeys.

None of these files is committed. `tests/upstream/MANIFEST.json` records URL, revision,
size, sha256 and licence; `scripts/fetch_upstream.py` fetches and checks them into the
ignored `tests/upstream/` folder, and their tests skip while they are absent.

Test oracle: `ssh-keygen -l` (OpenSSH 10.3p1 on this machine) over freshly generated
throwaway keys and certificates. It runs only when `ssh-keygen` is on the PATH.

## Ranked improvements

1. **Options as sshd reads them.** Dequote with the `\"` rule only; names matched
   case-insensitively; flags take no value, valued options must be quoted and followed by
   a comma or the end; unknown names, trailing commas and duplicated `command`,
   `principals` or `from` are errors; `environment` needs `NAME=value` with an
   alphanumeric or underscore name; `permitopen` needs `host:port`, `permitlisten`
   `[host:]port` (port 1 to 65535 or `*`, IPv6 in brackets); `tunnel` a number or `any`;
   `expiry-time` `YYYYMMDD[Z]` or `YYYYMMDDHHMM[SS][Z]`. Each error names the option.
2. **Key blob decoding.** Known type names only (the sshd table, certificates included);
   the type inside the blob must agree with the line; Ed25519 keys are 32 bytes,
   ML-DSA-44 + Ed25519 keys 1344, ECDSA points are uncompressed, of the curve's size and on
   the curve, security keys carry an application string, RSA moduli are positive and at
   least 1024 bits, no trailing bytes. Certificates: nonce, key fields, serial, user or
   host type, key id, principals, validity, critical options, extensions, a plain CA key.
3. **Fingerprints.** `SHA256:` unpadded base64 and `MD5:` colon hex of the plain key blob
   (a certificate is fingerprinted by its key, like ssh-keygen), the key size and short
   type name, matching `ssh-keygen -l` byte for byte.
4. **Safe builder.** `build_line` checks every part: known option names, values that
   sshd can read back (no NUL, CR, LF, no trailing backslash), a key type and blob that
   decode, a comment without line breaks. The output always parses back to the same record.
5. **Typed API.** `PublicKey` and `Certificate` records from `AuthorizedKey.public_key()`,
   option lookups (`values`, `has_flag`), `AuthKeyError` carrying the line number.
6. **File checking and command line.** `check_file` returns every problem with its line
   number instead of stopping at the first; `authkeyline FILE` prints one line per key like
   `ssh-keygen -l` (with `-E md5`), `--json`, and exits 1 on broken lines. It fits:
   auditing an authorized_keys file is a shell task.
7. **Contracts.** Option list and key types read from the pinned sources, OpenSSH's authopt
   cases run through the parser, ssh-keygen as oracle for fingerprints, sizes and
   rejections, README examples run, the installed wheel and its console script are driven
   from an empty folder.
8. **Docs and packaging.** README with executed examples and an API table, CHANGELOG,
   keywords and classifiers, an sdist without planning notes or fetched files.

## Out of scope

- Verifying certificate signatures and matching `from=` patterns against a client: both
  need a server context or a crypto library; this stays a zero-dependency codec. sshd
  also refuses a certificate whose signature does not verify.
- Port names in `permitopen` and `permitlisten` (`host:ssh`): sshd resolves them with the
  local services database, which differs per system; only numbers and `*` are accepted.
- `ssh-dss`: removed from current OpenSSH and absent from the sshd(8) list.

## Independent review

Fixed, each with a test in `tests/test_review_fixes.py` and, where ssh-keygen can say
it, a two-way oracle case in `tests/test_oracle.py`:

- Base64 whose spare bits before the padding were set was accepted; `b64_pton` refuses
  it. The blob must now be canonical, and C whitespace inside it is skipped as
  `b64_pton` does.
- CR and NUL were refused anywhere in a line, while sshd ignores the comment and works
  on C strings. A NUL now ends the line and a CR may sit in the comment; `build_line`
  still writes neither.
- `tunnel` and port numbers did not take the sign and leading blanks `strtonum`
  accepts, and an `expiry-time` at the UTC epoch, which sshd refuses, was accepted.
- A certificate's signature type was not compared with its CA key. It is now; the
  signature itself is still not verified, which the docs and a test now state plainly
  instead of claiming full sshd parity.
- The command line crashed on a missing file or a directory (now status 2 with a
  message) and on comments that are not UTF-8 or not printable on the console (files and
  stdin are read as bytes and the comment is written back unchanged). The shown comment
  stops at a CR, as in `ssh-keygen -l`.
- The local gate type-checks the tests again (`mypy --strict src tests`).
