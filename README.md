# authkeyline

[![Lianes8 Certified](https://lianes8studio.com/certified/lianes8-certified-badge.svg)](https://lianes8studio.com/certified)

Parse, check and safely build OpenSSH `authorized_keys` lines into typed records,
the way sshd reads them. Zero dependencies.

## Install

```
pip install authkeyline
```

## Usage

The examples use a made-up Ed25519 key (its 32 bytes are 0 to 31); every block runs as
part of the test suite and prints what its comments say.

```python
from authkeyline import parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
key = parse_line(
    f'restrict,command="/usr/bin/backup --all",from="10.0.0.1,10.0.0.2" ssh-ed25519 {BLOB} alice@host'
)

print(key.key_type, key.comment)
print(key.values("from"))
print(key.has_flag("RESTRICT"))
print(key.fingerprint())
print(key.fingerprint("md5"))
# ssh-ed25519 alice@host
# ('10.0.0.1,10.0.0.2',)
# True
# SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA
# MD5:0f:a2:0a:d7:38:3e:65:45:08:6b:63:84:1c:ff:dc:ba
```

Option values come back exactly as sshd sees them. Only `\"` is an escape inside the
quotes; every other backslash is kept:

```python
from authkeyline import parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
key = parse_line(f'command="echo \\"hi\\" c:\\\\temp",environment="LANG=C" ssh-ed25519 {BLOB}')
print(key.options[0].value)
print(key.environment())
# echo "hi" c:\\temp
# {'LANG': 'C'}
```

`parse_line` refuses what sshd refuses, with the reason: unknown options, unquoted
values, a repeated `command`, a malformed `permitopen`, `environment` or `expiry-time`,
an unknown key type, a blob that is not base64, whose embedded type differs from the line,
whose Ed25519 key is not 32 bytes, whose ECDSA point is off the curve, or whose RSA modulus
is under 1024 bits:

```python
from authkeyline import AuthKeyError, parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
for line in [f"command=ls ssh-ed25519 {BLOB}", f"ssh-rsa {BLOB}", "no-pty ssh-ed25519 AAAA"]:
    try:
        parse_line(line)
    except AuthKeyError as error:
        print(error)
# value of 'command' must be in double quotes
# line says 'ssh-rsa' but the key blob holds 'ssh-ed25519'
# key blob is truncated
```

### Building lines safely

`build_line` writes a record back and refuses anything that would not read back as the
same record: unknown option names, values with line breaks or a trailing backslash, a
comment that breaks the line. Values cannot smuggle in other options or keys.

```python
from authkeyline import AuthKeyError, KeyOption, build_line, parse_line
import dataclasses

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
public = parse_line(f"ssh-ed25519 {BLOB} deploy")
restricted = dataclasses.replace(
    public, options=(KeyOption("restrict"), KeyOption("command", 'rsync --server "a b"'))
)
print(build_line(restricted))
try:
    build_line(dataclasses.replace(public, comment="x\nssh-ed25519 AAAA intruder"))
except AuthKeyError as error:
    print(error)
# restrict,command="rsync --server \"a b\"" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f deploy
# comment holds a NUL or a line break
```

### Whole files

```python
from authkeyline import check_file, parse_file

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
text = f"# team keys\nssh-ed25519 {BLOB} one\n\nbogus ssh-ed25519 {BLOB} two\n"
print(check_file(text))
print(len(parse_file(text.replace("bogus ", ""))))
# [LineProblem(line=4, message="unknown option 'bogus'")]
# 2
```

`parse_file` raises on the first bad line with `error.line` set; `check_file` lists them
all. Blank lines and `#` comments are skipped, as sshd does. To read a real file, pass
its text: `parse_file(Path.home().joinpath(".ssh/authorized_keys").read_text())`.

### Command line

```
authkeyline ~/.ssh/authorized_keys          # one line per key, like ssh-keygen -l
authkeyline -E md5 authorized_keys           # MD5 fingerprints
authkeyline --json authorized_keys           # options, sizes, certificate details
authkeyline --check authorized_keys          # only report broken lines
```

Broken lines go to standard error as `FILE:LINE: reason` and the exit status is 1; a file
that cannot be read, or a wrong argument, gives status 2. The listing prints each key as
portable OpenSSH's `ssh-keygen -l` does in a UTF-8 locale: the options field stands in for
a missing comment, a comment starting with `#` is not shown, the comment stops at a CR and
keeps its trailing blanks, and control characters and bytes that are not UTF-8 are written
as `\ooo` octal escapes, so a hostile comment cannot send escape sequences to a terminal.
The test suite compares this with `ssh-keygen` 10.3p1, and it was checked against 10.2p1
on Linux. Two differences remain: the Windows port of OpenSSH (9.5p2) writes control bytes
as they are, and a line sshd uses but `ssh-keygen` cannot read (two blanks after the
options) is still listed.

## API

| Name | What it does |
| --- | --- |
| `parse_line(line)` | One line to an `AuthorizedKey`, checked like sshd; raises `AuthKeyError` |
| `parse_file(text)` | Every key of a file; the first bad line raises with `.line` set |
| `check_file(text)` | Every broken line as a `LineProblem(line, message)` |
| `build_line(key)` | A record back to a line that reads back the same, or `AuthKeyError` |
| `AuthorizedKey` | `options`, `key_type`, `key_base64`, `comment`; `public_key()`, `fingerprint()`, `values()`, `has_flag()`, `environment()`, `key_bytes()` |
| `KeyOption` | `name` as written and `value` (`None` for a flag) |
| `PublicKey` | `key_type`, `short_type`, `bits`, `blob` (the decoded blob), `plain_blob` (the bare key a fingerprint hashes), `application`, `certificate`, `fingerprint()` |
| `Certificate` | `cert_type`, `serial`, `key_id`, `principals`, validity, critical options, extensions, `ca_key`, `signature_type` |
| `LineProblem` | `line` number and `message` |
| `KEY_TYPES` | The key type names sshd accepts, certificates included |
| `AuthKeyError` | A `ValueError` with `reason` and `line`; arguments and record fields of the wrong type raise `TypeError` |

## Rules it follows

Lines are read the way sshd's own authorized_keys loop reads them: the option grammar and
rules of OpenSSH's `sshauthopt_parse`, the key type table of `sshkey.c` (certificates and
the `rsa-sha2-256` and `rsa-sha2-512` aliases included), the blob layouts of RFC 4253,
RFC 5656 and RFC 8709 and the certificate format of draft-miller-ssh-cert. The test suite
compares the library with OpenSSH's own C code, built from a pinned commit, on 12,000
seeded lines, and with `ssh-keygen -l` on fresh keys. Where it differs from sshd, on
purpose:

- Certificate signatures are not verified (that needs a crypto library), so a certificate
  with a forged signature parses while sshd skips it. The signature type is checked
  against the CA key. CA keys marked `cert-authority` are plain keys and fully checked.
- Ports given by service name in `permitopen` and `permitlisten` (`host:ssh`) are refused,
  since sshd looks them up in the local services database, which differs per system.
- `from=` patterns are kept as text, not matched against a client.
- `expiry-time` must be digits only. sshd built on glibc also takes blanks before a field
  (`"2025 101"`), because glibc's `strptime` skips them; OpenBSD's does not, and the
  library follows the stricter reading.
- An `expiry-time` without `Z` or `UTC` is local time on the server. sshd refuses one that
  falls on the epoch in its own time zone; the library cannot know that zone, so it only
  refuses the UTC epoch.
- Trailing spaces, tabs and CR are dropped from the comment, so files with CRLF line ends
  read cleanly; sshd keeps them, and they change nothing.
- `build_line` keeps comments and values to one line of text without NUL or CR.

The [GUIDE](https://github.com/JaviLianes8/authkeyline/blob/main/GUIDE.md) has every rule
and error in detail, and the
[CHANGELOG](https://github.com/JaviLianes8/authkeyline/blob/main/CHANGELOG.md) what
changed in each release.

## Why

An `authorized_keys` line packs an options field, a key type, a base64 blob and a comment
into one string, and the options field has its own quoting rules. The parsers on PyPI read
it differently from sshd (checked with sshpubkeys 3.3.1 and asyncssh 2.24.1):
sshpubkeys turns `command="echo \"hi\""` into `echo \hi\` and accepts an unquoted
`command=ls`, two `command` options, `permitopen="host"` and `expiry-time="soon"`;
asyncssh reads `command="c:\x"` as `c:x`, accepts unknown options and keeps the last of
two `command` options; both refuse lines whose key type is `rsa-sha2-256`. A line sshd
skips can look fine, and a forced command can read differently from the one sshd runs.
`authkeyline` is a small, typed, zero-dependency library that reads a line as sshd does,
says why sshd would skip it, and writes lines that cannot be steered into extra options
or keys.

## Development

`python scripts/fetch_upstream.py` downloads the OpenSSH sources, RFCs and draft listed in
`tests/upstream/MANIFEST.json` (they are not part of the repository; their tests skip
without them). `sh scripts/sshd-oracle/build.sh <folder>` builds OpenSSH's own reader;
point `AUTHKEYLINE_SSHD_HARNESS` at it to compare. `scripts/check.ps1` runs format, lint,
types and tests. Set `AUTHKEYLINE_E2E=1` to also build the wheel and test the installed
package and its command.

## License

MIT. See [LICENSE](https://github.com/JaviLianes8/authkeyline/blob/main/LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
