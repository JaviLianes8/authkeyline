# authkeyline

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

Broken lines go to standard error as `FILE:LINE: reason` and the exit status is 1. The
listing matches `ssh-keygen -l` byte for byte (the test suite compares them).

## API

| Name | What it does |
| --- | --- |
| `parse_line(line)` | One line to an `AuthorizedKey`, checked like sshd; raises `AuthKeyError` |
| `parse_file(text)` | Every key of a file; the first bad line raises with `.line` set |
| `check_file(text)` | Every broken line as a `LineProblem(line, message)` |
| `build_line(key)` | A record back to a line that reads back the same, or `AuthKeyError` |
| `AuthorizedKey` | `options`, `key_type`, `key_base64`, `comment`; `public_key()`, `fingerprint()`, `values()`, `has_flag()`, `environment()`, `key_bytes()` |
| `KeyOption` | `name` as written and `value` (`None` for a flag) |
| `PublicKey` | `key_type`, `short_type`, `bits`, `application`, `certificate`, `fingerprint()` |
| `Certificate` | `cert_type`, `serial`, `key_id`, `principals`, validity, critical options, extensions, `ca_key`, `signature_type` |
| `LineProblem` | `line` number and `message` |
| `KEY_TYPES` | The key type names sshd accepts, certificates included |
| `AuthKeyError` | A `ValueError` with `reason` and `line` |

## What it follows

- The options grammar and rules of OpenSSH's `sshauthopt_parse` and the option list of
  sshd(8): case-insensitive names, quoted values, `no-` forms, single `command`,
  `principals` and `from`, `permitopen` and `permitlisten` targets, `tunnel`,
  `expiry-time`, `environment` (first value of a name wins).
- The key type table of OpenSSH (`ssh-ed25519`, `sk-ssh-ed25519@openssh.com`,
  `ecdsa-sha2-nistp256/384/521`, `sk-ecdsa-sha2-nistp256@openssh.com`, `ssh-rsa`,
  `ssh-mldsa44-ed25519`, their certificates, and the `rsa-sha2-256/512` names that sshd
  reads as RSA keys), the blob layouts of RFC 4253, RFC 5656 and RFC 8709, and the
  certificate format of draft-miller-ssh-cert.
- Fingerprints are computed over the bare key, as `ssh-keygen -l` does, so a certificate
  has the fingerprint of its key.

Not done: certificate signatures are not verified and `from=` patterns are not matched
against a client, as both need a crypto library or a connection. Port names such as
`host:ssh` in `permitopen` are refused, since sshd resolves them per system.

## Why

An `authorized_keys` line packs an options field, a key type, a base64 blob and a comment
into one string, and the options field has its own grammar. Splitting on whitespace or
commas gets it wrong, and a builder that quotes values naively lets a value add options or
whole keys. This library reads a line exactly as sshd does, says why sshd would skip it,
and writes lines that cannot be steered.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
