# authkeyline guide

How every public name behaves, in detail. Each Python block below runs as a test: the
comment lines at its end hold what it prints, in order. The examples use a made-up Ed25519
key whose 32 bytes are 0 to 31.

## How a line is read

`parse_line` follows sshd's authorized_keys loop step by step:

1. A final `\n` is allowed; any other line break is an error. The line ends at a NUL, as
   sshd reads C strings.
2. Leading spaces and tabs are skipped. A line that is then empty (or only C whitespace)
   or starts with `#` is not an entry: `parse_line` raises, `parse_file` and `check_file`
   skip it.
3. If the first field (up to a space or tab) is a key type name, there is no options
   field. Otherwise the options field is read first; it ends at a space or tab outside
   double quotes.
4. The key type must be one of `KEY_TYPES`, then comes the base64 blob, then the comment:
   the rest of the line after spaces and tabs, without trailing spaces, tabs or CR.
5. The blob is decoded and checked as `sshkey_fromb` does: canonical base64 (padding
   required, no set spare bits, C whitespace inside ignored), the type inside the blob
   agrees with the type on the line (`rsa-sha2-256` and `rsa-sha2-512` are RSA, a
   `webauthn-sk-ecdsa` line reads an `sk-ecdsa` blob and so on), every field is present
   and nothing trails.

```python
from authkeyline import AuthKeyError, parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
key = parse_line(f"\tssh-ed25519 {BLOB}  laptop key \r\n")
print(repr(key.comment), key.options)
for line in ["  # comment", f"ssh-ed25519 {BLOB}\nssh-ed25519 {BLOB}", "ssh-ed25519"]:
    try:
        parse_line(line)
    except AuthKeyError as error:
        print(error)
# 'laptop key' ()
# not an authorized_keys entry
# text holds more than one line
# missing key blob
```

## Options

Names are compared without case and kept as written in `KeyOption.name`.

- Flags: `restrict` and `cert-authority`, and `port-forwarding`, `agent-forwarding`,
  `x11-forwarding`, `touch-required`, `verify-required`, `pty`, `user-rc` with or
  without a `no-` prefix. A flag cannot take a value.
- Valued options take a double-quoted value: `command`, `principals`, `from`,
  `environment`, `permitopen`, `permitlisten`, `tunnel` and `expiry-time`. Inside the
  quotes only `\"` is an escape; every other backslash is kept, as sshd keeps it.
- `command`, `principals` and `from` may appear once each.
- `environment="NAME=value"`: the name is letters, digits and `_`. The first value of a
  name wins, as in sshd.
- `permitopen="host:port"` and `permitlisten="[host:]port"`: the host may be an IPv6
  address in brackets, `/` may separate host and port, the port is 1 to 65535 or `*`.
- `tunnel="N"` is a device number up to 2,147,483,645 or `any`.
- `expiry-time` is `YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`, local time or UTC with
  a final `Z` or `UTC`; the fields must be in range (seconds up to 61, as `strptime`
  allows), and the UTC epoch itself is refused, as sshd refuses a zero expiry.
- An empty element between commas is skipped; a comma followed by a space ends the field.
- sshd's count limits apply, counted as sshd counts them: `SSH_AUTHOPT_ENV_MAX` (1,024)
  environment names and `SSH_AUTHOPT_PERMIT_MAX` (4,096) `permitopen` and `permitlisten`
  targets each, checked before each new one is added.

```python
from authkeyline import parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
key = parse_line(
    'No-PTY,permitopen="[::1]:5432",permitopen="db/*",environment="A=1",environment="A=2",'
    f'command="c:\\temp\\run \\"x\\"" ssh-ed25519 {BLOB}'
)
print(key.has_flag("no-pty"), key.values("PermitOpen"))
print(key.environment(), key.values("command")[0])
# True ('[::1]:5432', 'db/*')
# {'A': '1'} c:\temp\run "x"
```

## Keys and certificates

`AuthorizedKey.public_key()` returns a `PublicKey`: the type inside the blob, the label
and size `ssh-keygen -l` prints, the security key application of `sk-` keys and, for a
certificate, a `Certificate`. RSA moduli must have at least 1,024 bits and integers at
most 16,384; Ed25519 keys are 32 bytes; ECDSA points must be uncompressed points on the
named curve. A certificate's signature type must fit its CA key, but the signature itself
is not verified, which is the one check sshd makes that the library does not.

Fingerprints are computed over the bare key, as `ssh-keygen -l` does, so a certificate
has the fingerprint of the key it certifies.

```python
from authkeyline import parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
public = parse_line(f"ssh-ed25519 {BLOB}").public_key()
print(public.short_type, public.bits, public.fingerprint())
# ED25519 256 SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA
```

## Building lines

`build_line` writes options, key type, blob and comment separated by single spaces and
then reads the line back: if the result is not the same record it refuses. It also
refuses option names that are not flags or valued options, values or comments holding
NUL, CR or LF, and values ending in a backslash (sshd would read the closing quote as
escaped). Quotes in values are escaped. Fields of the wrong type raise `TypeError`.

```python
import dataclasses

from authkeyline import AuthKeyError, KeyOption, build_line, parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
key = parse_line(f"ssh-ed25519 {BLOB} ci")
for options in [(KeyOption("command", "a\\"),), (KeyOption('no-pty,command="x"'),)]:
    try:
        build_line(dataclasses.replace(key, options=options))
    except AuthKeyError as error:
        print(error)
try:
    build_line(dataclasses.replace(key, comment=" padded"))
except AuthKeyError as error:
    print(error)
# value of 'command' ends with a backslash, which sshd cannot read
# 'no-pty,command="x"' is not a flag option
# the record does not read back the same; check the fields' spacing
```

## Errors

Every problem with the text is an `AuthKeyError`, a `ValueError`. `reason` is the message
and `line` the 1-based line number when it comes from `parse_file` (the message then
starts with `line N: `); `check_file` returns the same reasons as `LineProblem` items.
Messages quote at most 40 characters of any value taken from the input, with the full
length when they cut it, and never quote the value of an `environment` option, which may
hold a secret. Arguments of the wrong type raise `TypeError`.

```python
from authkeyline import AuthKeyError, parse_file

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
text = f'ssh-ed25519 {BLOB}\nenvironment="TOKEN" ssh-ed25519 {BLOB}\n'
try:
    parse_file(text)
except AuthKeyError as error:
    print(error.line, error.reason)
# 2 environment value is not NAME=value
```

## Command line

`authkeyline [FILE ...]` (or `python -m authkeyline`) reads the files, or standard input
for `-` or no file. Without options it prints `bits fingerprint comment (TYPE)` for every
key, exactly as `ssh-keygen -l -f FILE` does; `-E md5` switches the hash, `--json` prints
the options, sizes and certificate details, `--check` prints nothing but the broken lines.
Broken lines go to standard error as `FILE:LINE: reason`. The exit status is 0 when every
line is fine, 1 when a line is broken and 2 when a file cannot be read. Bytes that are not
UTF-8 are written back as they were read.

## Stability

From 1.0.0 the names in `__all__`, their parameters, the fields of the records and the
error types follow semantic versioning. What sshd accepts can change with OpenSSH
releases; when it does, the library follows sshd in a minor release and the CHANGELOG
says so. Error messages are for people and may be reworded.
