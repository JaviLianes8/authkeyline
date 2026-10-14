# authkeyline

Parse and rebuild OpenSSH authorized_keys lines into typed records

## Install

```
pip install authkeyline
```

## Usage

```python
from authkeyline import parse_line, build_line, parse_file

line = 'command="/usr/bin/backup",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@host'
key = parse_line(line)

key.key_type  # 'ssh-ed25519'
key.key_base64  # 'AAAAC3NzaC1lZDI1NTE5'
key.comment  # 'alice@host'
key.options  # (KeyOption('command', '/usr/bin/backup'), KeyOption('no-pty', None))
key.key_bytes()  # raw bytes of the decoded blob

build_line(key) == line  # True
```

Valued options keep their text unquoted, so a `command=` or `from=` value may
hold the commas, spaces and escaped quotes that the quoting protected:

```python
key = parse_line('from="10.0.0.1,10.0.0.2" ssh-rsa AAAAB3Nza... host')
key.options[0].value  # '10.0.0.1,10.0.0.2'
```

`parse_file` reads a whole `authorized_keys` file and skips blank and `#`
comment lines:

```python
keys = parse_file(open("~/.ssh/authorized_keys").read())
```

A line with no key type or no blob, or a blob that is not base64, raises
`AuthKeyError`.

## Why

OpenSSH `authorized_keys` lines pack an options field, a key type, a base64
blob and a comment into one string, and the options field has its own grammar:
comma-separated flags mixed with `name="value"` pairs whose quoted values can
contain commas, spaces and escaped quotes. Splitting on whitespace or commas
gets this wrong.

`sshpubkeys` targets fingerprint validation and pulls in cryptography
dependencies; the existing `authkeys` package is a key-resolving
`AuthorizedKeysCommand` provider, not a line parser. There was no small, typed,
zero-dependency codec that just reads one line into a structured record and
builds it back. This is that: pure structure, no crypto.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
