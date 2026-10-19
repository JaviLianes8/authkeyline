"""Parse, check and safely build OpenSSH authorized_keys lines into typed records.

``KEY_TYPES`` is the frozen set of key type names sshd accepts on a line, certificates
and the ``rsa-sha2-256`` and ``rsa-sha2-512`` aliases of RSA included:

>>> from authkeyline import KEY_TYPES
>>> "ssh-ed25519" in KEY_TYPES, "rsa-sha2-512" in KEY_TYPES, "ssh-dss" in KEY_TYPES
(True, True, False)
>>> len(KEY_TYPES)
22
"""

from __future__ import annotations

from ._build import build_line
from ._codec import LineProblem, check_file, parse_file, parse_line
from ._errors import AuthKeyError
from ._keytypes import KEY_TYPES as _KEY_TYPES
from ._model import AuthorizedKey, KeyOption
from ._records import Certificate, PublicKey

__version__ = "1.0.0"

KEY_TYPES: frozenset[str] = frozenset(_KEY_TYPES)

__all__ = [
    "KEY_TYPES",
    "AuthKeyError",
    "AuthorizedKey",
    "Certificate",
    "KeyOption",
    "LineProblem",
    "PublicKey",
    "build_line",
    "check_file",
    "parse_file",
    "parse_line",
]
