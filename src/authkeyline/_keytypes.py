"""The key type names OpenSSH accepts in authorized_keys, from the keyimpls table of sshkey.c."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyType:
    name: str
    family: str  # rsa, ed25519, ecdsa, ecdsa-sk, ed25519-sk, mldsa44-ed25519
    curve: str | None
    cert: bool
    short: str

    @property
    def identity(self) -> tuple[str, str | None, bool]:
        """What sshd compares between the line and the blob: key type and curve."""
        return (self.family, self.curve, self.cert)


def _pair(name: str, family: str, short: str, curve: str | None = None) -> list[KeyType]:
    cert = name.replace("@openssh.com", "") + "-cert-v01@openssh.com"
    return [KeyType(name, family, curve, False, short), KeyType(cert, family, curve, True, short)]


_TYPES: list[KeyType] = [
    *_pair("ssh-ed25519", "ed25519", "ED25519"),
    *_pair("sk-ssh-ed25519@openssh.com", "ed25519-sk", "ED25519-SK"),
    # ssh-mldsa-eddsa.c names the certificate without the -v01@openssh.com suffix.
    KeyType("ssh-mldsa44-ed25519", "mldsa44-ed25519", None, False, "MLDSA44-ED25519"),
    KeyType("ssh-mldsa44-ed25519-cert", "mldsa44-ed25519", None, True, "MLDSA44-ED25519"),
    *_pair("ecdsa-sha2-nistp256", "ecdsa", "ECDSA", "nistp256"),
    *_pair("ecdsa-sha2-nistp384", "ecdsa", "ECDSA", "nistp384"),
    *_pair("ecdsa-sha2-nistp521", "ecdsa", "ECDSA", "nistp521"),
    *_pair("sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sk", "ECDSA-SK", "nistp256"),
    *_pair("webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sk", "ECDSA-SK", "nistp256"),
    *_pair("ssh-rsa", "rsa", "RSA"),
    # RFC 8332 signature names map to the RSA key type in sshkey.c, so sshd reads them too.
    *_pair("rsa-sha2-256", "rsa", "RSA"),
    *_pair("rsa-sha2-512", "rsa", "RSA"),
]

KEY_TYPES: dict[str, KeyType] = {kind.name: kind for kind in _TYPES}

# The name ssh-keygen writes for each plain key when it fingerprints it.
PLAIN_NAMES: dict[tuple[str, str | None], str] = {
    ("ed25519", None): "ssh-ed25519",
    ("ed25519-sk", None): "sk-ssh-ed25519@openssh.com",
    ("mldsa44-ed25519", None): "ssh-mldsa44-ed25519",
    ("ecdsa", "nistp256"): "ecdsa-sha2-nistp256",
    ("ecdsa", "nistp384"): "ecdsa-sha2-nistp384",
    ("ecdsa", "nistp521"): "ecdsa-sha2-nistp521",
    ("ecdsa-sk", "nistp256"): "sk-ecdsa-sha2-nistp256@openssh.com",
    ("rsa", None): "ssh-rsa",
}


def short_name(kind: KeyType) -> str:
    return kind.short + ("-CERT" if kind.cert else "")


# Signature names each CA key type can produce (the sigalg entries of the sshkey.c impls).
SIGNATURE_NAMES: dict[tuple[str, str | None], frozenset[str]] = {
    ("ed25519", None): frozenset({"ssh-ed25519"}),
    ("ed25519-sk", None): frozenset({"sk-ssh-ed25519@openssh.com"}),
    ("mldsa44-ed25519", None): frozenset({"ssh-mldsa44-ed25519"}),
    ("ecdsa", "nistp256"): frozenset({"ecdsa-sha2-nistp256"}),
    ("ecdsa", "nistp384"): frozenset({"ecdsa-sha2-nistp384"}),
    ("ecdsa", "nistp521"): frozenset({"ecdsa-sha2-nistp521"}),
    ("ecdsa-sk", "nistp256"): frozenset(
        {"sk-ecdsa-sha2-nistp256@openssh.com", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"}
    ),
    ("rsa", None): frozenset({"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}),
}
