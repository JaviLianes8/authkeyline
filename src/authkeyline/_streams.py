"""Output for the command line: raw bytes, closed streams and readers that go away."""

from __future__ import annotations

import contextlib
import errno
import os
import re
import sys
from collections.abc import Iterator
from typing import TextIO

# Lone surrogates that surrogateescape cannot turn back into a byte: a Windows file name or
# argument can hold them, since its command line and file names are UTF-16 without checks.
_UNPAIRED = re.compile("[\ud800-\udc7f\udd00-\udfff]")
# On Windows no surrogate of a name or argument stands for a byte, U+DC80..U+DCFF included.
_ANY_SURROGATE = re.compile("[\ud800-\udfff]")


@contextlib.contextmanager
def quiet_when_the_reader_goes() -> Iterator[None]:
    try:
        yield
    except OSError as exc:
        # The reader went away (| head): stop quietly, as ssh-keygen does.
        if not isinstance(exc, BrokenPipeError) and exc.errno not in (errno.EPIPE, errno.EINVAL):
            raise
        _silence()


def _silence() -> None:
    """Point the standard streams at the null device so the final flush cannot fail."""
    null = os.open(os.devnull, os.O_WRONLY)
    for stream in (sys.stdout, sys.stderr):
        # A stream that is not a real file, as under a test runner, is left alone.
        with contextlib.suppress(OSError, ValueError, AttributeError):
            os.dup2(null, stream.fileno())
    os.close(null)


def _escaped(pattern: re.Pattern[str], text: str) -> str:
    return pattern.sub(lambda found: f"\\u{ord(found.group()):04x}", text)


def native(text: str, windows: bool = os.name == "nt") -> str:
    """A file name or argument as the system gave it, ready for ``encode``.

    On POSIX a surrogate in U+DC80..U+DCFF is a byte of the name and stays. Windows names
    are UTF-16, so there every lone surrogate is escaped.
    """
    return _escaped(_ANY_SURROGATE, text) if windows else text


def encode(text: str) -> bytes:
    """UTF-8 that cannot fail: a byte kept as a surrogate comes back, any other is escaped."""
    return _escaped(_UNPAIRED, text).encode("utf-8", errors="surrogateescape")


def valid_text(value: str) -> str:
    """Valid Unicode for JSON: a byte that is not UTF-8 becomes U+FFFD."""
    return encode(value).decode("utf-8", "replace")


def write(stream: TextIO | None, line: str) -> None:
    put(stream, line + "\n")


def put(stream: TextIO | None, message: str) -> None:
    if stream is None:
        return  # started with the stream closed (>&-), so there is nobody to tell
    raw = getattr(stream, "buffer", None)
    if raw is None:
        stream.write(message)
        stream.flush()
        return
    # Text already waiting in the stream goes first, so the order on the wire is kept.
    stream.flush()
    raw.write(encode(message))
    raw.flush()
