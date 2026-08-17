"""Policy-neutral framing helpers for bounded ClamAV command replies."""

from __future__ import annotations

from typing import Protocol

CLAMD_PING_REQUEST = b"PING\n"
CLAMD_PING_MAX_REPLY_BYTES = 64


class ReceivingSocket(Protocol):
    def recv(self, size: int) -> bytes: ...


def recv_terminated_reply(
    sock: ReceivingSocket,
    *,
    max_bytes: int,
) -> bytes:
    """Receive one bounded ClamAV reply without discarding buffered trailing data."""
    data = bytearray()
    while len(data) < max_bytes:
        chunk = sock.recv(max_bytes - len(data))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in data or b"\0" in data:
            break
    return bytes(data)


def ping_reply_is_pong(data: bytes) -> bool:
    """Recognize only a complete canonical PONG frame."""
    if data.endswith(b"\r\n"):
        payload = data[:-2]
    elif data.endswith((b"\n", b"\0")):
        payload = data[:-1]
    else:
        return False
    return payload == b"PONG"
