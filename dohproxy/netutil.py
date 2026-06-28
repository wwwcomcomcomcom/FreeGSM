"""Shared socket primitives used by both the Windows and macOS relays.

These were duplicated across ``tcp_proxy``/``https_proxy`` (Windows, pydivert) and
``macos/resolver``/``macos/socks_proxy`` (macOS, no pydivert). This module imports
neither pydivert nor any platform-specific code, so it loads everywhere and is the
single home for the recv-exactly loop, the bidirectional pump, and the
ClientHello-splitting relay.
"""

from __future__ import annotations

import logging
import socket
import threading

from . import config, dpi


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes, or fewer if the peer closes first.

    Returns a buffer shorter than ``n`` only on EOF; callers must length-check
    the result before trusting it.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


def pump(src: socket.socket, dst: socket.socket) -> None:
    """Copy ``src`` -> ``dst`` until EOF, then half-close ``dst``'s write side.

    An idle read timeout reaps a half-open/stalled connection so it can't hold a
    thread + two sockets indefinitely.
    """
    try:
        src.settimeout(config.RELAY_IDLE_TIMEOUT)
    except OSError:
        pass
    try:
        while True:
            data = src.recv(65535)
            if not data:
                break
            dst.sendall(data)
    except OSError:  # includes socket.timeout (idle connection)
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def split_relay(client: socket.socket, upstream: socket.socket,
                host: str, port: int, log: logging.Logger, tag: str) -> None:
    """Read the first client segment (the TLS ClientHello on :443) and re-emit it
    fragmented across two TLS records via :func:`dpi.split_hello`, then run a dumb
    bidirectional pipe for the rest of the connection.

    ``tag`` is the log prefix (e.g. ``"HTTPS"`` or ``"SOCKS"``). Only :443 TLS
    handshakes are split; any other port is piped straight through.
    """
    # Only :443 needs us to read the client's first segment before forwarding,
    # so we can re-emit the ClientHello as two TLS records. For every other port
    # -- including server-speaks-first protocols (SSH/SMTP/IMAP) routed through
    # the macOS tunnel -- skip the blocking first-read, which would otherwise
    # stall the whole connection waiting for client bytes that never come.
    if port == 443:
        client.settimeout(config.HTTPS_FIRST_READ_TIMEOUT)
        try:
            first = client.recv(65535)
        except (socket.timeout, OSError):
            return
        client.settimeout(None)
        if not first:
            return

        try:
            if dpi.is_tls_handshake(first):
                segs = dpi.split_hello(first, config.SPLIT_MIN, config.SPLIT_MAX)
                log.info("[%s] %s:%d  SNI=%s  ClientHello %dB -> %d TLS records",
                         tag, host, port, dpi.sni_name(first), len(first), len(segs))
                for seg in segs:
                    upstream.sendall(seg)
            else:
                # Plaintext on :443: forward untouched.
                upstream.sendall(first)
        except OSError as exc:
            log.debug("[%s] %s:%d first write failed: %s", tag, host, port, exc)
            return

    reverse = threading.Thread(target=pump, args=(upstream, client),
                               name=f"{tag.lower()}-pump", daemon=True)
    reverse.start()
    pump(client, upstream)
    # Wait for the upstream->client direction to finish on its own (upstream EOF
    # or the idle timeout in pump). A short fixed timeout here would force-close
    # the upstream mid-response and truncate a large/slow download.
    reverse.join()
