"""Gunicorn thread worker for the Admin UI that never parks a thread on an idle socket.

gunicorn's gthread worker hands every accepted connection to a pool thread,
which waits up to 5 s for the first bytes and then, for TLS, completes the
handshake and blocks reading the request line with no timeout. Browsers open
spare connections ahead of need (preconnect, late socket binding): the TLS
handshake completes and no request follows for a long time. Each such socket
pins a pool thread, so two of them stall the whole Admin UI (default
``--threads 2``) until the browser closes or uses them, which is why a full
page reload "fixes" it. Reproduced against gunicorn 27.0.1: two idle
post-handshake TLS connections held a ``/health`` request for as long as they
stayed open.

This worker returns such a connection to the main poller instead: before the
first bytes arrive, and again after the TLS handshake while no request data is
buffered or readable. The poller hands it back to a pool thread when the
client sends its request, and closes it after ``--keep-alive`` seconds of
silence, as for any kept-alive connection.
"""

from __future__ import annotations

import errno
import ssl

from gunicorn.workers import gthread

# Private in gunicorn (pinned in requirements.txt): bound at import so a rename
# fails the worker boot instead of dropping every connection at run time.
_DEFER = gthread._DEFER


class AdminThreadWorker(gthread.ThreadWorker):
    def handle(self, conn: gthread.TConn):
        if not conn.initialized:
            if not conn.data_ready and not conn.wait_for_data(0):
                return _DEFER
            if self.cfg.is_ssl:
                try:
                    conn.init()
                except ssl.SSLError as exc:
                    # Same outcome and logging as the base worker.
                    if exc.args[0] == ssl.SSL_ERROR_EOF:
                        self.log.debug("ssl connection closed")
                    else:
                        self.log.debug("Error processing SSL request.")
                        self.handle_error(None, conn.sock, conn.client, exc)
                    return False
                except OSError as exc:
                    if exc.errno not in {errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN}:
                        self.log.exception("Socket error processing request.")
                    else:
                        self.log.debug("Ignoring %s during TLS handshake", exc)
                    return False
                except Exception as exc:
                    self.handle_error(None, conn.sock, conn.client, exc)
                    return False
                if not conn.is_http2 and not conn.sock.pending():
                    # Request bytes still in the kernel buffer wake the poller
                    # again; decrypted ones (pending) would not, so only defer
                    # when neither exists.
                    conn.data_ready = False
                    if not conn.wait_for_data(0):
                        return _DEFER
        return super().handle(conn)
