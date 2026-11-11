"""Minimal IMAP IDLE watcher over a raw TLS socket.

imaplib is not used here on purpose. IDLE needs reads with a timeout, and a
timed-out `socket.makefile` reader (which imaplib uses) becomes permanently
unreadable ("cannot read from timed out object"). So the watcher speaks just
enough IMAP itself: LOGIN, SELECT, IDLE, DONE, NOOP, LOGOUT, with `select()`
doing the waiting and a plain blocking socket underneath.
"""

import select
import socket
import ssl
import time
import re

HOST = "imap.gmail.com"
PORT = 993


class IdleError(RuntimeError):
    pass


class IdleWatcher:
    def __init__(self, user, password, mailbox="INBOX", connect_timeout=60):
        self.user = user
        self.password = password
        self.mailbox = mailbox
        self.connect_timeout = connect_timeout
        self.sock = None
        self.buffer = bytearray()
        self.counter = 0
        self.last_lines = []
        self.uidnext = None
        self.uidvalidity = None

    # -- connection -------------------------------------------------------
    def connect(self):
        context = ssl.create_default_context()
        raw = socket.create_connection((HOST, PORT), timeout=self.connect_timeout)
        try:
            self.sock = context.wrap_socket(raw, server_hostname=HOST)
        except Exception:
            raw.close()
            raise
        # All waiting is done with select(); the socket itself must not time
        # out, or it would be poisoned for the rest of the connection.
        self.sock.settimeout(None)
        greeting = self._read_line(self.connect_timeout)
        if not greeting.startswith(b"* OK"):
            raise IdleError("bad greeting: %r" % greeting)
        self._command(b"LOGIN", self._quote(self.user), self._quote(self.password), timeout=30)
        self._command(b"SELECT", self._quote(self.mailbox), timeout=30)
        for line in self.last_lines:
            text = line.decode("ascii", "replace")
            match = re.search(r"\[UIDNEXT (\d+)\]", text)
            if match:
                self.uidnext = int(match.group(1))
            match = re.search(r"\[UIDVALIDITY (\d+)\]", text)
            if match:
                self.uidvalidity = int(match.group(1))

    @staticmethod
    def _quote(value):
        return ('"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"').encode()

    def _send(self, data):
        if self.sock is None:
            raise IdleError("not connected")
        try:
            self.sock.sendall(data)
        except OSError as exc:
            raise IdleError("send failed: %s" % exc) from exc

    def _read_line(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            index = self.buffer.find(b"\r\n")
            if index >= 0:
                line = bytes(self.buffer[:index])
                del self.buffer[: index + 2]
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IdleError("timeout waiting for a line")
            # TLS can hold decrypted bytes that select() cannot see.
            try:
                pending = self.sock.pending() if hasattr(self.sock, "pending") else 0
            except OSError:
                pending = 0
            if not pending:
                try:
                    ready, _, _ = select.select([self.sock], [], [], remaining)
                except OSError as exc:
                    raise IdleError("select failed: %s" % exc) from exc
                if not ready:
                    raise IdleError("timeout waiting for a line")
            try:
                chunk = self.sock.recv(65536)
            except OSError as exc:
                raise IdleError("recv failed: %s" % exc) from exc
            if not chunk:
                raise IdleError("connection closed by server")
            self.buffer.extend(chunk)

    def _next_tag(self):
        self.counter += 1
        return b"W%d" % self.counter

    def _command(self, name, *args, timeout=30):
        tag = self._next_tag()
        parts = [tag, name]
        parts.extend(args)
        self._send(b" ".join(parts) + b"\r\n")
        self.last_lines = []
        while True:
            line = self._read_line(timeout)
            if line.startswith(tag + b" "):
                pieces = line.split(b" ", 2)
                status = pieces[1].upper() if len(pieces) > 1 else b""
                if status != b"OK":
                    raise IdleError(
                        "%s failed: %s"
                        % (name.decode("ascii", "replace"), line.decode("utf-8", "replace"))
                    )
                return line
            self.last_lines.append(line)

    def noop(self, timeout=30):
        self._command(b"NOOP", timeout=timeout)

    def logout(self):
        try:
            if self.sock is not None:
                self._command(b"LOGOUT", timeout=10)
        except Exception:
            pass
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        self.sock = None

    # -- idle -------------------------------------------------------------
    def idle(self, seconds):
        """IDLE for up to `seconds`.

        Returns 'exists' when the server reported new mail in the selected
        mailbox, or 'timeout' when the window expired (re-issue then).
        """
        tag = self._next_tag()
        self._send(tag + b" IDLE\r\n")
        line = self._read_line(30)
        if not line.startswith(b"+"):
            raise IdleError("IDLE refused: %s" % line.decode("utf-8", "replace"))

        deadline = time.monotonic() + seconds
        result = "timeout"
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = self._read_line(remaining)
            except IdleError as exc:
                if "timeout waiting for a line" in str(exc):
                    break
                raise
            upper = line.upper()
            if b"EXISTS" in upper:
                result = "exists"
                break
            if b"BYE" in upper:
                raise IdleError("server said BYE: %s" % line.decode("utf-8", "replace"))

        self._send(b"DONE\r\n")
        deadline = time.monotonic() + 60
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IdleError("no reply to DONE")
            line = self._read_line(remaining)
            if line.startswith(tag + b" "):
                break
        return result
