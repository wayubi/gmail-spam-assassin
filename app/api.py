"""JSON API plus the single-page UI.

Every API route needs X-Api-Token (or Authorization: Bearer). The page itself
is public: it only renders, and asks for the token before doing anything.
"""

import hashlib
import hmac
import json
import os
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import blacklist, imap, listing, quarantine, runner, state, whitelist

MAX_BODY = 64 * 1024
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_static_cache = {}


def _int_param(query, name, default, low, high):
    raw = (query.get(name) or [""])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


class Handler(BaseHTTPRequestHandler):
    server_version = "gmail-spam-assassin/1.0"
    protocol_version = "HTTP/1.1"
    cfg = None  # set by serve()

    # -- logging: method and path only, never the token -------------------
    def log_message(self, fmt, *args):
        try:
            message = fmt % args
        except Exception:
            message = str(fmt)
        print("[api] %s %s" % (self.address_string(), message), flush=True)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_HEAD(self):
        self._dispatch("GET", head_only=True)

    # -- routing ----------------------------------------------------------
    def _dispatch(self, method, head_only=False):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if len(path) > 1:
            path = path.rstrip("/")
        query = urllib.parse.parse_qs(parsed.query)

        # Drain the request body up front. An unread body would desynchronise
        # the next request on a keep-alive connection.
        self._raw = b""
        self._body_error = None
        if method in ("POST", "DELETE"):
            self._raw, self._body_error = self._read_raw_body()

        try:
            if method == "GET" and path == "/":
                return self._static("index.html", head_only=head_only)
            if method == "GET" and path == "/healthz":
                return self._json(200, {"ok": True}, head_only=head_only)
            if not self._authorized():
                return self._json(
                    401,
                    {"error": "missing or wrong X-Api-Token"},
                    head_only=head_only,
                )

            if method == "GET" and path == "/status":
                return self._status(head_only)
            if method == "GET" and path == "/messages":
                if query.get("refresh"):
                    listing.invalidate()
                days = _int_param(query, "days", self.cfg.list_days, 1, 365)
                limit = _int_param(query, "limit", 200, 1, 1000)
                folder = (query.get("folder") or ["all"])[0].lower()
                return self._json(
                    200, listing.messages(self.cfg, days, limit, folder), head_only
                )
            if method == "GET" and path == "/senders":
                if query.get("refresh"):
                    listing.invalidate()
                days = _int_param(query, "days", self.cfg.list_days, 1, 365)
                limit = _int_param(query, "limit", 200, 1, 1000)
                return self._json(
                    200, listing.senders(self.cfg, days, limit), head_only
                )
            if method == "GET" and path == "/blacklist":
                return self._blacklist(head_only)
            if method == "GET" and path == "/mailboxes":
                conn = imap.connect(self.cfg.gmail_user, self.cfg.gmail_password)
                try:
                    names = imap.list_mailboxes(conn)
                    all_mail = imap.match_mailbox(names, "/all mail", imap.ALL_MAIL)
                    spam = imap.match_mailbox(names, "/spam")
                    trash = imap.match_mailbox(names, "/trash")
                    q_label = imap.match_label(names, self.cfg.quarantine_label)
                finally:
                    imap.logout(conn)
                return self._json(
                    200,
                    {
                        "mailboxes": names,
                        "all_mail": all_mail,
                        "spam": spam,
                        "trash": trash,
                        "quarantine_label": q_label,
                        "can_delete": bool(trash),
                        "note": "Gmail hides Spam and Trash from IMAP unless "
                        "'Show in IMAP' is enabled for them in Settings > Labels. "
                        "Trash is required for deletion: without it a live run "
                        "refuses to delete anything. The quarantine label must "
                        "also exist and be shown in IMAP.",
                    },
                    head_only,
                )
            if method == "POST" and path == "/blacklist":
                return self._blacklist_add()
            if method == "POST" and path == "/blacklist/remove":
                return self._blacklist_remove()
            if method == "DELETE" and path.startswith("/blacklist/"):
                address = urllib.parse.unquote(path[len("/blacklist/") :])
                if not address:
                    return self._json(400, {"error": "no address in the path"}, head_only)
                return self._json(
                    200,
                    blacklist.remove(self.cfg.blacklist_path, [address]),
                    head_only,
                )
            if method == "GET" and path == "/whitelist":
                return self._whitelist(head_only)
            if method == "POST" and path == "/whitelist":
                return self._whitelist_add()
            if method == "POST" and path == "/whitelist/remove":
                return self._whitelist_remove()
            if method == "DELETE" and path.startswith("/whitelist/"):
                address = urllib.parse.unquote(path[len("/whitelist/") :])
                if not address:
                    return self._json(400, {"error": "no address in the path"}, head_only)
                result = whitelist.remove(self.cfg.whitelist_path, [address])
                return self._json(200, result, head_only)
            if method == "GET" and path == "/quarantine":
                return self._quarantine(head_only)
            if method == "POST" and path == "/quarantine":
                return self._quarantine_add()
            if method == "POST" and path == "/quarantine/remove":
                return self._quarantine_remove()
            if method == "DELETE" and path.startswith("/quarantine/"):
                address = urllib.parse.unquote(path[len("/quarantine/") :])
                if not address:
                    return self._json(400, {"error": "no address in the path"}, head_only)
                result = quarantine.remove(self.cfg.quarantine_path, [address])
                return self._json(200, result, head_only)
            if method == "POST" and path == "/run":
                return self._run()
            if method == "GET" and path == "/audit":
                limit = _int_param(query, "limit", 100, 1, 1000)
                return self._json(
                    200,
                    {"lines": state.tail_jsonl(self.cfg.audit_path, limit)},
                    head_only,
                )
            if method == "GET" and path.startswith("/runs/"):
                return self._run_status(path[len("/runs/") :], head_only)
            return self._json(404, {"error": "not found: %s" % path}, head_only)
        except Exception as exc:  # noqa: BLE001 - always answer with JSON
            return self._json(500, {"error": str(exc)}, head_only)

    # -- handlers ---------------------------------------------------------
    def _status(self, head_only):
        data = state.read_state(self.cfg.state_path)
        entries, errors = blacklist.load(
            self.cfg.blacklist_path, self.cfg.allow_freemail_domains
        )
        q_entries, q_errors = quarantine.load(self.cfg.quarantine_path)
        payload = {
            "ok": True,
            "mode": self.cfg.mode,
            "dry_run": self.cfg.dry_run,
            "running": runner.busy(),
            "blacklist_entries": len(entries),
            "blacklist_errors": errors,
            "whitelist_entries": len(whitelist.load(self.cfg.whitelist_path)[0]),
            "quarantine_entries": len(q_entries),
            "quarantine_errors": q_errors,
            "quarantine_label": self.cfg.quarantine_label,
            "quarantine_age": self.cfg.quarantine_age.text,
            "quarantine_cutoff": self.cfg.quarantine_age.cutoff(
                datetime.now(timezone.utc)
            ).date().isoformat(),
            "mailboxes": ["[Gmail]/All Mail", "[Gmail]/Spam"],
            "trash_is_terminal": True,
            "max_delete_per_run": self.cfg.max_delete_per_run,
            "max_trash_per_run": self.cfg.max_trash_per_run,
            "poll_interval": self.cfg.poll_interval,
            "list_days": self.cfg.list_days,
            "state": data,
        }
        return self._json(200, payload, head_only)

    def _blacklist(self, head_only):
        entries, errors = blacklist.load(
            self.cfg.blacklist_path, self.cfg.allow_freemail_domains
        )
        return self._json(
            200,
            {
                "path": self.cfg.blacklist_path,
                "count": len(entries),
                "entries": entries,
                "errors": errors,
            },
            head_only,
        )

    def _blacklist_add(self):
        body, error = self._body()
        if error:
            return self._json(400, {"error": error})
        addresses = body.get("addresses")
        if addresses is None and body.get("address"):
            addresses = [body["address"]]
        if not isinstance(addresses, list) or not addresses:
            return self._json(400, {"error": "expected {\"addresses\": [...]}"})
        result = blacklist.add(
            self.cfg.blacklist_path, addresses, self.cfg.allow_freemail_domains
        )
        result["count"] = len(
            blacklist.load(
                self.cfg.blacklist_path, self.cfg.allow_freemail_domains
            )[0]
        )
        return self._json(200, result)

    def _blacklist_remove(self):
        body, error = self._body()
        if error:
            return self._json(400, {"error": error})
        addresses = body.get("addresses")
        if addresses is None and body.get("address"):
            addresses = [body["address"]]
        if not isinstance(addresses, list) or not addresses:
            return self._json(400, {"error": "expected {\"addresses\": [...]}"})
        result = blacklist.remove(self.cfg.blacklist_path, addresses)
        return self._json(200, result)

    def _addresses(self):
        """Shared body parsing for the list endpoints."""
        body, error = self._body()
        if error:
            return None, self._json(400, {"error": error})
        addresses = body.get("addresses")
        if addresses is None and body.get("address"):
            addresses = [body["address"]]
        if not isinstance(addresses, list) or not addresses:
            return None, self._json(400, {"error": "expected {\"addresses\": [...]}"})
        return addresses, None

    def _whitelist(self, head_only):
        entries, errors = whitelist.load(self.cfg.whitelist_path)
        return self._json(
            200,
            {
                "path": self.cfg.whitelist_path,
                "count": len(entries),
                "entries": entries,
                "errors": errors,
            },
            head_only,
        )

    def _whitelist_add(self):
        addresses, error = self._addresses()
        if error:
            return error
        result = whitelist.add(self.cfg.whitelist_path, addresses)
        result["count"] = len(whitelist.load(self.cfg.whitelist_path)[0])
        return self._json(200, result)

    def _whitelist_remove(self):
        addresses, error = self._addresses()
        if error:
            return error
        result = whitelist.remove(self.cfg.whitelist_path, addresses)
        return self._json(200, result)

    def _quarantine(self, head_only):
        entries, errors = quarantine.load(self.cfg.quarantine_path)
        return self._json(
            200,
            {
                "path": self.cfg.quarantine_path,
                "count": len(entries),
                "entries": entries,
                "errors": errors,
                "label": self.cfg.quarantine_label,
                "age": self.cfg.quarantine_age.text,
                "cutoff": self.cfg.quarantine_age.cutoff(
                    datetime.now(timezone.utc)
                ).date().isoformat(),
            },
            head_only,
        )

    def _quarantine_add(self):
        addresses, error = self._addresses()
        if error:
            return error
        result = quarantine.add(self.cfg.quarantine_path, addresses)
        result["count"] = len(quarantine.load(self.cfg.quarantine_path)[0])
        return self._json(200, result)

    def _quarantine_remove(self):
        addresses, error = self._addresses()
        if error:
            return error
        result = quarantine.remove(self.cfg.quarantine_path, addresses)
        return self._json(200, result)

    def _run(self):
        body, error = self._body()
        if error:
            return self._json(400, {"error": error})
        dry = body.get("dry_run")
        if dry is not None:
            dry = bool(dry)
        if runner.busy():
            return self._json(
                409, {"error": "a run is already in progress", "running": True}
            )
        run_id = uuid.uuid4().hex[:12]
        cfg = self.cfg

        def work():
            try:
                result = runner.run_purge(
                    cfg, dry_run=dry, reason="api", run_id=run_id
                )
            except Exception:  # noqa: BLE001 - a background thread must not die loudly
                return
            if result and result.get("skipped"):
                runner.record_skipped(cfg, run_id, result["skipped"], dry)

        threading.Thread(target=work, name="api-run", daemon=True).start()
        return self._json(202, {"accepted": True, "run_id": run_id, "running": True})

    def _run_status(self, run_id, head_only):
        if not run_id:
            return self._json(400, {"error": "no run id"}, head_only)
        record = runner.get_run(run_id)
        if record is not None:
            return self._json(
                200,
                {"found": True, "running": runner.busy(), "run": record},
                head_only,
            )
        for record in reversed(state.tail_jsonl(self.cfg.audit_path, 5000)):
            if record.get("kind") == "summary" and record.get("run_id") == run_id:
                return self._json(
                    200,
                    {"found": True, "running": runner.busy(), "run": record},
                    head_only,
                )
        return self._json(
            200, {"found": False, "running": runner.busy()}, head_only
        )

    # -- plumbing ---------------------------------------------------------
    def _authorized(self):
        token = self.cfg.api_token
        supplied = self.headers.get("X-Api-Token", "")
        if not supplied:
            header = self.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                supplied = header[7:].strip()
        if not supplied or not token:
            return False
        return hmac.compare_digest(supplied, token)

    def _read_raw_body(self):
        if (self.headers.get("Transfer-Encoding") or "").strip():
            self.close_connection = True
            return b"", "chunked request bodies are not supported"
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            return b"", "bad Content-Length"
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            return b"", "body too large (limit %d bytes)" % MAX_BODY
        return (self.rfile.read(length) if length else b""), None

    def _body(self):
        if self._body_error:
            return {}, self._body_error
        raw = self._raw or b"{}"
        if not raw.strip():
            return {}, None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            return {}, "invalid JSON: %s" % exc
        if not isinstance(data, dict):
            return {}, "expected a JSON object"
        return data, None

    def _static(self, name, head_only=False):
        cached = _static_cache.get(name)
        if cached is None:
            path = os.path.join(STATIC_DIR, name)
            try:
                with open(path, "rb") as handle:
                    payload = handle.read()
            except OSError:
                return self._json(404, {"error": "not found"}, head_only)
            etag = '"%s"' % hashlib.sha1(payload).hexdigest()
            cached = (payload, etag)
            _static_cache[name] = cached
        payload, etag = cached
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("ETag", etag)
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)

    def _json(self, code, payload, head_only=False):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def serve(cfg, stop_event):
    Handler.cfg = cfg
    httpd = ThreadingHTTPServer((cfg.api_host, cfg.api_port), Handler)
    httpd.daemon_threads = True
    watcher = threading.Thread(
        target=_shutdown_on_stop, args=(httpd, stop_event), daemon=True
    )
    watcher.start()
    print("[api] listening on %s:%d" % (cfg.api_host, cfg.api_port), flush=True)
    httpd.serve_forever(poll_interval=0.5)


def _shutdown_on_stop(httpd, stop_event):
    stop_event.wait()
    try:
        httpd.shutdown()
    except Exception:
        pass
