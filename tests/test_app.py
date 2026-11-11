import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import blacklist, config, imap, state  # noqa: E402

ok = 0
bad = 0


def check(name, condition, detail=""):
    global ok, bad
    if condition:
        ok += 1
        print("  ok   %s" % name)
    else:
        bad += 1
        print("  FAIL %s %s" % (name, detail))


print("blacklist validation")
for entry in ["A@B.com", "  hello@genomelink.io  ", "@spam.example.com"]:
    try:
        print("    %-28r -> %r" % (entry, blacklist.validate(entry)))
    except blacklist.InvalidEntry as exc:
        print("    %-28r -> refused: %s" % (entry, exc))

check("normalises case", blacklist.validate("A@B.com") == "a@b.com")
try:
    blacklist.validate("example.com")
    check("bare domain refused", False)
except blacklist.InvalidEntry:
    check("bare domain refused", True)
for bad_entry in ["@gmail.com", 'a"b@c.com', "a b@c.com", "@", "a@@b.com", "a@b"]:
    try:
        blacklist.validate(bad_entry)
        check("refuses %r" % bad_entry, False)
    except blacklist.InvalidEntry:
        check("refuses %r" % bad_entry, True)

entries, errors = blacklist.parse_text(
    "# c\n\na@b.com\n@spam.example\nbogus\nA@B.com\n"
)
check("parse dedupes", entries == ["a@b.com", "@spam.example"], entries)
check("parse reports bad line", len(errors) == 1 and errors[0]["line"] == 5, errors)

print("blacklist add/remove")
tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "blacklist.txt")
blacklist.ensure(path)
res = blacklist.add(path, ["x@y.com", "@spam.example", "bad", "x@y.com"])
check("add new", res["added"] == ["x@y.com", "@spam.example"], res)
check("add dup skipped", res["skipped"] == ["x@y.com"], res)
check("add bad rejected", len(res["errors"]) == 1, res)
text = open(path).read()
check("comments preserved", text.startswith("# gmail-spam-assassin blacklist"), text[:60])
res = blacklist.remove(path, ["X@Y.COM", "nope@nope.com"])
check("remove case-insensitive", res["removed"] == ["x@y.com"], res)
check("remove missing reported", res["missing"] == ["nope@nope.com"], res)
entries, errors = blacklist.load(path)
check("file still parses", entries == ["@spam.example"] and not errors, entries)
check("matches exact", blacklist.matches("X@Y.COM", ["x@y.com"]) == "x@y.com")
check("matches domain", blacklist.matches("a@spam.example", ["@spam.example"]) == "@spam.example")
check("no false domain match", blacklist.matches("a@notspam.example", ["@spam.example"]) is None)

print("imap parsing")
meta = (
    b'1 (UID 42 X-GM-MSGID 1234567890123456789 '
    b'X-GM-LABELS ("\\\\Inbox" "\\\\Important" "Receipts") '
    b'INTERNALDATE " 9-Nov-2026 04:00:00 -0800" '
    b'BODY[HEADER.FIELDS (FROM SUBJECT)] {120}'
)
headers = b"From: Genomelink <noreply@genomelink.io>\r\nSubject: =?UTF-8?B?SGVsbG8=?= world\r\n\r\n"
rows = imap._parse_fetch([(meta, headers), b")"])
check("one row parsed", len(rows) == 1, rows)
row = rows[0]
check("uid", row["uid"] == 42, row)
check("msgid", row["msgid"] == 1234567890123456789, row)
check("labels", row["labels"] == ["Inbox", "Important", "Receipts"], row["labels"])
check("from addr", row["from_addr"] == "noreply@genomelink.io", row)
check("from name", row["from_name"] == "Genomelink", row)
check("subject decoded", row["subject"] == "Hello world", row["subject"])
check("date parsed", row["date"] == "2026-11-09T12:00:00+00:00", row["date"])

print("imap helpers")
check("compress single", imap.compress_uids([42]) == "42")
check("compress range", imap.compress_uids([101, 102, 103, 105, 107, 108]) == "101:103,105,107:108")
check("compress dedupes/sorts", imap.compress_uids([3, 1, 2]) == "1:3")
check("match all mail", imap.match_mailbox(["[Gmail]/All Mail"], "/all mail") == "[Gmail]/All Mail")
check("match label case-insensitive", imap.match_label(["Quarantine"], "quarantine") == "Quarantine")


class SelectionConn:
    def __init__(self):
        self.calls = 0
        self.untagged_responses = {"UIDNEXT": [b"77"], "UIDVALIDITY": [b"55"]}

    def select(self, mailbox, readonly=False):
        self.calls += 1
        return "OK", [b"1"]


sel = SelectionConn()
imap.select(sel, "INBOX", readonly=True)
imap.select(sel, "INBOX", readonly=True)
check("same read-only selection reused", sel.calls == 1, sel.calls)
imap.select(sel, "INBOX", readonly=False)
check("writable upgrade selects once", sel.calls == 2, sel.calls)
imap.select(sel, "INBOX", readonly=True)
check("read-only on writable does not downgrade", sel.calls == 2, sel.calls)
imap.select(sel, "Other", readonly=True)
check("different mailbox selects", sel.calls == 3, sel.calls)
check("uidnext parsed", sel.uidnext == 77, sel.uidnext)
check("uidvalidity parsed", sel.uidvalidity == 55, sel.uidvalidity)

print("state")
state_path = os.path.join(tmp, "state.json")
state.update_state(state_path, heartbeat=state.now_iso(), watcher="idle")
check("state roundtrip", state.read_state(state_path)["watcher"] == "idle")
audit = os.path.join(tmp, "audit.jsonl")
state.append_audit(audit, {"kind": "message", "uid": 1})
state.append_audit(audit, {"kind": "summary", "ok": True})
check("audit tail", [r["kind"] for r in state.tail_jsonl(audit, 10)] == ["message", "summary"])
check("audit tail limit", len(state.tail_jsonl(audit, 1)) == 1)

state.append_audit_many(audit, [{"kind": "batch", "i": i} for i in range(4)])
batch_tail = state.tail_jsonl(audit, 3)
check("append many writes all", [row.get("i") for row in batch_tail] == [1, 2, 3], batch_tail)

big = os.path.join(tmp, "big.jsonl")
with open(big, "w", encoding="utf-8") as handle:
    for index in range(5000):
        handle.write('{"kind":"big","i":%d}\n' % index)
long_tail = state.tail_jsonl(big, 3)
check("reverse tail reads the end", [row["i"] for row in long_tail] == [4997, 4998, 4999], long_tail)

rot = os.path.join(tmp, "rot.jsonl")
old_max = state.MAX_AUDIT_BYTES
state.MAX_AUDIT_BYTES = 300
try:
    for index in range(20):
        state.append_audit(rot, {"kind": "rot", "i": index, "pad": "x" * 80})
    check("audit rotates by size", os.path.exists(rot + ".1"), os.listdir(tmp))
finally:
    state.MAX_AUDIT_BYTES = old_max

print("config")
os.environ.update(
    GMAIL_USER="a@b.com",
    GMAIL_APP_PASSWORD="abcd efgh ijkl mnop",
    SPAM_API_TOKEN="x" * 24,
    DATA_DIR=tmp,
    MODE="idle",
    DRY_RUN="true",
)
cfg = config.load()
check("password spaces stripped", cfg.gmail_password == "abcdefghijklmnop", cfg.gmail_password)
check("no config problems", cfg.problems() == [], cfg.problems())
check("dry run true", cfg.dry_run is True)
check("blacklist budget", cfg.max_trash_per_run == 200, cfg.max_trash_per_run)

print("age parsing")
from datetime import datetime, timezone  # noqa: E402

from app import age  # noqa: E402

NOW = datetime(2026, 5, 31, 12, 0, tzinfo=timezone.utc)
cases = {
    "14": (14, "d", "14 days"),
    "14d": (14, "d", "14 days"),
    "14 days": (14, "d", "14 days"),
    "1 day": (1, "d", "1 day"),
    "3m": (3, "m", "3 months"),
    "1 year": (1, "y", "1 year"),
}
for spec, (count, unit, text) in cases.items():
    parsed = age.Age.parse(spec)
    check("parse %r" % spec, (parsed.count, parsed.unit, parsed.text) == (count, unit, text), parsed)
for spec in ["3w", "0", "0d", "-3d", "", "abc", "3 m 2", "1.5m", "1001d"]:
    try:
        age.Age.parse(spec)
        check("refuse age %r" % spec, False)
    except ValueError:
        check("refuse age %r" % spec, True)
months = age.Age.parse("3m").cutoff(NOW)
check("months clamp to month end", months.date().isoformat() == "2026-02-28", months)
check("year is calendar not 365d", age.Age.parse("1y").cutoff(NOW).date().isoformat() == "2025-05-31")
leap = datetime(2024, 2, 29, 0, 0, tzinfo=timezone.utc)
check("leap day clamps", age.Age.parse("1y").cutoff(leap).date().isoformat() == "2023-02-28")
check("exact cutoff is expired", age.Age.parse("14d").expired("2026-05-17T12:00:00+00:00", NOW) is True)
check("one second younger is not", age.Age.parse("14d").expired("2026-05-17T12:00:01+00:00", NOW) is False)
check("future is not expired", age.Age.parse("14d").expired("2030-01-01T00:00:00+00:00", NOW) is False)
check("unreadable date is unknown", age.Age.parse("14d").expired("not-a-date", NOW) is None)
check("config exposes age", cfg.quarantine_age.text == "14 days", cfg.quarantine_age)
check("gmail form", age.Age.parse("3m").gmail == "3m" and age.Age.parse("14").gmail == "14d")
os.environ["QUARANTINE_AGE"] = "3w"
bad_cfg = config.load()
check("bad age becomes a problem", any("QUARANTINE_AGE" in p for p in bad_cfg.problems()), bad_cfg.problems())
os.environ["QUARANTINE_AGE"] = "14d"
os.environ["QUARANTINE_LABEL"] = "[Gmail]/Trash"
bad_label = config.load()
check("system label refused", any("QUARANTINE_LABEL" in p for p in bad_label.problems()), bad_label.problems())
os.environ["QUARANTINE_LABEL"] = 'Foo"Bar'
quoted_label = config.load()
check("quoted label refused", any("QUARANTINE_LABEL" in p for p in quoted_label.problems()), quoted_label.problems())
os.environ["QUARANTINE_LABEL"] = "Quarantine"

print("http api")
from app import api  # noqa: E402

port = 18099
api.Handler.cfg = cfg
server = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(
    ("127.0.0.1", port), api.Handler
)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(0.4)

BASE = "http://127.0.0.1:%d" % port


def call(method, path, body=None, token="x" * 24):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        req.add_header("X-Api-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


status, payload = call("GET", "/healthz", token="")
check("healthz unauthenticated", status == 200 and payload["ok"] is True, (status, payload))
status, payload = call("GET", "/status", token="")
check("status needs token", status == 401, (status, payload))
status, payload = call("GET", "/status")
check("status with token", status == 200 and payload["mode"] == "idle", (status, payload))
status, payload = call("POST", "/blacklist", {"addresses": ["spam@example.com", "nope"]})
check("add via api", status == 200 and payload["added"] == ["spam@example.com"], (status, payload))
check("add rejects bad", len(payload["errors"]) == 1, payload)
status, payload = call("GET", "/blacklist")
check("list blacklist", "spam@example.com" in payload["entries"], payload)
status, payload = call("POST", "/blacklist/remove", {"addresses": ["spam@example.com"]})
check("remove via api", payload["removed"] == ["spam@example.com"], payload)
status, payload = call("GET", "/whitelist")
check("whitelist starts empty", status == 200 and payload["count"] == 0, (status, payload))
status, payload = call("POST", "/whitelist", {"addresses": ["@gmail.com", "keep@example.com"]})
check(
    "whitelist allows freemail wildcard",
    status == 200 and payload["added"] == ["@gmail.com", "keep@example.com"],
    (status, payload),
)
status, payload = call("GET", "/status")
check("status counts whitelist", payload.get("whitelist_entries") == 2, payload)
status, payload = call("POST", "/whitelist/remove", {"addresses": ["@gmail.com"]})
check("whitelist remove", payload["removed"] == ["@gmail.com"], payload)
status, payload = call("DELETE", "/whitelist/keep%40example.com")
check("whitelist delete by path", payload["removed"] == ["keep@example.com"], payload)

status, payload = call("POST", "/quarantine", {"addresses": ["move@example.com"]})
check("move setup quarantine", payload["added"] == ["move@example.com"], payload)
status, payload = call("POST", "/blacklist", {"addresses": ["move@example.com"]})
check(
    "add to blacklist removes from quarantine",
    payload["added"] == ["move@example.com"]
    and payload["removed_from"].get("quarantine") == ["move@example.com"],
    payload,
)
status, payload = call("GET", "/quarantine")
check("quarantine no longer has it", "move@example.com" not in payload["entries"], payload)

status, payload = call("POST", "/whitelist", {"addresses": ["@move.example"]})
check("move setup whitelist", payload["added"] == ["@move.example"], payload)
status, payload = call("POST", "/quarantine", {"addresses": ["@move.example"]})
check(
    "add to quarantine removes from whitelist",
    payload["removed_from"].get("whitelist") == ["@move.example"],
    payload,
)

status, payload = call("POST", "/blacklist", {"addresses": ["both@example.com"]})
check("both setup blacklist", payload["added"] == ["both@example.com"], payload)
status, payload = call("POST", "/quarantine", {"addresses": ["both@example.com"]})
check("both moved to quarantine", payload["removed_from"].get("blacklist") == ["both@example.com"], payload)
status, payload = call("POST", "/quarantine", {"addresses": ["both@example.com"]})
check(
    "repeat add is a no-op",
    payload["skipped"] == ["both@example.com"]
    and payload["removed_from"] == {},
    payload,
)

status, payload = call("POST", "/quarantine", {"addresses": ["dup@example.com"]})
check("dup setup quarantine", payload["added"] == ["dup@example.com"], payload)
blacklist.add(cfg.blacklist_path, ["dup@example.com"])
status, payload = call("POST", "/blacklist", {"addresses": ["dup@example.com"]})
check(
    "skipped target still cleans the other list",
    payload["skipped"] == ["dup@example.com"]
    and payload["removed_from"].get("quarantine") == ["dup@example.com"],
    payload,
)

status, payload = call("POST", "/whitelist", {"addresses": ["exact@keep.example"]})
check("exact setup whitelist", payload["added"] == ["exact@keep.example"], payload)
status, payload = call("POST", "/blacklist", {"addresses": ["@keep.example"]})
check(
    "domain add does not remove exact whitelist",
    payload["removed_from"] == {},
    payload,
)
status, payload = call("GET", "/whitelist")
check("exact whitelist remains", "exact@keep.example" in payload["entries"], payload)

# Clean up the exclusivity fixtures.
call("POST", "/blacklist/remove", {"addresses": ["move@example.com", "both@example.com", "dup@example.com", "@keep.example"]})
call("POST", "/quarantine/remove", {"addresses": ["@move.example", "both@example.com", "dup@example.com"]})
call("POST", "/whitelist/remove", {"addresses": ["exact@keep.example"]})
status, payload = call("GET", "/quarantine")
check(
    "quarantine starts empty with config",
    status == 200 and payload["count"] == 0 and payload["label"] == "Quarantine"
    and payload["age"] == "14 days",
    (status, payload),
)
status, payload = call("POST", "/quarantine", {"addresses": ["@gmail.com", "hold@example.com"]})
check(
    "quarantine refuses freemail wildcard",
    payload["added"] == ["hold@example.com"] and len(payload["errors"]) == 1,
    payload,
)
status, payload = call("GET", "/status")
check("status counts quarantine", payload.get("quarantine_entries") == 1, payload)
status, payload = call("POST", "/quarantine/remove", {"addresses": ["hold@example.com"]})
check("quarantine remove", payload["removed"] == ["hold@example.com"], payload)
status, payload = call("POST", "/quarantine", {"addresses": ["hold2@example.com"]})
check("quarantine add again", payload["added"] == ["hold2@example.com"], payload)
status, payload = call("DELETE", "/quarantine/hold2%40example.com")
check("quarantine delete by path", payload["removed"] == ["hold2@example.com"], payload)
status, payload = call("GET", "/nonexistent")
check("404 json", status == 404, (status, payload))
status, payload = call("POST", "/blacklist", {"addresses": "notalist"})
check("400 on bad body shape", status == 400, (status, payload))
req = urllib.request.Request(BASE + "/")
with urllib.request.urlopen(req, timeout=10) as r:
    page = r.read().decode()
check("page served", "Gmail Spam Assassin" in page)

print("background run api")
from app import runner as runner_mod  # noqa: E402

original_run = runner_mod.run_purge
original_busy = runner_mod.busy


def fake_run(cfg, dry_run=None, reason="manual", run_id=None):
    rid = run_id or "fake-run"
    state.append_audit(
        cfg.audit_path,
        {"kind": "summary", "run_id": rid, "ok": True, "dry_run": dry_run, "filed": 1},
    )
    state.update_state(cfg.state_path, last_run_id=rid, last_run=state.now_iso())
    return {"ok": True, "run_id": rid}


runner_mod.run_purge = fake_run
try:
    status, payload = call("POST", "/run", {})
    check("run accepted asynchronously", status == 202 and payload.get("accepted"), (status, payload))
    run_id = payload.get("run_id")
    found = None
    for _ in range(50):
        status, payload = call("GET", "/runs/" + (run_id or ""))
        if payload.get("found"):
            found = payload.get("run")
            break
        time.sleep(0.05)
    check("run summary retrievable", found and found.get("run_id") == run_id, found)

    runner_mod.busy = lambda: True
    status, payload = call("POST", "/run", {})
    check("busy run refused", status == 409 and payload.get("running") is True, (status, payload))
finally:
    runner_mod.run_purge = original_run
    runner_mod.busy = original_busy
    runner_mod._rerun.clear()

server.shutdown()
print("\n%d passed, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
