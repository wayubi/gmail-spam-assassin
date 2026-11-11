import json
import os
import re
import sys
import tempfile
import imaplib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import blacklist, config, imap, runner, state  # noqa: E402

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


def expand(uidset):
    out = []
    for part in str(uidset).split(","):
        if not part:
            continue
        if ":" in part:
            start, end = part.split(":", 1)
            out.extend(str(value) for value in range(int(start), int(end) + 1))
        else:
            out.append(part)
    return out


SENDERS = {
    101: "bad@spam.example",
    102: "Bad Person <bad@spam.example>",
    103: "lookalike@notspam.example",   # substring match must NOT be deleted
    104: "protected@spam.example",     # whitelisted: must NOT be deleted
}


class FakeConn:
    capabilities = (b"IMAP4REV1", b"X-GM-EXT-1")
    trash_visible = True

    def __init__(self):
        self.deleted = []
        self.stored = []
        self.copied = []
        self.selected = None

    def list(self):
        lines = [
            b'(\\HasNoChildren) "/" "[Gmail]/All Mail"',
            b'(\\HasNoChildren) "/" "[Gmail]/Spam"',
            b'(\\HasNoChildren) "/" "INBOX"',
        ]
        if self.trash_visible:
            lines.append(b'(\\HasNoChildren) "/" "[Gmail]/Trash"')
        return "OK", lines

    def select(self, mailbox, readonly=False):
        self.selected = mailbox
        return "OK", [b"3"]

    def uid(self, command, *args):
        if command == "SEARCH":
            return "OK", [b"101 102 103"]
        if command == "FETCH":
            data = []
            for uid in args[0].split(","):
                uid = int(uid)
                headers = ("From: %s\r\nSubject: hello %d\r\n\r\n" % (SENDERS[uid], uid)).encode()
                meta = (
                    '1 (UID %d X-GM-MSGID %d X-GM-LABELS ("\\\\Inbox") '
                    'INTERNALDATE " 9-Nov-2026 04:00:00 -0800" '
                    "BODY[HEADER.FIELDS (FROM SUBJECT)] {%d}" % (uid, 9000 + uid, len(headers))
                ).encode()
                data.append((meta, headers))
            return "OK", data
        if command == "COPY":
            self.copied.append((args[0], args[1]))
            return "OK", [b""]
        if command == "STORE":
            self.stored.extend(args[0].split(","))
            return "OK", [b""]
        if command == "EXPUNGE":
            self.deleted.extend(args[0].split(","))
            return "OK", [b""]
        return "OK", [b""]

    def close(self):
        pass

    def logout(self):
        pass


tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "blacklist.txt")
blacklist.ensure(path)
blacklist.add(path, ["@spam.example"])

os.environ.update(
    GMAIL_USER="a@b.com",
    GMAIL_APP_PASSWORD="abcdefghijklmnop",
    SPAM_API_TOKEN="x" * 24,
    DATA_DIR=tmp,
    MODE="poll",
    DRY_RUN="true",
    MAX_DELETE_PER_RUN="500",
)

cfg = config.load()
imap.connect = lambda user, password, timeout=60: FakeConn()

print("dry run")
res = runner.run_purge(cfg, dry_run=True, reason="test")
check("dry run ok", res["ok"] is True, res)
check("dry run matched 4 (2 real x 2 mailboxes)", res["matched"] == 4, res["matched"])
check("dry run deletes nothing", res["trashed"] == 0, res["trashed"])
check("dry run would trash 4", res["would_trash"] == 4, res["would_trash"])
check("lookalike not counted", res["matched"] == 4, res["matched"])

lines = state.tail_jsonl(cfg.audit_path, 100)
messages = [line for line in lines if line.get("kind") == "message"]
check("audit has 4 messages", len(messages) == 4, len(messages))
check("audit action would-trash", all(m["action"] == "would-trash" for m in messages))
check("audit has no bodies", all("body" not in m for m in messages))
check("summary recorded", any(line.get("kind") == "summary" for line in lines))

print("live run")
conn = FakeConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(cfg, dry_run=False, reason="test")
check("live ok", res["ok"] is True, res)
check("live trashed 4", res["trashed"] == 4, res["trashed"])
check("live would_trash 0", res["would_trash"] == 0, res["would_trash"])
check("two mailboxes", res["mailboxes"] == ["[Gmail]/All Mail", "[Gmail]/Spam"], res["mailboxes"])
check("trash resolved", res.get("trash") == "[Gmail]/Trash", res.get("trash"))
check("copied into Trash", conn.copied and all(dst == '"[Gmail]/Trash"' for _src, dst in conn.copied), conn.copied)
check("copied all 4", sum(len(expand(src)) for src, _dst in conn.copied) == 4, conn.copied)
check("never expunged", conn.deleted == [], conn.deleted)
check("never flagged deleted", conn.stored == [], conn.stored)

lines = state.tail_jsonl(cfg.audit_path, 100)
actions = [line["action"] for line in lines if line.get("kind") == "message"]
check("audit trashed 4", actions.count("trashed") == 4, actions)

print("trash hidden")
hidden = FakeConn()
hidden.trash_visible = False
imap.connect = lambda user, password, timeout=60: hidden
res = runner.run_purge(cfg, dry_run=True, reason="test")
check("dry run survives hidden Trash", res["ok"] is True, res)
check(
    "dry run warns about Trash",
    any("Trash" in w for w in res["warnings"]),
    res["warnings"],
)
imap.connect = lambda user, password, timeout=60: hidden
res = runner.run_purge(cfg, dry_run=False, reason="test")
check("live refuses without Trash", res["ok"] is False, res)
check(
    "refusal names Trash",
    any("Trash" in e for e in res["errors"]),
    res["errors"],
)
check("refusal copied nothing", hidden.copied == [], hidden.copied)

print("rerun mode")
calls = []
original_once = runner._run_once
runner._run_once = lambda cfg, dry_run=None, reason="manual", run_id=None: (
    calls.append(dry_run),
    {"ok": True},
)[1]
runner._rerun.set()
runner.run_purge(cfg, dry_run=False)
check("rerun uses config default", calls == [False, None], calls)
runner._run_once = original_once
runner._rerun.clear()

print("cap")
blacklist.add(path, ["second@spam.example"])
cfg2 = config.load()
cfg2 = cfg2.__class__(**{**cfg2.__dict__, "max_delete_per_run": 2, "max_trash_per_run": 2})
conn = FakeConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(cfg2, dry_run=False, reason="test")
check("cap respected", res["trashed"] == 2, res["trashed"])
check("cap flagged", res["capped"] is True, res["capped"])


class WhitelistConn(FakeConn):
    """Same mailbox, but the search also returns the whitelisted sender."""

    def uid(self, command, *args):
        if command == "SEARCH":
            return "OK", [b"101 102 104"]
        return FakeConn.uid(self, command, *args)


def reset_whitelist(entries):
    with open(cfg.whitelist_path, "w", encoding="utf-8") as handle:
        handle.write("# test\n" + "\n".join(entries) + "\n")


print("whitelist")
reset_whitelist(["protected@spam.example", "@notspam.example"])
conn = WhitelistConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(cfg, dry_run=False, reason="test")
check("whitelist run ok", res["ok"] is True, res)
check("whitelist counted", res["whitelisted"] == 2, res.get("whitelisted"))
check("whitelisted suppressed", res["suppressed"] == 2, res["suppressed"])
check("non-whitelisted still trashed", res["trashed"] == 4, res["trashed"])
copied = [uid for src, _dst in conn.copied for uid in expand(src)]
check("whitelisted never copied", "104" not in copied, copied)
check("others copied", sorted(copied) == ["101", "101", "102", "102"], copied)

print("whitelist beats blacklist")
reset_whitelist(["@spam.example"])
conn = WhitelistConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(cfg, dry_run=False, reason="test")
check("nothing deleted", res["trashed"] == 0 and res["matched"] == 0, res)
check("all suppressed", res["suppressed"] == 6, res["suppressed"])
check("no copy issued", conn.copied == [], conn.copied)
check(
    "overlap warned",
    any("both lists" in w for w in res["warnings"]),
    res["warnings"],
)

print("listing hides whitelist")
from app import listing  # noqa: E402

reset_whitelist(["@notspam.example"])
connections = []


def connect_counts(user, password, timeout=60):
    connections.append(1)
    return FakeConn()


imap.connect = connect_counts
listing.reset()
data = listing.messages(cfg, 30, 100, "all")
check("listing opened one connection", len(connections) == 1, connections)
addresses = [row["from_addr"] for row in data["messages"]]
check("whitelisted row hidden", "lookalike@notspam.example" not in addresses, addresses)
check("hidden counted", data["hidden"] == 1, data["hidden"])
check("other rows kept", len(addresses) == 2, addresses)
groups = listing.senders(cfg, 30, 50)
check("senders hide whitelist too", [g["address"] for g in groups["senders"]] == ["bad@spam.example"], groups)
check("senders hidden counted", groups["hidden"] == 1, groups["hidden"])
check("senders shared the raw cache", len(connections) == 1, connections)

blacklist.add(path, ["bad@spam.example"])
data = listing.messages(cfg, 30, 100, "all")
check("list edit did not refetch", len(connections) == 1, connections)
check(
    "list edit updated the flag",
    any(row["blacklisted"] == "bad@spam.example" for row in data["messages"]),
    data["messages"],
)
listing.invalidate()
data = listing.messages(cfg, 30, 100, "all")
check("invalidate kept the connection", len(connections) == 1, connections)

print("listing generation guard")
calls = []


def producer():
    calls.append(1)
    listing.invalidate()
    return "value"


first = listing._cached(("generation-test",), producer)
second = listing._cached(("generation-test",), producer)
check("generation discards the stale store", first == "value" and second == "value" and len(calls) == 2, calls)
listing.reset()

print("listing connection retry")
class AbortConn(FakeConn):
    def uid(self, command, *args):
        if command == "SEARCH":
            raise imaplib.IMAP4.abort("gone")
        return FakeConn.uid(self, command, *args)

attempts = []
def connect_abort(user, password, timeout=60):
    attempts.append(1)
    return AbortConn() if len(attempts) == 1 else FakeConn()

imap.connect = connect_abort
listing.reset()
data = listing.messages(cfg, 30, 10, "all")
check("listing retried once", len(attempts) == 2, attempts)
check("listing returned rows after retry", data["count"] >= 1, data["count"])
listing.reset()

print("listing stale shutdown")
class StaleConn(FakeConn):
    def __init__(self):
        FakeConn.__init__(self)
        self.shutdowns = 0
        self.closes = 0

    def shutdown(self):
        self.shutdowns += 1

    def close(self):
        self.closes += 1
        raise AssertionError("close should not be called on a stale connection")


stale = StaleConn()
listing._conn = stale
listing._conn_key = (cfg.gmail_user, cfg.gmail_password)
listing._conn_last_used = 0
imap.connect = lambda user, password, timeout=60: FakeConn()
data = listing.messages(cfg, 30, 10, "all")
check("stale connection shut down", stale.shutdowns == 1, stale.shutdowns)
check("stale connection not closed politely", stale.closes == 0, stale.closes)
check("stale connection replaced", data["count"] >= 1, data["count"])
listing.reset()

print("quarantine")
from datetime import datetime, timezone  # noqa: E402

from app import age, quarantine  # noqa: E402

OLD = "01-Oct-2026 00:00:00 +0000"
NEW = "10-Nov-2026 00:00:00 +0000"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def qmsg(address, when, labels, msgid, subject):
    return {"from": address, "when": when, "labels": labels, "msgid": msgid, "subject": subject}


class QuarantineConn:
    capabilities = (b"IMAP4REV1", b"X-GM-EXT-1")
    label_visible = True
    create_ok = True

    def __init__(self):
        self.selected = None
        self.stored = []
        self.copied = []
        self.queries = []
        self.created = []
        self.before = []
        self.fetches = []
        self.all_mail = {
            101: qmsg("old@q.example", OLD, ["\\Inbox"], 8101, "old from"),
            102: qmsg("new@q.example", NEW, ["\\Inbox"], 8102, "new from"),
            103: qmsg("keep@q.example", NEW, ["\\Inbox"], 8103, "kept"),
            104: qmsg("other@spam.example", NEW, ["\\Inbox"], 8104, "other"),
        }
        self.label_box = {
            201: qmsg("old@q.example", OLD, ["Quarantine"], 8201, "held old"),
            202: qmsg("new@q.example", NEW, ["Quarantine"], 8202, "held new"),
            203: qmsg("gone@other.example", OLD, ["Quarantine"], 8203, "stale"),
            204: qmsg("keep@q.example", OLD, ["Quarantine"], 8204, "held whitelisted"),
        }
        self.spam = {}

    def list(self):
        names = [
            '(\\HasNoChildren) "/" "[Gmail]/All Mail"',
            '(\\HasNoChildren) "/" "[Gmail]/Spam"',
            '(\\HasNoChildren) "/" "[Gmail]/Trash"',
            '(\\HasNoChildren) "/" "INBOX"',
        ]
        if self.label_visible:
            names.append('(\\HasNoChildren) "/" "Quarantine"')
        return "OK", [name.encode() for name in names]

    def select(self, mailbox, readonly=False):
        self.selected = mailbox.strip('"')
        return "OK", [b"1"]

    def create(self, mailbox):
        self.created.append(mailbox)
        if not self.create_ok:
            return "NO", [b"[CANNOT] invalid mailbox name"]
        self.label_visible = True
        return "OK", [b"Success"]

    def status(self, mailbox, names):
        name = mailbox.strip('"')
        box = {
            "[Gmail]/All Mail": self.all_mail,
            "Quarantine": self.label_box,
            "[Gmail]/Spam": self.spam,
            "INBOX": self.all_mail,
        }.get(name, {})
        return "OK", [('"%s" (MESSAGES %d)' % (name, len(box))).encode()]

    def _box(self):
        return {
            "[Gmail]/All Mail": self.all_mail,
            "Quarantine": self.label_box,
            "[Gmail]/Spam": self.spam,
            "INBOX": self.all_mail,
        }.get(self.selected, {})

    def uid(self, command, *args):
        if command == "SEARCH":
            box = self._box()
            if args == ("ALL",):
                uids = sorted(box)
            elif args and args[0] == "BEFORE":
                self.before.append(args[1])
                limit = datetime.strptime(args[1], "%d-%b-%Y").date()
                uids = sorted(
                    uid
                    for uid, meta in box.items()
                    if datetime.strptime(
                        meta["when"], "%d-%b-%Y %H:%M:%S %z"
                    ).date()
                    < limit
                )
            elif args and args[0] == "UID":
                start = int(args[1].split(":", 1)[0])
                uids = sorted(uid for uid in box if uid >= start)
            else:
                query = args[-1].strip('"')
                self.queries.append(query)
                terms = re.findall(r"from:([^\s}]+)", query)
                uids = sorted(
                    uid
                    for uid, meta in box.items()
                    if any(
                        meta["from"].lower() == term
                        or meta["from"].lower().endswith("@" + term)
                        for term in terms
                    )
                )
            return "OK", [" ".join(str(uid) for uid in uids).encode()]
        if command == "FETCH":
            self.fetches.append((self.selected, args[0]))
            box = self._box()
            data = []
            for uid in [int(value) for value in args[0].split(",")]:
                meta = box.get(uid)
                if not meta:
                    continue
                headers = (
                    "From: %s\r\nSubject: %s\r\n\r\n"
                    % (meta["from"], meta["subject"])
                ).encode()
                labels = " ".join(
                    '"%s"' % name.replace("\\", "\\\\") for name in meta["labels"]
                )
                text = (
                    '1 (UID %d X-GM-MSGID %d X-GM-LABELS (%s) '
                    'INTERNALDATE "%s" '
                    "BODY[HEADER.FIELDS (FROM SUBJECT)] {%d}"
                    % (uid, meta["msgid"], labels, meta["when"], len(headers))
                ).encode()
                data.append((text, headers))
            return "OK", data
        if command == "STORE":
            self.stored.append((self.selected, args[0], args[1], args[2] if len(args) > 2 else ""))
            if len(args) > 2:
                values = re.findall(r'"((?:[^"\\]|\\.)*)"', args[2])
                values = [value.replace("\\\\", "\\") for value in values]
                box = self._box()
                for uid in expand(args[0]):
                    meta = box.get(int(uid))
                    if meta is None:
                        continue
                    if args[1] == "+X-GM-LABELS":
                        for value in values:
                            if value not in meta["labels"]:
                                meta["labels"].append(value)
                    elif args[1] == "-X-GM-LABELS":
                        meta["labels"] = [
                            label for label in meta["labels"] if label not in values
                        ]
            return "OK", [b""]
        if command == "COPY":
            box = self._box()
            for uid in expand(args[0]):
                box.pop(int(uid), None)
            self.copied.append((self.selected, args[0], args[1]))
            return "OK", [b""]
        return "OK", [b""]

    def close(self):
        pass

    def logout(self):
        pass


class PartialConn(QuarantineConn):
    """A blacklisted domain with one quarantined sender inside it."""

    def __init__(self):
        QuarantineConn.__init__(self)
        for box in (self.all_mail, self.spam):
            box[107] = qmsg("one@spam.example", NEW, ["\\Inbox"], 8107, "held one")
            box[108] = qmsg("two@spam.example", NEW, ["\\Inbox"], 8108, "trashed two")

    def uid(self, command, *args):
        if command == "SEARCH":
            return "OK", [b"107 108"]
        return QuarantineConn.uid(self, command, *args)


def reset_list(path, entries):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# test\n" + "".join(entry + "\n" for entry in entries))


reset_list(path, [])
reset_list(cfg.whitelist_path, ["keep@q.example"])
reset_list(cfg.quarantine_path, ["@q.example"])
qcfg = cfg.__class__(**{**cfg.__dict__, "quarantine_age": age.Age(14, "d")})
runner._now = lambda: NOW

conn = QuarantineConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=False, reason="test")
check("quarantine run ok", res["ok"] is True, res)
check("run summary kept in memory", runner.get_run(res["run_id"]) is not None)
check("one entry counted", res["quarantine_entries"] == 1, res)
check("new mail filed", res["filed"] == 1, res["filed"])
check("two messages expired", res["expired"] == 2, res["expired"])
check("held counted", res["held"] == 3, res["held"])
check("due search used the cutoff", conn.before == ["29-Oct-2026"], conn.before)
check(
    "young held mail never fetched",
    all("202" not in uids.split(",") for box, uids in conn.fetches if box == "Quarantine"),
    conn.fetches,
)
check("stale label mail reported", res["quarantine_stale"] == 1, res["quarantine_stale"])
check("whitelist suppressed both copies", res["suppressed"] == 2, res["suppressed"])
check("lookalike untouched", all("104" not in item[1] for item in conn.stored + conn.copied), conn.stored)
label_stores = [item for item in conn.stored if item[2] == "+X-GM-LABELS"]
inbox_stores = [item for item in conn.stored if item[2] == "-X-GM-LABELS"]
check("filed with the label", label_stores and label_stores[0][1] == "102" and "Quarantine" in label_stores[0][3], conn.stored)
check("taken out of inbox", inbox_stores and inbox_stores[0][1] == "102" and "Inbox" in inbox_stores[0][3], conn.stored)
sources = sorted(item[0] for item in conn.copied)
check("expired from label and all mail", sources == ["Quarantine", "[Gmail]/All Mail"], conn.copied)
check("all copies go to trash", all(item[2] == '"[Gmail]/Trash"' for item in conn.copied), conn.copied)
check(
    "search excludes the label",
    any("-label:" in query for query in conn.queries),
    conn.queries,
)

print("quarantine search batching")
reset_list(path, [])
reset_list(cfg.whitelist_path, [])
reset_list(cfg.quarantine_path, ["@q.example", "new@q.example"])
conn = QuarantineConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=True, reason="test")
check(
    "one query carried both senders",
    any(query.count("from:") >= 2 for query in conn.queries),
    conn.queries,
)
check(
    "old and young queries were split",
    any("older_than:14d" in query for query in conn.queries)
    and any("newer_than:14d" in query for query in conn.queries),
    conn.queries,
)
check("batched run still planned files", res["would_file"] >= 1, res["would_file"])

print("quarantine beats blacklist")
reset_list(path, ["@q.example"])
reset_list(cfg.whitelist_path, ["keep@q.example"])
reset_list(cfg.quarantine_path, ["@q.example"])
conn = QuarantineConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=False, reason="test")
check("blacklist entry skipped", res["blacklist_skipped"] == 1, res)
check(
    "overlap warned",
    any("quarantine wins" in warning for warning in res["warnings"]),
    res["warnings"],
)
check("no blacklist trash", res["trashed"] == 0, res["trashed"])
check("quarantine still filed", res["filed"] == 1, res["filed"])

print("quarantine wins per message inside a blacklisted domain")
reset_list(path, ["@spam.example"])
reset_list(cfg.whitelist_path, [])
reset_list(cfg.quarantine_path, ["one@spam.example"])
conn = PartialConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=False, reason="test")
check("partial entry is not skipped", res["blacklist_skipped"] == 0, res["blacklist_skipped"])
check("quarantined sender held back", res["suppressed"] == 2, res["suppressed"])
check("other sender in the domain trashed", res["trashed"] == 2, res["trashed"])
copied = [uid for _src, uids, _dst in conn.copied for uid in expand(uids)]
check("quarantined UID never copied", "107" not in copied, copied)
check("other UID copied from both mailboxes", copied.count("108") == 2, copied)
check(
    "partial overlap warned",
    any("overlaps quarantine" in warning for warning in res["warnings"]),
    res["warnings"],
)

print("quarantine dry run")
reset_list(path, [])
reset_list(cfg.whitelist_path, ["keep@q.example"])
reset_list(cfg.quarantine_path, ["@q.example"])
conn = QuarantineConn()
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=True, reason="test")
check("dry would file one", res["would_file"] == 1, res["would_file"])
check("dry would expire two", res["would_expire"] == 2, res["would_expire"])
check("dry counts all held", res["held"] == 4, res["held"])
check("dry stores nothing", conn.stored == [], conn.stored)
check("dry copies nothing", conn.copied == [], conn.copied)

print("quarantine abort brake")
qcfg_abort = qcfg.__class__(**{**qcfg.__dict__, "quarantine_abort_over": 1})
conn = QuarantineConn()
conn.all_mail[105] = qmsg("old2@q.example", OLD, ["\\Inbox"], 8105, "old2")
conn.all_mail[106] = qmsg("old3@q.example", OLD, ["\\Inbox"], 8106, "old3")
conn.label_box[205] = qmsg("old2@q.example", OLD, ["Quarantine"], 8205, "held old2")
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg_abort, dry_run=False, reason="test")
check("abort deleted nothing", res["expired"] == 0 and conn.copied == [], (res["expired"], conn.copied))
check(
    "abort named the setting",
    any("QUARANTINE_ABORT_OVER" in warning for warning in res["warnings"]),
    res["warnings"],
)
check("abort still filed new mail", res["filed"] == 1, res["filed"])
check("abort kept the label intact", res["held"] == 5, res["held"])

print("quarantine label created on demand")
conn = QuarantineConn()
conn.label_visible = False
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=False, reason="test")
check("label created", res["quarantine_created"] is True, res)
check("create used the configured name", conn.created == ['"Quarantine"'], conn.created)
check("run continued after create", res["filed"] == 1 and res["expired"] == 2, res)
check("created run counted the label", res["held"] == 3, res["held"])
check("create produced no errors", res["errors"] == [], res["errors"])

print("quarantine label creation refused")
conn = QuarantineConn()
conn.label_visible = False
conn.create_ok = False
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=False, reason="test")
check(
    "refused create is reported",
    any("could not create" in error for error in res["errors"]),
    res["errors"],
)
check("refused create filed nothing", conn.stored == [], conn.stored)
check("refused create deleted nothing", conn.copied == [], conn.copied)

print("quarantine cutoff day boundary")
reset_list(path, [])
reset_list(cfg.whitelist_path, ["keep@q.example"])
reset_list(cfg.quarantine_path, ["@q.example"])
conn = QuarantineConn()
# Same day as the cutoff (28 Oct), but after the 12:00 cutoff instant.
conn.label_box[206] = qmsg(
    "new@q.example", "28-Oct-2026 18:00:00 +0000", ["Quarantine"], 8206, "after cutoff"
)
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_purge(qcfg, dry_run=False, reason="test")
fetched = [uids.split(",") for box, uids in conn.fetches if box == "Quarantine"]
check(
    "day-granular search includes the cutoff day",
    any("206" in chunk for chunk in fetched),
    fetched,
)
copied = [
    uid for box, uids, _dst in conn.copied if box == "Quarantine" for uid in expand(uids)
]
check("nothing on the cutoff day was deleted early", "206" not in copied, copied)
check("boundary run still expired the older one", res["expired"] == 2, res["expired"])
check("boundary message counted as held", res["held"] == 4, res["held"])

print("quarantine bulk due drains across runs")
reset_list(path, [])
reset_list(cfg.whitelist_path, [])
reset_list(cfg.quarantine_path, ["@q.example"])
saved_ceiling = runner.FETCH_CEILING
runner.FETCH_CEILING = 1
try:
    conn = QuarantineConn()
    conn.label_box = {
        201: qmsg("old@q.example", OLD, ["Quarantine"], 8201, "held old"),
        207: qmsg("old@q.example", OLD, ["Quarantine"], 8207, "held old 2"),
    }
    conn.all_mail = {102: qmsg("new@q.example", NEW, ["\\Inbox"], 8102, "new from")}
    imap.connect = lambda user, password, timeout=60: conn
    first = runner.run_purge(qcfg, dry_run=False, reason="test")
    second = runner.run_purge(qcfg, dry_run=False, reason="test")
    check("first run drains one due", first["expired"] == 1, first["expired"])
    check("second run drains the next", second["expired"] == 1, second["expired"])
    check(
        "both were drained from the same due query",
        first["expired"] + second["expired"] == 2,
        (first["expired"], second["expired"]),
    )
    check("label empties", second["held"] == 0, second["held"])
finally:
    runner.FETCH_CEILING = saved_ceiling

print("rotating quarantine batches")
saved_batch = runner.SEARCH_BATCH
saved_file = runner.FILE_CEILING
runner.SEARCH_BATCH = 1
runner.FILE_CEILING = 2
try:
    conn = QuarantineConn()
    conn.all_mail = {
        301: qmsg("one@one.example", NEW, ["\\Inbox"], 8301, "one a"),
        302: qmsg("one@one.example", NEW, ["\\Inbox"], 8302, "one b"),
        303: qmsg("two@two.example", NEW, ["\\Inbox"], 8303, "two a"),
        304: qmsg("two@two.example", NEW, ["\\Inbox"], 8304, "two b"),
        305: qmsg("three@three.example", NEW, ["\\Inbox"], 8305, "three a"),
        306: qmsg("three@three.example", NEW, ["\\Inbox"], 8306, "three b"),
    }
    conn.label_box = {}
    conn.spam = {}
    reset_list(path, [])
    reset_list(cfg.whitelist_path, [])
    reset_list(
        cfg.quarantine_path,
        ["@one.example", "@two.example", "@three.example"],
    )
    state.update_state(cfg.state_path, quarantine_batch_offset=0)
    imap.connect = lambda user, password, timeout=60: conn
    runner._rerun.clear()
    offsets = []
    filed = []
    stores = []
    for _ in range(3):
        before = len(conn.stored)
        res = runner.run_purge(qcfg, dry_run=False, reason="test")
        filed.append(res["filed"])
        offsets.append(state.read_state(cfg.state_path).get("quarantine_batch_offset"))
        new_stores = conn.stored[before:]
        stores.append(
            [
                uid
                for item in new_stores
                if item[2] == "+X-GM-LABELS"
                for uid in expand(item[1])
            ]
        )
    check("each run files its share", filed == [2, 2, 2], filed)
    check("cursor advances", offsets == [1, 2, 0], offsets)
    check(
        "each sender batch was filed",
        stores == [["301", "302"], ["303", "304"], ["305", "306"]],
        stores,
    )
finally:
    runner.SEARCH_BATCH = saved_batch
    runner.FILE_CEILING = saved_file

print("rotating blacklist batches")
runner.SEARCH_BATCH = 1
try:
    conn = QuarantineConn()
    conn.all_mail = {
        401: qmsg("one@one.example", NEW, ["\\Inbox"], 8401, "one"),
        402: qmsg("two@two.example", NEW, ["\\Inbox"], 8402, "two"),
        403: qmsg("three@three.example", NEW, ["\\Inbox"], 8403, "three"),
    }
    conn.label_box = {}
    conn.spam = {}
    reset_list(path, ["@one.example", "@two.example", "@three.example"])
    reset_list(cfg.whitelist_path, [])
    reset_list(cfg.quarantine_path, [])
    state.update_state(cfg.state_path, blacklist_batch_offset=0)
    bcfg = qcfg.__class__(**{**qcfg.__dict__, "max_trash_per_run": 1})
    imap.connect = lambda user, password, timeout=60: conn
    runner._rerun.clear()
    offsets = []
    copied = []
    trashed = []
    for _ in range(3):
        before = len(conn.copied)
        res = runner.run_purge(bcfg, dry_run=False, reason="test")
        trashed.append(res["trashed"])
        offsets.append(state.read_state(cfg.state_path).get("blacklist_batch_offset"))
        copied.append([uid for _src, uids, _dst in conn.copied[before:] for uid in expand(uids)])
    check("blacklist cursor advances", offsets == [1, 2, 0], offsets)
    check("one blacklist deletion per run", trashed == [1, 1, 1], trashed)
    check("each blacklist batch was reached", copied == [["401"], ["402"], ["403"]], copied)
finally:
    runner.SEARCH_BATCH = saved_batch

print("blacklist mid-batch resume")
runner.SEARCH_BATCH = 1
try:
    conn = QuarantineConn()
    conn.all_mail = {501: qmsg("one@one.example", NEW, ["\\Inbox"], 8501, "one")}
    conn.spam = {502: qmsg("one@one.example", NEW, ["\\Inbox"], 8502, "one spam")}
    conn.label_box = {}
    reset_list(path, ["@one.example"])
    reset_list(cfg.whitelist_path, [])
    reset_list(cfg.quarantine_path, [])
    state.update_state(cfg.state_path, blacklist_batch_offset=0)
    bcfg = qcfg.__class__(**{**qcfg.__dict__, "max_trash_per_run": 1})
    imap.connect = lambda user, password, timeout=60: conn
    runner._rerun.clear()
    first = runner.run_purge(bcfg, dry_run=False, reason="test")
    offset1 = state.read_state(cfg.state_path).get("blacklist_batch_offset")
    mailbox1 = state.read_state(cfg.state_path).get("blacklist_mailbox_offset")
    second = runner.run_purge(bcfg, dry_run=False, reason="test")
    offset2 = state.read_state(cfg.state_path).get("blacklist_batch_offset")
    mailbox2 = state.read_state(cfg.state_path).get("blacklist_mailbox_offset")
    copied = [uid for _src, uids, _dst in conn.copied for uid in expand(uids)]
    check("one batch keeps the batch cursor", offset1 == 0 and offset2 == 0, (offset1, offset2))
    check("mailbox order rotates", (mailbox1, mailbox2) == (1, 0), (mailbox1, mailbox2))
    check("both mailboxes were used", copied == ["501", "502"], copied)
finally:
    runner.SEARCH_BATCH = saved_batch
    imap.connect = lambda user, password, timeout=60: QuarantineConn()

print("skipped run record")
skipped = runner.record_skipped(qcfg, "skip-test", "another run is already in progress", True)
check("skipped summary stored", runner.get_run("skip-test") is not None, skipped)
check("skipped summary marked", skipped.get("ok") is False and skipped.get("skipped"), skipped)

print("incremental new-mail run")
reset_list(path, ["@spam.example"])
reset_list(cfg.whitelist_path, [])
reset_list(cfg.quarantine_path, ["@q.example"])
conn = QuarantineConn()
conn.all_mail[109] = qmsg("new@q.example", NEW, ["\\Inbox"], 8109, "new arrival")
conn.all_mail[110] = qmsg("bad@spam.example", NEW, ["\\Inbox"], 8110, "black arrival")
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_new_mail(
    qcfg, since_uid=109, uidvalidity=None, dry_run=False, reason="test"
)
check("incremental ok", res["ok"] is True and not res.get("fallback"), res)
check("incremental filed one", res["filed"] == 1, res["filed"])
check("incremental trashed one", res["trashed"] == 1, res["trashed"])
check("incremental advanced uidnext", res.get("uidnext") == 111, res.get("uidnext"))
stored = [item for item in conn.stored if item[2] == "+X-GM-LABELS"]
check("incremental label store", stored and stored[0][1] == "109", conn.stored)
copied = [uid for _src, uids, _dst in conn.copied for uid in expand(uids)]
check("incremental copy", "110" in copied and "109" not in copied, copied)

print("incremental UIDVALIDITY fallback")
conn = QuarantineConn()
conn.untagged_responses = {"UIDVALIDITY": [b"123"]}
imap.connect = lambda user, password, timeout=60: conn
res = runner.run_new_mail(qcfg, since_uid=109, uidvalidity=456, dry_run=True)
check("uidvalidity change falls back", res.get("fallback") is True, res)

print("idle uid bookkeeping")
from app import main as main_mod  # noqa: E402

check(
    "reconnect keeps the old cursor",
    main_mod._uid_reconnect_state(100, 1, 120, 1) == (100, 1, False),
    main_mod._uid_reconnect_state(100, 1, 120, 1),
)
check(
    "first connect initialises",
    main_mod._uid_reconnect_state(None, None, 120, 1) == (120, 1, False),
    main_mod._uid_reconnect_state(None, None, 120, 1),
)
check(
    "uidvalidity change resets and sweeps",
    main_mod._uid_reconnect_state(100, 1, 120, 2) == (120, 2, True),
    main_mod._uid_reconnect_state(100, 1, 120, 2),
)
check(
    "failed run does not advance",
    main_mod._next_uidnext({"ok": False, "uidnext": 999}, 100) == 100,
)
check(
    "dry run advances",
    main_mod._next_uidnext({"ok": True, "dry_run": True, "uidnext": 999}, 100) == 999,
)
check(
    "errors do not advance",
    main_mod._next_uidnext(
        {"ok": True, "dry_run": False, "errors": ["x"], "uidnext": 999}, 100
    )
    == 100,
)
check(
    "successful run advances",
    main_mod._next_uidnext({"ok": True, "dry_run": False, "uidnext": 999}, 100) == 999,
)

print("no blacklist")
empty = os.path.join(tmp, "empty.txt")
blacklist.ensure(empty)
cfg3 = cfg2.__class__(**{**cfg2.__dict__, "blacklist_path": empty}) if False else cfg2
print("\n%d passed, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
