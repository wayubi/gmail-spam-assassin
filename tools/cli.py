#!/usr/bin/env python3
"""spam-assassin: command line client for the container's own API.

    docker exec gmail-spam-assassin spam-assassin status
    docker exec gmail-spam-assassin spam-assassin senders --days 7
    docker exec gmail-spam-assassin spam-assassin add someone@example.com @spam.example
    docker exec gmail-spam-assassin spam-assassin rm someone@example.com
    docker exec gmail-spam-assassin spam-assassin hold someone@example.com @spam.example
    docker exec gmail-spam-assassin spam-assassin release someone@example.com
    docker exec gmail-spam-assassin spam-assassin run --live

Uses SPAM_API_URL (default http://127.0.0.1:8080) and SPAM_API_TOKEN, both set
in the container environment.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8080"


def request(method, path, body=None, timeout=180):
    base = os.environ.get("SPAM_API_URL", DEFAULT_URL).rstrip("/")
    token = os.environ.get("SPAM_API_TOKEN", "")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("X-Api-Token", token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:
            payload = {"error": "HTTP %s" % exc.code}
        fail(payload)
    except urllib.error.URLError as exc:
        fail({"error": "cannot reach %s: %s" % (base, exc.reason)})
    except ValueError as exc:
        fail({"error": "bad JSON from API: %s" % exc})


def fail(payload):
    print(json.dumps(payload, indent=2), file=sys.stderr)
    sys.exit(1)


def short(text, width):
    text = "" if text is None else str(text)
    return text if len(text) <= width else text[: width - 1] + "…"


def show_status(data):
    state = data.get("state") or {}
    print("mode          %s" % data.get("mode"))
    print("dry run       %s" % ("yes (nothing is deleted)" if data.get("dry_run") else "no"))
    print("running       %s" % data.get("running"))
    print("blacklist     %s entries" % data.get("blacklist_entries"))
    print("whitelist     %s entries" % data.get("whitelist_entries"))
    print(
        "quarantine    %s entries · %s held · expires older than %s (%s)"
        % (
            data.get("quarantine_entries"),
            state.get("last_held", "–"),
            data.get("quarantine_cutoff"),
            data.get("quarantine_age"),
        )
    )
    print("label         %s" % data.get("quarantine_label"))
    print("watcher       %s" % state.get("watcher"))
    print("last run      %s (%s, ok=%s)" % (state.get("last_run"), state.get("last_reason"), state.get("last_ok")))
    print("last result   matched=%s suppressed=%s trashed=%s would_trash=%s "
          "filed=%s expired=%s held=%s capped=%s"
          % (state.get("last_matched"), state.get("last_suppressed"),
             state.get("last_trashed"), state.get("last_would_trash"),
             state.get("last_filed"), state.get("last_expired"),
             state.get("last_held"), state.get("last_capped")))
    if state.get("last_error"):
        print("last error    %s" % state["last_error"])
    for error in data.get("blacklist_errors") or []:
        print("blacklist line %s: %s (%s)" % (error["line"], error["entry"], error["reason"]))
    for error in data.get("quarantine_errors") or []:
        print("quarantine line %s: %s (%s)" % (error["line"], error["entry"], error["reason"]))


def show_messages(data):
    rows = data.get("messages") or []
    print("%-20s  %-34s  %-46s  %s" % ("date", "from", "subject", "flags"))
    for row in rows:
        flags = []
        if row.get("blacklisted"):
            flags.append("blacklisted")
        if row.get("quarantined"):
            flags.append("quarantine")
        if row.get("folder") == "Spam":
            flags.append("spam")
        print(
            "%-20s  %-34s  %-46s  %s"
            % (
                short(row.get("date"), 20),
                short(row.get("from_addr") or row.get("from_name"), 34),
                short(row.get("subject"), 46),
                ",".join(flags),
            )
        )
    print("\n%d message(s), last %s day(s)" % (data.get("count", 0), data.get("days")))
    if data.get("hidden"):
        print("%d hidden by whitelist" % data["hidden"])
    for warning in data.get("warnings") or []:
        print("warning: %s" % warning)


def show_senders(data):
    rows = data.get("senders") or []
    print("%-4s  %-40s  %-8s  %-20s  %s" % ("#", "address", "count", "latest", "subject"))
    for index, row in enumerate(rows, 1):
        marker = "*" if row.get("blacklisted") else ("+" if row.get("quarantined") else " ")
        print(
            "%s%-3d  %-40s  %-8s  %-20s  %s"
            % (
                marker,
                index,
                short(row.get("address"), 40),
                row.get("count"),
                short(row.get("latest_date"), 20),
                short(row.get("latest_subject"), 50),
            )
        )
    print("\n%d sender(s); * = already blacklisted, + = in quarantine" % data.get("count", 0))
    if data.get("hidden"):
        print("%d sender(s) hidden by whitelist" % data["hidden"])
    for warning in data.get("warnings") or []:
        print("warning: %s" % warning)


def show_blacklist(data):
    for entry in data.get("entries") or []:
        print(entry)
    print("\n%d entr%s in %s"
          % (data.get("count", 0), "y" if data.get("count") == 1 else "ies", data.get("path")))
    for error in data.get("errors") or []:
        print("line %s ignored: %s (%s)" % (error["line"], error["entry"], error["reason"]))


def show_quarantine(data):
    for entry in data.get("entries") or []:
        print(entry)
    print("\n%d entr%s in %s"
          % (data.get("count", 0), "y" if data.get("count") == 1 else "ies", data.get("path")))
    print("label %s · age %s · expires older than %s"
          % (data.get("label"), data.get("age"), data.get("cutoff")))
    for error in data.get("errors") or []:
        print("line %s ignored: %s (%s)" % (error["line"], error["entry"], error["reason"]))


def show_run(data):
    if data.get("skipped"):
        print("skipped: %s" % data["skipped"])
        return
    print("run %s (%s)%s" % (data.get("run_id"), data.get("reason"),
                             " DRY RUN" if data.get("dry_run") else ""))
    print("  matched      %s" % data.get("matched"))
    print("  suppressed   %s" % data.get("suppressed"))
    print("  trashed      %s" % data.get("trashed"))
    print("  would trash  %s" % data.get("would_trash"))
    print("  filed        %s" % data.get("filed"))
    print("  would file   %s" % data.get("would_file"))
    print("  expired      %s" % data.get("expired"))
    print("  would expire %s" % data.get("would_expire"))
    print("  held         %s" % data.get("held"))
    if data.get("quarantine_stale"):
        print("  stale label  %s" % data.get("quarantine_stale"))
    print("  capped       %s" % data.get("capped"))
    print("  duration     %ss" % data.get("duration_s"))
    for error in data.get("errors") or []:
        print("  error        %s" % error)
    for warning in data.get("warnings") or []:
        print("  warning      %s" % warning)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="spam-assassin", description=__doc__)
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="watcher, last run, blacklist size")

    messages = sub.add_parser("list", help="recent messages")
    messages.add_argument("--days", type=int, default=None)
    messages.add_argument("--limit", type=int, default=100)
    messages.add_argument("--folder", choices=["all", "inbox", "spam"], default="all")

    senders = sub.add_parser("senders", help="recent senders grouped by address")
    senders.add_argument("--days", type=int, default=None)
    senders.add_argument("--limit", type=int, default=200)

    sub.add_parser("blacklist", help="show blacklist entries")

    sub.add_parser("whitelist", help="show senders that are never deleted or listed")

    sub.add_parser("quarantine", help="show senders held before deletion, with label and age")

    sub.add_parser("mailboxes", help="IMAP folders this account exposes")

    add = sub.add_parser("add", help="add addresses or @domains to the blacklist")
    add.add_argument("entries", nargs="+")

    remove = sub.add_parser("rm", help="remove addresses or @domains from the blacklist")
    remove.add_argument("entries", nargs="+")

    allow = sub.add_parser("allow", help="never delete these, and hide them from lists")
    allow.add_argument("entries", nargs="+")

    disallow = sub.add_parser("disallow", help="stop hiding / protecting these")
    disallow.add_argument("entries", nargs="+")

    hold = sub.add_parser("hold", help="label, hold, then delete these senders")
    hold.add_argument("entries", nargs="+")

    release = sub.add_parser("release", help="stop holding and queued deletions for these")
    release.add_argument("entries", nargs="+")

    run = sub.add_parser("run", help="trigger a purge now")
    run.add_argument("--live", action="store_true", help="actually delete (overrides DRY_RUN)")
    run.add_argument("--dry-run", action="store_true", help="force a dry run")

    audit = sub.add_parser("audit", help="recent audit log records")
    audit.add_argument("--limit", type=int, default=20)

    args = parser.parse_args(argv)

    if args.command == "status":
        data = request("GET", "/status")
        return print(json.dumps(data, indent=2)) if args.json else show_status(data)
    if args.command == "list":
        params = {"limit": args.limit, "folder": args.folder}
        if args.days:
            params["days"] = args.days
        data = request("GET", "/messages?" + urllib.parse.urlencode(params))
        return print(json.dumps(data, indent=2)) if args.json else show_messages(data)
    if args.command == "senders":
        params = {"limit": args.limit}
        if args.days:
            params["days"] = args.days
        data = request("GET", "/senders?" + urllib.parse.urlencode(params))
        return print(json.dumps(data, indent=2)) if args.json else show_senders(data)
    if args.command == "blacklist":
        data = request("GET", "/blacklist")
        return print(json.dumps(data, indent=2)) if args.json else show_blacklist(data)
    if args.command == "whitelist":
        data = request("GET", "/whitelist")
        return print(json.dumps(data, indent=2)) if args.json else show_blacklist(data)
    if args.command == "quarantine":
        data = request("GET", "/quarantine")
        return print(json.dumps(data, indent=2)) if args.json else show_quarantine(data)
    if args.command == "mailboxes":
        data = request("GET", "/mailboxes")
        for name in data.get("mailboxes") or []:
            print(name)
        print("\nAll Mail: %s" % data.get("all_mail"))
        print("Spam:     %s" % data.get("spam"))
        print("Trash:    %s" % data.get("trash"))
        print("Quarantine label: %s" % data.get("quarantine_label"))
        if not data.get("can_delete"):
            print("\ndeletion is disabled: Trash is not visible over IMAP")
        print(data.get("note", ""))
        return 0
    if args.command == "add":
        data = request("POST", "/blacklist", {"addresses": args.entries})
        print(json.dumps(data, indent=2))
        return 0 if not data.get("errors") else 1
    if args.command == "rm":
        data = request("POST", "/blacklist/remove", {"addresses": args.entries})
        print(json.dumps(data, indent=2))
        return 0 if not data.get("errors") else 1
    if args.command == "allow":
        data = request("POST", "/whitelist", {"addresses": args.entries})
        print(json.dumps(data, indent=2))
        return 0 if not data.get("errors") else 1
    if args.command == "disallow":
        data = request("POST", "/whitelist/remove", {"addresses": args.entries})
        print(json.dumps(data, indent=2))
        return 0 if not data.get("errors") else 1
    if args.command == "hold":
        data = request("POST", "/quarantine", {"addresses": args.entries})
        print(json.dumps(data, indent=2))
        return 0 if not data.get("errors") else 1
    if args.command == "release":
        data = request("POST", "/quarantine/remove", {"addresses": args.entries})
        print(json.dumps(data, indent=2))
        return 0 if not data.get("errors") else 1
    if args.command == "run":
        body = {}
        if args.live:
            body["dry_run"] = False
        if args.dry_run:
            body["dry_run"] = True
        data = request("POST", "/run", body)
        return print(json.dumps(data, indent=2)) if args.json else show_run(data)
    if args.command == "audit":
        data = request("GET", "/audit?limit=%d" % args.limit)
        for line in data.get("lines") or []:
            print(json.dumps(line, ensure_ascii=False))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
