"""One delete run: blacklist purge plus the quarantine hold/expire cycle.

The run is serialised by a non-blocking lock: if a scheduled run and an API
"run now" collide, the second one returns immediately instead of opening a
second set of IMAP connections.

Order matters:

  1. expire mail already sitting in the quarantine label;
  2. file or expire newly matched quarantine mail;
  3. purge blacklisted senders (skipping any that quarantine also covers).

Quarantine never uses \\Deleted/EXPUNGE. Filing is an X-GM-LABELS edit, and
expiry is the same COPY into [Gmail]/Trash that the blacklist uses.
"""

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from . import blacklist, imap, quarantine, state, whitelist

# Never fetch more than this many candidates per sender per mailbox in one run.
# Deleting makes the next search smaller, so progress continues either way.
FETCH_CEILING = 2000

# Labelling is cheap but not free, and a huge burst should not hold the run
# open for an hour. The rest is filed on the next cycle.
FILE_CEILING = 2000

_run_lock = threading.Lock()


def busy():
    return _run_lock.locked()


def _now():
    """Separate function so tests can pin the clock."""
    return datetime.now(timezone.utc)


def _covers(entry, address):
    addr = (address or "").strip().lower()
    if not addr or "@" not in addr:
        return False
    if entry.startswith("@"):
        return addr.rsplit("@", 1)[1] == entry[1:]
    return addr == entry


def _overlaps(entry, hidden):
    """True when a blacklist entry is fully shielded by the whitelist."""
    if entry.startswith("@"):
        return entry in hidden
    return whitelist.matches(entry, hidden) is not None


def _pattern_overlap(left, right):
    """True when two entries can match the same sender."""
    if left == right:
        return True
    if left.startswith("@") and not right.startswith("@"):
        return _covers(left, right)
    if right.startswith("@") and not left.startswith("@"):
        return _covers(right, left)
    return False


def _quarantine_overlaps(entry, entries):
    return any(_pattern_overlap(entry, other) for other in entries)


def _quarantine_covers(entry, entries):
    """True when quarantine shields the whole blacklist entry.

    A wildcard blacklist entry with only some quarantined addresses inside it
    is not fully covered: the rest of that domain must still be deleted.
    """
    if entry.startswith("@"):
        return entry in entries
    return quarantine.matches(entry, entries) is not None


def _has_label(meta, label):
    wanted = label.lower()
    return any((name or "").lower() == wanted for name in meta.get("labels") or [])


def _delete_budget(cfg, summary):
    used = (
        summary["trashed"]
        + summary["would_trash"]
        + summary["expired"]
        + summary["would_expire"]
    )
    return cfg.max_delete_per_run - used


def _audit(cfg, summary, **record):
    record.setdefault("ts", state.now_iso())
    try:
        state.append_audit(cfg.audit_path, record)
        return True
    except OSError as exc:
        summary["errors"].append("audit write failed: %s" % exc)
        return False


def run_purge(cfg, dry_run=None, reason="manual"):
    dry = cfg.dry_run if dry_run is None else bool(dry_run)
    if not _run_lock.acquire(blocking=False):
        return {"ok": False, "skipped": "another run is already in progress"}

    run_id = uuid.uuid4().hex[:12]
    started = state.now_iso()
    started_monotonic = time.monotonic()
    now = _now()
    summary = {
        "run_id": run_id,
        "reason": reason,
        "dry_run": dry,
        "started": started,
        "entries": 0,
        "mailboxes": [],
        "matched": 0,
        "trashed": 0,
        "would_trash": 0,
        "suppressed": 0,
        "capped": False,
        "blacklist_errors": [],
        "blacklist_skipped": 0,
        "whitelisted": 0,
        "whitelist_errors": [],
        "quarantine_entries": 0,
        "quarantine_errors": [],
        "quarantine_created": False,
        "quarantine_label": cfg.quarantine_label,
        "quarantine_age": cfg.quarantine_age.text,
        "quarantine_cutoff": cfg.quarantine_age.cutoff(now).isoformat(
            timespec="seconds"
        ),
        "held": 0,
        "filed": 0,
        "would_file": 0,
        "expired": 0,
        "would_expire": 0,
        "quarantine_stale": 0,
        "undated": 0,
        "warnings": [],
        "errors": [],
        "ok": False,
    }
    conn = None
    try:
        entries, parse_errors = blacklist.load(
            cfg.blacklist_path, cfg.allow_freemail_domains
        )
        hidden, whitelist_errors = whitelist.load(cfg.whitelist_path)
        q_entries, q_errors = quarantine.load(cfg.quarantine_path)
        summary["entries"] = len(entries)
        summary["blacklist_errors"] = parse_errors
        summary["whitelisted"] = len(hidden)
        summary["whitelist_errors"] = whitelist_errors
        summary["quarantine_entries"] = len(q_entries)
        summary["quarantine_errors"] = q_errors

        skipped = set()
        for entry in entries:
            if _overlaps(entry, hidden):
                summary["warnings"].append(
                    "%s is in both lists; the whitelist wins and nothing from "
                    "it will be deleted" % entry
                )
            if _quarantine_overlaps(entry, q_entries):
                if _quarantine_covers(entry, q_entries):
                    skipped.add(entry)
                    summary["warnings"].append(
                        "%s is fully covered by quarantine; quarantine wins "
                        "and the whole entry is skipped" % entry
                    )
                else:
                    summary["warnings"].append(
                        "%s overlaps quarantine; quarantine wins for the "
                        "senders it names, the rest are still trashed" % entry
                    )
        summary["blacklist_skipped"] = len(skipped)

        if not entries and not q_entries:
            summary["ok"] = True
            summary["note"] = "blacklist and quarantine are empty; nothing to do"
            return summary

        conn = imap.connect(cfg.gmail_user, cfg.gmail_password)
        available = imap.list_mailboxes(conn)
        all_mail = imap.find_mailbox(conn, "/all mail", imap.ALL_MAIL)
        if not all_mail:
            raise imap.ImapError(
                "cannot find All Mail over IMAP; folders seen: %s"
                % (", ".join(available) if available else "none")
            )
        mailboxes = [all_mail]
        spam = imap.find_mailbox(conn, "/spam")
        if spam:
            mailboxes.append(spam)
        else:
            summary["warnings"].append(
                "[Gmail]/Spam is not exposed over IMAP, so spam is not swept. "
                "Enable 'Show in IMAP' for Spam under Gmail Settings > Labels."
            )
        summary["mailboxes"] = mailboxes
        summary["folders_seen"] = available

        trash = imap.find_mailbox(conn, "/trash")
        if trash:
            summary["trash"] = trash
        else:
            message = (
                "[Gmail]/Trash is not exposed over IMAP, so messages cannot be "
                "moved to Trash. Enable 'Show in IMAP' for Trash under Gmail "
                "Settings > Labels."
            )
            if not dry:
                # Fail closed: without Trash there is no recoverable delete,
                # and this app must never fall back to a permanent one.
                raise imap.ImapError(message)
            summary["warnings"].append(message + " (dry run continues)")

        q_label = None
        if q_entries:
            q_label = imap.find_label(conn, cfg.quarantine_label)
            if not q_label:
                # Gmail maps IMAP CREATE onto a label. Create it on demand so
                # the list works without a manual trip through Settings; if
                # the server refuses, say exactly what it said.
                try:
                    q_label = imap.create_label(conn, cfg.quarantine_label)
                except imap.ImapError as exc:
                    summary["errors"].append(
                        "quarantine label %r is missing or hidden, and IMAP "
                        "could not create it (%s); if it already exists in "
                        "Gmail, enable 'Show in IMAP' under Settings > Labels, "
                        "otherwise create it there" % (cfg.quarantine_label, exc)
                    )
                else:
                    if q_label:
                        summary["quarantine_created"] = True
                    else:
                        summary["errors"].append(
                            "created quarantine label %r but it is still not "
                            "listed; enable 'Show in IMAP' for it under Gmail "
                            "Settings > Labels" % cfg.quarantine_label
                        )
            if q_label and (
                q_label.lower().startswith("[gmail]")
                or q_label.lower() in ("inbox", "all mail", "spam", "trash")
            ):
                summary["errors"].append(
                    "quarantine label %r resolved to a system folder; refusing "
                    "to use it" % q_label
                )
                q_label = None
            elif q_label:
                summary["quarantine_folder"] = q_label

        if q_entries and q_label:
            _quarantine_expire(
                conn, cfg, q_entries, hidden, q_label, trash, dry, summary, run_id, now
            )
            _quarantine_file(
                conn,
                cfg,
                q_entries,
                hidden,
                q_label,
                all_mail,
                trash,
                dry,
                summary,
                run_id,
                now,
            )

        for entry in entries:
            if entry in skipped:
                continue
            for mailbox in mailboxes:
                remaining = _delete_budget(cfg, summary)
                if remaining <= 0:
                    summary["capped"] = True
                    break
                _purge_entry(
                    conn,
                    cfg,
                    entry,
                    mailbox,
                    dry,
                    remaining,
                    run_id,
                    summary,
                    trash,
                    hidden,
                    q_entries,
                )
        summary["ok"] = True
    except Exception as exc:  # noqa: BLE001 - the run must always be recorded
        summary["ok"] = False
        summary["errors"].append(str(exc))
        _audit(
            cfg,
            summary,
            kind="error",
            run_id=run_id,
            reason=reason,
            error=str(exc),
        )
    finally:
        imap.logout(conn)
        _run_lock.release()
        summary["duration_s"] = round(time.monotonic() - started_monotonic, 2)
        summary["finished"] = state.now_iso()
        try:
            state.append_audit(cfg.audit_path, dict(summary, kind="summary"))
            state.update_state(
                cfg.state_path,
                last_run=summary["finished"],
                last_run_id=run_id,
                last_reason=reason,
                last_ok=summary["ok"],
                last_dry_run=dry,
                last_trashed=summary["trashed"],
                last_would_trash=summary["would_trash"],
                last_matched=summary["matched"],
                last_suppressed=summary["suppressed"],
                last_entries=summary["entries"],
                last_capped=summary["capped"],
                last_filed=summary["filed"],
                last_would_file=summary["would_file"],
                last_expired=summary["expired"],
                last_would_expire=summary["would_expire"],
                last_held=summary["held"],
                last_stale=summary["quarantine_stale"],
                last_quarantine_entries=summary["quarantine_entries"],
                last_error=(summary["errors"] or [None])[-1],
                last_duration_s=summary["duration_s"],
                heartbeat=state.now_iso(),
            )
        except Exception:
            pass
    return summary


def _quarantine_expire(
    conn, cfg, q_entries, hidden, label, trash, dry, summary, run_id, now
):
    """Delete messages in the label that are past the configured age.

    The server does the date filtering: UID SEARCH BEFORE returns only the
    messages whose INTERNALDATE is old enough, so the thousands of younger
    held messages are never fetched or walked. The day is deliberately one
    past the cutoff (IMAP dates are day-granular) and the exact timestamp is
    checked again below, so nothing is deleted early.
    """
    cutoff = cfg.quarantine_age.cutoff(now)
    day = (cutoff.date() + timedelta(days=1)).strftime("%d-%b-%Y")
    try:
        due = imap.search_before(conn, label, day)
    except imap.ImapError as exc:
        summary["errors"].append("quarantine scan in %s: %s" % (label, exc))
        return

    try:
        total = imap.mailbox_count(conn, label)
    except imap.ImapError:
        try:
            total = len(imap.all_uids(conn, label))
        except imap.ImapError:
            total = 0
    summary["held"] = total

    if not due:
        return
    try:
        metas = imap.fetch_meta(conn, due[:FETCH_CEILING])
    except imap.ImapError as exc:
        summary["errors"].append("quarantine fetch in %s: %s" % (label, exc))
        return

    seen = set()
    candidates = []
    repairs = []
    for meta in metas:
        key = meta["msgid"] or ("uid:%s" % meta["uid"])
        if key in seen:
            continue
        seen.add(key)
        labels = {name.lower() for name in meta.get("labels") or []}
        if "trash" in labels or "spam" in labels:
            continue
        if whitelist.matches(meta["from_addr"], hidden):
            summary["suppressed"] += 1
            continue
        # Only senders still on the list are managed. Removing an entry stops
        # its queued deletions; the mail stays in the label until it is cleaned
        # up or the sender is added back.
        if not quarantine.matches(meta["from_addr"], q_entries):
            summary["quarantine_stale"] += 1
            continue
        if "inbox" in labels:
            # Filing is two STOREs; if the second failed, finish the job here
            # instead of leaving it half-filed until it expires.
            repairs.append(meta)
        # BEFORE is day-granular, so check the exact instant again.
        state_flag = cfg.quarantine_age.expired(meta["date"], now)
        if state_flag is None:
            summary["undated"] += 1
            continue
        if state_flag:
            candidates.append(meta)

    if repairs and not dry:
        try:
            imap.select_writable(conn, label)
            imap.remove_labels(
                conn, [meta["uid"] for meta in repairs], ["\\Inbox"]
            )
        except imap.ImapError as exc:
            summary["errors"].append("quarantine inbox repair in %s: %s" % (label, exc))

    if not candidates:
        return

    if cfg.quarantine_abort_over and len(candidates) > cfg.quarantine_abort_over:
        summary["warnings"].append(
            "quarantine: %d messages are past %s but QUARANTINE_ABORT_OVER=%d; "
            "nothing was expired. Raise the limit deliberately to proceed."
            % (len(candidates), cfg.quarantine_age.text, cfg.quarantine_abort_over)
        )
        return

    remaining = _delete_budget(cfg, summary)
    if remaining <= 0:
        summary["capped"] = True
        return
    limited = candidates[:remaining]
    if len(candidates) > remaining:
        summary["capped"] = True

    action = "would-expire" if dry else "expired"
    for meta in limited:
        _audit(
            cfg,
            summary,
            kind="message",
            run_id=run_id,
            dry_run=dry,
            entry=quarantine.matches(meta["from_addr"], q_entries),
            folder=label,
            uid=meta["uid"],
            msgid=meta["msgid"],
            **{"from": meta["from_addr"]},
            from_name=meta["from_name"],
            subject=meta["subject"],
            date=meta["date"],
            label=label,
            action=action,
        )

    if dry:
        summary["would_expire"] += len(limited)
        return

    try:
        imap.select_writable(conn, label)
        moved = imap.move_to_trash(conn, [meta["uid"] for meta in limited], trash)
        summary["expired"] += moved
        summary["held"] = max(0, total - moved)
    except imap.ImapError as exc:
        summary["errors"].append("quarantine expiry in %s: %s" % (label, exc))


def _quarantine_file(
    conn, cfg, q_entries, hidden, label, all_mail, trash, dry, summary, run_id, now
):
    """Label recent mail, and send already-old matches straight to Trash."""
    files = []
    expired = []
    seen = set()

    for entry in q_entries:
        sender = entry[1:] if entry.startswith("@") else entry
        # Excluding the label keeps a big backlog from pinning the first 2000
        # search hits forever: filed mail drops out, so each run progresses.
        query = 'from:%s -label:"%s"' % (sender, label)
        try:
            uids = imap.search_uids(conn, query, all_mail)
        except imap.ImapError as exc:
            summary["errors"].append("%s in %s: %s" % (entry, all_mail, exc))
            continue
        if not uids:
            continue
        try:
            metas = imap.fetch_meta(conn, uids[-FETCH_CEILING:])
        except imap.ImapError as exc:
            summary["errors"].append("fetch in %s: %s" % (all_mail, exc))
            continue

        for meta in metas:
            # Gmail's from: search is a substring match; only exact senders
            # qualify, same rule as the blacklist.
            if not _covers(entry, meta["from_addr"]):
                continue
            key = meta["msgid"] or ("uid:%s" % meta["uid"])
            if key in seen:
                continue
            seen.add(key)
            if whitelist.matches(meta["from_addr"], hidden):
                summary["suppressed"] += 1
                continue
            labelled = _has_label(meta, label)
            inboxed = any(
                (name or "").lower() == "inbox" for name in meta.get("labels") or []
            )
            # Already filed and out of Inbox: the expiry pass owns it now.
            if labelled and not inboxed:
                continue
            state_flag = cfg.quarantine_age.expired(meta["date"], now)
            if state_flag is None:
                summary["undated"] += 1
                continue
            if state_flag:
                expired.append(meta)
            else:
                files.append(meta)

    if expired and cfg.quarantine_abort_over and len(expired) > cfg.quarantine_abort_over:
        summary["warnings"].append(
            "quarantine: %d matched messages are already past %s but "
            "QUARANTINE_ABORT_OVER=%d; they were left in place. Raise the "
            "limit deliberately to delete them."
            % (len(expired), cfg.quarantine_age.text, cfg.quarantine_abort_over)
        )
        expired = []

    if len(files) > FILE_CEILING:
        files = files[:FILE_CEILING]
        summary["capped"] = True

    remaining = _delete_budget(cfg, summary)
    if remaining <= 0:
        if expired:
            summary["capped"] = True
        expired = []
    else:
        limited = expired[:remaining]
        if len(expired) > remaining:
            summary["capped"] = True
        expired = limited

    for meta in files:
        _audit(
            cfg,
            summary,
            kind="message",
            run_id=run_id,
            dry_run=dry,
            entry=quarantine.matches(meta["from_addr"], q_entries),
            folder=all_mail,
            uid=meta["uid"],
            msgid=meta["msgid"],
            **{"from": meta["from_addr"]},
            from_name=meta["from_name"],
            subject=meta["subject"],
            date=meta["date"],
            label=label,
            action="would-quarantine" if dry else "quarantined",
        )
    for meta in expired:
        _audit(
            cfg,
            summary,
            kind="message",
            run_id=run_id,
            dry_run=dry,
            entry=quarantine.matches(meta["from_addr"], q_entries),
            folder=all_mail,
            uid=meta["uid"],
            msgid=meta["msgid"],
            **{"from": meta["from_addr"]},
            from_name=meta["from_name"],
            subject=meta["subject"],
            date=meta["date"],
            label=label,
            action="would-expire" if dry else "expired",
        )

    if dry:
        summary["would_file"] += len(files)
        summary["would_expire"] += len(expired)
        return

    if files:
        try:
            imap.select_writable(conn, all_mail)
            uids = [meta["uid"] for meta in files]
            imap.add_labels(conn, uids, [label])
            imap.remove_labels(conn, uids, ["\\Inbox"])
            summary["filed"] += len(files)
        except imap.ImapError as exc:
            summary["errors"].append("quarantine filing in %s: %s" % (all_mail, exc))

    if expired:
        try:
            imap.select_writable(conn, all_mail)
            summary["expired"] += imap.move_to_trash(
                conn, [meta["uid"] for meta in expired], trash
            )
        except imap.ImapError as exc:
            summary["errors"].append("quarantine expiry in %s: %s" % (all_mail, exc))


def _purge_entry(
    conn, cfg, entry, mailbox, dry, budget, run_id, summary, trash, hidden, q_entries
):
    query = "from:%s" % (entry[1:] if entry.startswith("@") else entry)
    try:
        uids = imap.search_uids(conn, query, mailbox)
    except imap.ImapError as exc:
        summary["errors"].append("%s in %s: %s" % (entry, mailbox, exc))
        return
    if not uids:
        return

    candidates = uids[-FETCH_CEILING:]
    try:
        metas = imap.fetch_meta(conn, candidates)
    except imap.ImapError as exc:
        summary["errors"].append("fetch in %s: %s" % (mailbox, exc))
        return

    # Gmail's from: search is a substring match; only exact senders qualify.
    hits = [meta for meta in metas if _covers(entry, meta["from_addr"])]
    if not hits:
        return

    # The whitelist is a hard gate: a message that matches both lists is never
    # touched, and the skip is counted so the run cannot look more thorough
    # than it was.
    kept = [meta for meta in hits if not whitelist.matches(meta["from_addr"], hidden)]
    suppressed = len(hits) - len(kept)
    if suppressed:
        summary["suppressed"] += suppressed
    if not kept:
        return

    # Quarantine wins over the blacklist per message. This matters when a
    # blacklisted domain contains a quarantined address: that one sender is
    # held, the rest of the domain is still deleted.
    if q_entries:
        held_back = [
            meta
            for meta in kept
            if quarantine.matches(meta["from_addr"], q_entries) is not None
        ]
        if held_back:
            summary["suppressed"] += len(held_back)
            kept = [
                meta
                for meta in kept
                if quarantine.matches(meta["from_addr"], q_entries) is None
            ]
        if not kept:
            return
    hits = kept

    summary["matched"] += len(hits)
    limited = hits[:budget]
    if len(hits) > budget:
        summary["capped"] = True

    for meta in limited:
        _audit(
            cfg,
            summary,
            kind="message",
            run_id=run_id,
            dry_run=dry,
            entry=entry,
            folder=mailbox,
            uid=meta["uid"],
            msgid=meta["msgid"],
            **{"from": meta["from_addr"]},
            from_name=meta["from_name"],
            subject=meta["subject"],
            date=meta["date"],
            action="would-trash" if dry else "trashed",
        )

    if dry:
        summary["would_trash"] += len(limited)
        return

    try:
        imap.select_writable(conn, mailbox)
        summary["trashed"] += imap.move_to_trash(
            conn, [meta["uid"] for meta in limited], trash
        )
    except imap.ImapError as exc:
        summary["errors"].append("trash in %s: %s" % (mailbox, exc))
