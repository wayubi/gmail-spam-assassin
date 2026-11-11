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

# Sender searches are unioned into batches: one server round-trip per 25
# senders instead of one per sender. With hundreds of entries this is the
# difference between ~35 searches and ~800 per run.
SEARCH_BATCH = 25

# Headers fetched per batch per pass. Only a page is needed: the per-run
# budgets decide how many can be acted on, and whatever is handled drops out
# of the next search.
FETCH_PAGE = 500

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


def _file_budget(summary):
    return FILE_CEILING - summary["filed"] - summary["would_file"]


def _chunks(items, size):
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _batch_query(entries, extra=""):
    """One Gmail search for a set of senders, e.g. {from:a from:b}."""
    terms = " ".join(
        "from:%s" % (entry[1:] if entry.startswith("@") else entry)
        for entry in entries
    )
    if len(entries) == 1:
        query = terms
    else:
        query = "{%s}" % terms
    if extra:
        query += " " + extra
    return query


def _search_batch(conn, mailbox, entries, extra=""):
    """Search a batch, splitting it on error so one bad entry cannot break it."""
    try:
        return imap.search_uids(conn, _batch_query(entries, extra), mailbox), None
    except imap.ImapError as exc:
        if len(entries) <= 1:
            return [], "%s: %s" % (entries[0] if entries else "?", exc)
        middle = len(entries) // 2
        left, left_error = _search_batch(conn, mailbox, entries[:middle], extra)
        right, right_error = _search_batch(conn, mailbox, entries[middle:], extra)
        return left + right, left_error or right_error


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

        active = [entry for entry in entries if entry not in skipped]
        if active:
            _purge_batches(
                conn,
                cfg,
                active,
                q_entries,
                hidden,
                mailboxes,
                trash,
                dry,
                summary,
                run_id,
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
    """Label recent mail, and send already-old matches straight to Trash.

    Searches are batched and split by age, so Gmail does the filtering:
    older_than/newer_than plus -label mean only actionable messages come back.
    """
    seen = set()
    age = cfg.quarantine_age
    streams = (
        ("older_than:%s" % age.gmail, True),
        ("newer_than:%s" % age.gmail, False),
    )
    for batch in _chunks(q_entries, SEARCH_BATCH):
        if _file_budget(summary) <= 0 and _delete_budget(cfg, summary) <= 0:
            summary["capped"] = True
            break
        batch_files = []
        batch_expired = []
        for criterion, oldest_first in streams:
            if criterion.startswith("older") and _delete_budget(cfg, summary) <= 0:
                continue
            if criterion.startswith("newer") and _file_budget(summary) <= 0:
                continue
            extra = '-label:"%s" %s' % (label, criterion)
            uids, error = _search_batch(conn, all_mail, batch, extra)
            if error:
                summary["errors"].append(
                    "quarantine search in %s: %s" % (all_mail, error)
                )
            if not uids:
                continue
            page = uids[:FETCH_PAGE] if oldest_first else uids[-FETCH_PAGE:]
            try:
                metas = imap.fetch_meta(conn, page)
            except imap.ImapError as exc:
                summary["errors"].append("fetch in %s: %s" % (all_mail, exc))
                continue
            for meta in metas:
                entry = quarantine.matches(meta["from_addr"], batch)
                if entry is None:
                    # Substring hit, not an exact sender.
                    continue
                key = meta["msgid"] or ("uid:%s" % meta["uid"])
                if key in seen:
                    continue
                seen.add(key)
                if whitelist.matches(meta["from_addr"], hidden):
                    summary["suppressed"] += 1
                    continue
                if _has_label(meta, label):
                    # -label should have excluded it; belt and braces.
                    continue
                state_flag = age.expired(meta["date"], now)
                if state_flag is None:
                    summary["undated"] += 1
                    continue
                if state_flag:
                    batch_expired.append(meta)
                else:
                    batch_files.append(meta)

        delete_left = _delete_budget(cfg, summary)
        file_left = _file_budget(summary)
        if (
            batch_expired
            and cfg.quarantine_abort_over
            and len(batch_expired) > cfg.quarantine_abort_over
        ):
            summary["warnings"].append(
                "quarantine: %d matched messages are already past %s but "
                "QUARANTINE_ABORT_OVER=%d; they were left in place. Raise the "
                "limit deliberately to delete them."
                % (len(batch_expired), age.text, cfg.quarantine_abort_over)
            )
            batch_expired = []
        if len(batch_expired) > max(0, delete_left):
            batch_expired = batch_expired[: max(0, delete_left)]
            summary["capped"] = True
        if len(batch_files) > max(0, file_left):
            batch_files = batch_files[: max(0, file_left)]
            summary["capped"] = True
        if not batch_files and not batch_expired:
            continue

        for meta in batch_files:
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
        for meta in batch_expired:
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
            summary["would_file"] += len(batch_files)
            summary["would_expire"] += len(batch_expired)
            continue

        if batch_files:
            try:
                imap.select_writable(conn, all_mail)
                uids = [meta["uid"] for meta in batch_files]
                imap.add_labels(conn, uids, [label])
                imap.remove_labels(conn, uids, ["\\Inbox"])
                summary["filed"] += len(batch_files)
            except imap.ImapError as exc:
                summary["errors"].append(
                    "quarantine filing in %s: %s" % (all_mail, exc)
                )

        if batch_expired:
            try:
                imap.select_writable(conn, all_mail)
                summary["expired"] += imap.move_to_trash(
                    conn, [meta["uid"] for meta in batch_expired], trash
                )
            except imap.ImapError as exc:
                summary["errors"].append(
                    "quarantine expiry in %s: %s" % (all_mail, exc)
                )

    if not dry:
        _quarantine_repair(conn, cfg, q_entries, label, all_mail, summary)


def _quarantine_repair(conn, cfg, q_entries, label, all_mail, summary):
    """Finish the rare half-filed message: label applied, Inbox removal failed.

    -label excludes these from the normal filing search, so without this they
    would sit in Inbox until they aged out.
    """
    query = 'label:"%s" in:inbox' % label
    try:
        uids = imap.search_uids(conn, query, all_mail)
    except imap.ImapError as exc:
        summary["errors"].append("quarantine repair in %s: %s" % (all_mail, exc))
        return
    if not uids:
        return
    try:
        metas = imap.fetch_meta(conn, uids[:FETCH_PAGE])
    except imap.ImapError as exc:
        summary["errors"].append("quarantine repair fetch in %s: %s" % (all_mail, exc))
        return
    targets = []
    for meta in metas:
        if not _has_label(meta, label):
            continue
        if not any(
            (name or "").lower() == "inbox" for name in meta.get("labels") or []
        ):
            continue
        if quarantine.matches(meta["from_addr"], q_entries) is None:
            continue
        targets.append(meta)
    if not targets:
        return
    try:
        imap.select_writable(conn, all_mail)
        imap.remove_labels(conn, [meta["uid"] for meta in targets], ["\\Inbox"])
    except imap.ImapError as exc:
        summary["errors"].append("quarantine repair in %s: %s" % (all_mail, exc))


def _purge_batches(
    conn, cfg, entries, q_entries, hidden, mailboxes, trash, dry, summary, run_id
):
    """Delete blacklisted mail in batches of senders, not one sender at a time."""
    seen = set()
    for batch in _chunks(entries, SEARCH_BATCH):
        if _delete_budget(cfg, summary) <= 0:
            summary["capped"] = True
            break
        for mailbox in mailboxes:
            remaining = _delete_budget(cfg, summary)
            if remaining <= 0:
                summary["capped"] = True
                break
            uids, error = _search_batch(conn, mailbox, batch)
            if error:
                summary["errors"].append(
                    "blacklist search in %s: %s" % (mailbox, error)
                )
            if not uids:
                continue
            page = uids[:FETCH_PAGE]
            try:
                metas = imap.fetch_meta(conn, page)
            except imap.ImapError as exc:
                summary["errors"].append("fetch in %s: %s" % (mailbox, exc))
                continue

            hits = []
            for meta in metas:
                entry = blacklist.matches(meta["from_addr"], batch)
                if entry is None:
                    # Substring hit, not an exact sender.
                    continue
                key = (mailbox, meta["msgid"] or ("uid:%s" % meta["uid"]))
                if key in seen:
                    continue
                seen.add(key)
                if whitelist.matches(meta["from_addr"], hidden):
                    summary["suppressed"] += 1
                    continue
                if q_entries and quarantine.matches(
                    meta["from_addr"], q_entries
                ) is not None:
                    summary["suppressed"] += 1
                    continue
                hits.append((entry, meta))
            if not hits:
                continue

            summary["matched"] += len(hits)
            limited = hits[:remaining]
            if len(hits) > remaining:
                summary["capped"] = True

            for entry, meta in limited:
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
                continue

            try:
                imap.select_writable(conn, mailbox)
                summary["trashed"] += imap.move_to_trash(
                    conn, [meta["uid"] for _entry, meta in limited], trash
                )
            except imap.ImapError as exc:
                summary["errors"].append("trash in %s: %s" % (mailbox, exc))
