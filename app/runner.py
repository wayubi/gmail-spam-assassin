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

import collections
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

# Never fetch less than this, or a page of whitelisted/lookalike hits could
# starve the budget forever. The slack covers filtered messages in the page.
MIN_FETCH = 100
FETCH_SLACK = 50

# Labelling is cheap but not free, and a huge burst should not hold the run
# open for an hour. The rest is filed on the next cycle.
FILE_CEILING = 2000

_run_lock = threading.Lock()
_rerun = threading.Event()
_recent_runs = collections.deque(maxlen=50)
_recent_lock = threading.Lock()


def request_rerun():
    """A trigger arrived while a run was busy; ask for one more run."""
    _rerun.set()


def get_run(run_id):
    """Recent run summary from memory, so /runs does not read the audit file."""
    with _recent_lock:
        for record in reversed(_recent_runs):
            if record.get("run_id") == run_id:
                return record
    return None


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
    """Quarantine deletion budget: expiry plus old mail found while filing."""
    used = summary["expired"] + summary["would_expire"]
    return cfg.max_delete_per_run - used


def _trash_budget(cfg, summary):
    """Blacklist deletion budget, independent of quarantine."""
    used = summary["trashed"] + summary["would_trash"]
    return cfg.max_trash_per_run - used


def _file_budget(summary):
    return FILE_CEILING - summary["filed"] - summary["would_file"]


def _fetch_limit(budget, page=FETCH_PAGE):
    """How many headers are worth fetching for a given remaining budget."""
    if budget <= 0:
        return 0
    return min(page, max(MIN_FETCH, budget + FETCH_SLACK))


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


def _audit_many(cfg, summary, records):
    records = list(records)
    if not records:
        return True
    try:
        state.append_audit_many(cfg.audit_path, records)
        return True
    except OSError as exc:
        summary["errors"].append("audit write failed: %s" % exc)
        return False


def _progress(cfg, summary, phase):
    """Expose coarse progress while a long run is in flight."""
    try:
        state.update_state(
            cfg.state_path,
            running_phase=phase,
            running_counts={
                "filed": summary["filed"],
                "expired": summary["expired"],
                "trashed": summary["trashed"],
                "matched": summary["matched"],
            },
            heartbeat=state.now_iso(),
        )
    except Exception:
        pass


def _message_record(run_id, dry, entry, folder, meta, action, label=None):
    record = {
        "ts": state.now_iso(),
        "kind": "message",
        "run_id": run_id,
        "dry_run": dry,
        "entry": entry,
        "folder": folder,
        "uid": meta["uid"],
        "msgid": meta["msgid"],
        "from": meta["from_addr"],
        "from_name": meta["from_name"],
        "subject": meta["subject"],
        "date": meta["date"],
        "action": action,
    }
    if label is not None:
        record["label"] = label
    return record


def _new_summary(cfg, run_id, dry, reason, now):
    return {
        "run_id": run_id,
        "reason": reason,
        "dry_run": dry,
        "started": state.now_iso(),
        "phase_s": {},
        "imap_commands": {},
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


def _finish(cfg, summary, run_id, dry, reason, started_monotonic, conn):
    imap.logout(conn)
    summary["imap_commands"] = imap.command_counts(conn)
    _run_lock.release()
    summary["duration_s"] = round(time.monotonic() - started_monotonic, 2)
    summary["finished"] = state.now_iso()
    if summary.get("incremental"):
        # An incremental run does not scan the label; keep the last full count.
        summary["held"] = state.read_state(cfg.state_path).get("last_held", 0)
    extra = {}
    for key in ("quarantine_batch_offset", "blacklist_batch_offset", "blacklist_mailbox_offset"):
        if key in summary:
            extra[key] = summary[key]
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
            last_phase_s=summary["phase_s"],
            last_imap_commands=summary["imap_commands"],
            last_error=(summary["errors"] or [None])[-1],
            last_duration_s=summary["duration_s"],
            running_phase=None,
            running_counts=None,
            heartbeat=state.now_iso(),
            **extra,
        )
        if not dry and (
            summary["trashed"] or summary["filed"] or summary["expired"]
        ):
            try:
                from . import listing

                listing.invalidate()
            except Exception:
                pass
        with _recent_lock:
            _recent_runs.append(dict(summary))
    except Exception:
        pass


def record_skipped(cfg, run_id, reason, dry=False):
    """Record a requested run that never acquired the lock.

    Without this the caller holds a run id that never appears, and the page or
    CLI waits for a summary that will not exist.
    """
    now = _now()
    summary = _new_summary(cfg, run_id, dry, "api-skipped", now)
    summary.update(
        ok=False,
        skipped=reason,
        errors=[reason],
        finished=state.now_iso(),
        duration_s=0.0,
    )
    try:
        state.append_audit(cfg.audit_path, dict(summary, kind="summary"))
    except Exception:
        pass
    with _recent_lock:
        _recent_runs.append(dict(summary))
    return summary


def run_purge(cfg, dry_run=None, reason="manual", run_id=None):
    """Run once, plus one coalesced rerun at the configured mode."""
    result = _run_once(cfg, dry_run=dry_run, reason=reason, run_id=run_id)
    if result.get("skipped"):
        # An explicit request that lost the lock race must not be retried in
        # another mode under its own run_id. The busy run's wrapper performs
        # the coalesced config-mode rerun; the API records this request as
        # skipped.
        return result
    if _rerun.is_set():
        _rerun.clear()
        # A trigger that arrived during the run is not the caller's explicit
        # request: rerun in the configured mode, not the caller's override.
        result = _run_once(
            cfg, dry_run=None, reason=reason + "-rerun", run_id=None
        )
    return result


def _run_once(cfg, dry_run=None, reason="manual", run_id=None):
    dry = cfg.dry_run if dry_run is None else bool(dry_run)
    if not _run_lock.acquire(blocking=False):
        _rerun.set()
        return {"ok": False, "skipped": "another run is already in progress"}

    run_id = run_id or uuid.uuid4().hex[:12]
    started_monotonic = time.monotonic()
    now = _now()
    summary = _new_summary(cfg, run_id, dry, reason, now)
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
        all_mail = imap.match_mailbox(available, "/all mail", imap.ALL_MAIL)
        if not all_mail:
            raise imap.ImapError(
                "cannot find All Mail over IMAP; folders seen: %s"
                % (", ".join(available) if available else "none")
            )
        mailboxes = [all_mail]
        spam = imap.match_mailbox(available, "/spam")
        if spam:
            mailboxes.append(spam)
        else:
            summary["warnings"].append(
                "[Gmail]/Spam is not exposed over IMAP, so spam is not swept. "
                "Enable 'Show in IMAP' for Spam under Gmail Settings > Labels."
            )
        summary["mailboxes"] = mailboxes
        summary["folders_seen"] = available

        trash = imap.match_mailbox(available, "/trash")
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
            q_label = imap.match_label(available, cfg.quarantine_label)
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

        prior = state.read_state(cfg.state_path)
        # Shared by dry and live runs: rotation only affects fairness.
        q_offset = int(prior.get("quarantine_batch_offset") or 0)
        b_offset = int(prior.get("blacklist_batch_offset") or 0)
        bm_offset = int(prior.get("blacklist_mailbox_offset") or 0)

        if q_entries and q_label:
            phase_started = time.monotonic()
            _progress(cfg, summary, "expire")
            _quarantine_expire(
                conn, cfg, q_entries, hidden, q_label, trash, dry, summary, run_id, now
            )
            summary["phase_s"]["expire"] = round(time.monotonic() - phase_started, 2)

            phase_started = time.monotonic()
            _progress(cfg, summary, "file")
            q_offset = _quarantine_file(
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
                q_offset,
            )
            summary["quarantine_batch_offset"] = q_offset
            summary["phase_s"]["file"] = round(time.monotonic() - phase_started, 2)

        active = [entry for entry in entries if entry not in skipped]
        if active:
            phase_started = time.monotonic()
            _progress(cfg, summary, "purge")
            b_offset, bm_offset = _purge_batches(
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
                b_offset,
                bm_offset,
            )
            summary["blacklist_batch_offset"] = b_offset
            summary["blacklist_mailbox_offset"] = bm_offset
            summary["phase_s"]["purge"] = round(time.monotonic() - phase_started, 2)
        _progress(cfg, summary, None)
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
        _finish(cfg, summary, run_id, dry, reason, started_monotonic, conn)
    return summary


def run_new_mail(cfg, since_uid, uidvalidity, dry_run=None, reason="idle"):
    """Handle only the UIDs that arrived in INBOX since the last IDLE connect.

    Returns `fallback: True` when the cheap path cannot be trusted (UIDVALIDITY
    changed, too many arrivals, missing folder/label); the caller then runs the
    full batched sweep.
    """
    dry = cfg.dry_run if dry_run is None else bool(dry_run)
    if not _run_lock.acquire(blocking=False):
        _rerun.set()
        return {"ok": False, "skipped": "another run is already in progress"}

    run_id = uuid.uuid4().hex[:12]
    now = _now()
    summary = _new_summary(cfg, run_id, dry, reason, now)
    summary["incremental"] = True
    started_monotonic = time.monotonic()
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

        if since_uid is None:
            summary["fallback"] = True
            summary["ok"] = True
            return summary

        conn = imap.connect(cfg.gmail_user, cfg.gmail_password)
        names = imap.list_mailboxes(conn)
        trash = imap.match_mailbox(names, "/trash")
        q_label = (
            imap.match_label(names, cfg.quarantine_label) if q_entries else None
        )
        if q_entries and not q_label:
            summary["fallback"] = True
            summary["ok"] = True
            return summary

        imap.select(conn, imap.INBOX, readonly=True)
        summary["uidvalidity"] = conn.uidvalidity
        summary["server_uidnext"] = conn.uidnext
        if (
            uidvalidity is not None
            and conn.uidvalidity is not None
            and int(uidvalidity) != int(conn.uidvalidity)
        ):
            summary["fallback"] = True
            summary["ok"] = True
            summary["note"] = "UIDVALIDITY changed; full sweep"
            return summary

        uids = imap.search_since(conn, imap.INBOX, int(since_uid))
        if not uids:
            summary["uidnext"] = int(since_uid)
            summary["ok"] = True
            return summary
        if len(uids) > FETCH_PAGE:
            summary["fallback"] = True
            summary["ok"] = True
            summary["note"] = "more than %d new messages; full sweep" % FETCH_PAGE
            return summary

        metas = imap.fetch_meta(conn, uids)
        files = []
        expires = []
        trashes = []
        for meta in metas:
            if meta["uid"] < int(since_uid):
                continue
            labels = {name.lower() for name in meta.get("labels") or []}
            if "trash" in labels or "spam" in labels:
                continue
            if whitelist.matches(meta["from_addr"], hidden):
                summary["suppressed"] += 1
                continue
            held = quarantine.matches(meta["from_addr"], q_entries)
            if held:
                state_flag = cfg.quarantine_age.expired(meta["date"], now)
                if state_flag is None:
                    summary["undated"] += 1
                    continue
                if state_flag:
                    expires.append((held, meta))
                else:
                    files.append((held, meta))
                continue
            entry = blacklist.matches(meta["from_addr"], entries)
            if entry:
                trashes.append((entry, meta))

        if expires and cfg.quarantine_abort_over and len(expires) > cfg.quarantine_abort_over:
            summary["warnings"].append(
                "quarantine: %d new messages are already past %s but "
                "QUARANTINE_ABORT_OVER=%d; they were left in place."
                % (len(expires), cfg.quarantine_age.text, cfg.quarantine_abort_over)
            )
            expires = []
        delete_left = _delete_budget(cfg, summary)
        if len(expires) > delete_left:
            expires = expires[:delete_left]
            summary["capped"] = True
        file_left = _file_budget(summary)
        if len(files) > file_left:
            files = files[:file_left]
            summary["capped"] = True
        trash_left = _trash_budget(cfg, summary)
        if len(trashes) > trash_left:
            trashes = trashes[:trash_left]
            summary["capped"] = True

        if (expires or trashes) and not trash:
            summary["fallback"] = True
            summary["ok"] = True
            summary["note"] = "Trash is not visible; full sweep"
            return summary

        records = []
        for entry, meta in files:
            records.append(
                _message_record(
                    run_id,
                    dry,
                    entry,
                    imap.INBOX,
                    meta,
                    "would-quarantine" if dry else "quarantined",
                    label=q_label,
                )
            )
        for entry, meta in expires:
            records.append(
                _message_record(
                    run_id,
                    dry,
                    entry,
                    imap.INBOX,
                    meta,
                    "would-expire" if dry else "expired",
                    label=q_label,
                )
            )
        for entry, meta in trashes:
            records.append(
                _message_record(
                    run_id,
                    dry,
                    entry,
                    imap.INBOX,
                    meta,
                    "would-trash" if dry else "trashed",
                )
            )
        _audit_many(cfg, summary, records)

        summary["matched"] = len(trashes)
        summary["uidnext"] = max(uids) + 1
        if dry:
            summary["would_file"] += len(files)
            summary["would_expire"] += len(expires)
            summary["would_trash"] += len(trashes)
            summary["ok"] = True
            return summary

        if files:
            try:
                imap.select_writable(conn, imap.INBOX)
                ids = [meta["uid"] for _entry, meta in files]
                imap.add_labels(conn, ids, [q_label])
                imap.remove_labels(conn, ids, ["\\Inbox"])
                summary["filed"] += len(files)
            except imap.ImapError as exc:
                summary["errors"].append("incremental filing: %s" % exc)
        if expires:
            try:
                imap.select_writable(conn, imap.INBOX)
                summary["expired"] += imap.move_to_trash(
                    conn, [meta["uid"] for _entry, meta in expires], trash
                )
            except imap.ImapError as exc:
                summary["errors"].append("incremental expiry: %s" % exc)
        if trashes:
            try:
                imap.select_writable(conn, imap.INBOX)
                summary["trashed"] += imap.move_to_trash(
                    conn, [meta["uid"] for _entry, meta in trashes], trash
                )
            except imap.ImapError as exc:
                summary["errors"].append("incremental trash: %s" % exc)
        summary["ok"] = True
    except Exception as exc:  # noqa: BLE001
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
        summary["phase_s"]["incremental"] = round(
            time.monotonic() - started_monotonic, 2
        )
        _finish(cfg, summary, run_id, dry, reason, started_monotonic, conn)
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
    remaining = _delete_budget(cfg, summary)
    if remaining <= 0:
        summary["capped"] = True
        return
    limit = _fetch_limit(remaining, FETCH_CEILING)
    try:
        metas = imap.fetch_meta(conn, due[:limit])
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
    _audit_many(
        cfg,
        summary,
        [
            _message_record(
                run_id,
                dry,
                quarantine.matches(meta["from_addr"], q_entries),
                label,
                meta,
                action,
                label=label,
            )
            for meta in limited
        ],
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
    conn,
    cfg,
    q_entries,
    hidden,
    label,
    all_mail,
    trash,
    dry,
    summary,
    run_id,
    now,
    offset=0,
):
    """Label recent mail, and send already-old matches straight to Trash.

    Searches are batched and split by age, so Gmail does the filtering:
    older_than/newer_than plus -label mean only actionable messages come back.
    Batches start at a rotating offset so an early sender cannot starve later
    ones without adding any work to a run.
    """
    seen = set()
    age = cfg.quarantine_age
    batches = list(_chunks(q_entries, SEARCH_BATCH))
    if not batches:
        return 0
    offset = max(0, int(offset)) % len(batches)
    ordered = batches[offset:] + batches[:offset]
    stop_index = None
    streams = (
        ("older_than:%s" % age.gmail, True),
        ("newer_than:%s" % age.gmail, False),
    )
    for index, batch in enumerate(ordered):
        if _file_budget(summary) <= 0 and _delete_budget(cfg, summary) <= 0:
            if stop_index is None:
                stop_index = index
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
            budget = (
                _delete_budget(cfg, summary)
                if criterion.startswith("older")
                else _file_budget(summary)
            )
            limit = _fetch_limit(budget, FETCH_PAGE)
            if limit <= 0:
                continue
            page = uids[:limit] if oldest_first else uids[-limit:]
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

        _audit_many(
            cfg,
            summary,
            [
                _message_record(
                    run_id,
                    dry,
                    quarantine.matches(meta["from_addr"], q_entries),
                    all_mail,
                    meta,
                    "would-quarantine" if dry else "quarantined",
                    label=label,
                )
                for meta in batch_files
            ]
            + [
                _message_record(
                    run_id,
                    dry,
                    quarantine.matches(meta["from_addr"], q_entries),
                    all_mail,
                    meta,
                    "would-expire" if dry else "expired",
                    label=label,
                )
                for meta in batch_expired
            ],
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

        if stop_index is None and (
            _file_budget(summary) <= 0 or _delete_budget(cfg, summary) <= 0
        ):
            stop_index = index
        _progress(cfg, summary, "file")

    if not dry:
        _quarantine_repair(conn, cfg, q_entries, label, all_mail, summary)

    if stop_index is None:
        return 0
    return (offset + stop_index + 1) % len(batches)


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
    conn,
    cfg,
    entries,
    q_entries,
    hidden,
    mailboxes,
    trash,
    dry,
    summary,
    run_id,
    offset=0,
    mailbox_offset=0,
):
    """Delete blacklisted mail in batches of senders, not one sender at a time.

    Both the starting batch and the mailbox order rotate, so neither an early
    sender nor the first mailbox can starve the rest. No extra IMAP commands.
    """
    seen = set()
    batches = list(_chunks(entries, SEARCH_BATCH))
    count_mailboxes = max(1, len(mailboxes))
    mailbox_offset = max(0, int(mailbox_offset)) % count_mailboxes
    next_mailbox = (mailbox_offset + 1) % count_mailboxes
    if count_mailboxes > 1:
        mailboxes = mailboxes[mailbox_offset:] + mailboxes[:mailbox_offset]
    if not batches:
        return 0, next_mailbox
    offset = max(0, int(offset)) % len(batches)
    ordered = batches[offset:] + batches[:offset]
    stop_index = None
    for index, batch in enumerate(ordered):
        if _trash_budget(cfg, summary) <= 0:
            summary["capped"] = True
            if stop_index is None:
                stop_index = index
            break
        stopped = False
        for mailbox in mailboxes:
            remaining = _trash_budget(cfg, summary)
            if remaining <= 0:
                summary["capped"] = True
                stopped = True
                break
            uids, error = _search_batch(conn, mailbox, batch)
            if error:
                summary["errors"].append(
                    "blacklist search in %s: %s" % (mailbox, error)
                )
            if not uids:
                continue
            limit = _fetch_limit(remaining, FETCH_PAGE)
            if limit <= 0:
                continue
            page = uids[:limit]
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

            _audit_many(
                cfg,
                summary,
                [
                    _message_record(
                        run_id,
                        dry,
                        entry,
                        mailbox,
                        meta,
                        "would-trash" if dry else "trashed",
                    )
                    for entry, meta in limited
                ],
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
            _progress(cfg, summary, "purge")

        if stopped or _trash_budget(cfg, summary) <= 0:
            if stop_index is None:
                stop_index = index
            break

    if stop_index is None:
        return 0, next_mailbox
    return (offset + stop_index + 1) % len(batches), next_mailbox
