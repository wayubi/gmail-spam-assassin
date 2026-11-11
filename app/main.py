"""Entrypoint: one process, three threads.

    api        HTTP + the web page
    heartbeat  keeps state.json fresh so the container healthcheck is honest
    worker     startup catch-up, then IDLE (default) or polling

Nothing here touches Gmail's block list. The blacklist is this container's
file; deletions are IMAP operations against Gmail itself, and they stop at
[Gmail]/Trash, which Gmail empties on its own after 30 days.
"""

import logging
import os
import random
import signal
import sys
import threading
import time

from . import api, blacklist, config, idle, quarantine, runner, state, whitelist

log = logging.getLogger("spam-assassin")


def _log_summary(label, result):
    log.info(
        "%s: ok=%s matched=%s trashed=%s would_trash=%s filed=%s expired=%s "
        "held=%s suppressed=%s capped=%s errors=%s",
        label,
        result.get("ok"),
        result.get("matched"),
        result.get("trashed"),
        result.get("would_trash"),
        result.get("filed"),
        result.get("expired"),
        result.get("held"),
        result.get("suppressed"),
        result.get("capped"),
        len(result.get("errors") or []),
    )


def _heartbeat(cfg, stop):
    while not stop.wait(60):
        try:
            state.update_state(cfg.state_path, heartbeat=state.now_iso())
        except Exception as exc:  # noqa: BLE001
            log.warning("heartbeat failed: %s", exc)


def _worker(cfg, stop):
    try:
        result = runner.run_purge(cfg, reason="startup")
        _log_summary("startup", result)
    except Exception:  # noqa: BLE001
        log.exception("startup run failed")
    if cfg.mode == "idle":
        _idle_loop(cfg, stop)
    else:
        _poll_loop(cfg, stop)


def _uid_reconnect_state(last_uidnext, last_uidvalidity, new_uidnext, new_uidvalidity):
    """Decide the UID state after an IDLE (re)connect.

    A reconnect must not reset the cursor to the server's current UIDNEXT:
    mail that arrived while the watcher was down would be skipped until the
    hourly sweep. Only the first connect initialises it, or a UIDVALIDITY
    change resets it (and asks for a full sweep).
    """
    if new_uidnext is None:
        return last_uidnext, last_uidvalidity, False
    if last_uidnext is None or last_uidvalidity is None:
        return new_uidnext, new_uidvalidity, False
    if (
        new_uidvalidity is not None
        and last_uidvalidity is not None
        and new_uidvalidity != last_uidvalidity
    ):
        return new_uidnext, new_uidvalidity, True
    return last_uidnext, last_uidvalidity, False


def _next_uidnext(result, current):
    """Advance only when an incremental run succeeded with no action errors.

    Dry runs advance too: switching to live requires a restart, and the startup
    full sweep re-examines everything. Holding the cursor in dry mode would
    make every new message repeat the same incremental work and eventually
    turn into full sweeps.
    """
    if (
        result.get("ok")
        and not result.get("errors")
        and result.get("uidnext")
    ):
        return result["uidnext"]
    return current


def _fallback_uidnext(incremental, result, current):
    """After a full fallback sweep, advance if the sweep completed.

    Per-entry errors are retried by the next hourly sweep; gating on `errors`
    here would turn every new email into another full sweep while a persistent
    entry error exists.
    """
    if result.get("ok") and not result.get("skipped"):
        advance = incremental.get("uidnext") or incremental.get("server_uidnext")
        if advance:
            return advance
    return current


def _idle_loop(cfg, stop):
    backoff = 5
    last_sweep = time.monotonic()
    last_uidnext = None
    last_uidvalidity = None
    while not stop.is_set():
        watcher = idle.IdleWatcher(cfg.gmail_user, cfg.gmail_password)
        try:
            watcher.connect()
            backoff = 5
            state.update_state(
                cfg.state_path,
                watcher="idle",
                watcher_since=state.now_iso(),
                watcher_error=None,
                heartbeat=state.now_iso(),
            )
            log.info("watching INBOX with IDLE")
            last_uidnext, last_uidvalidity, reset = _uid_reconnect_state(
                last_uidnext, last_uidvalidity, watcher.uidnext, watcher.uidvalidity
            )
            if reset:
                log.info("UIDVALIDITY changed; running a full sweep")
                _log_summary("uidvalidity", runner.run_purge(cfg, reason="uidvalidity"))
                last_sweep = time.monotonic()
            while not stop.is_set():
                # Cap the wait so the hourly reconciliation sweep is actually
                # hourly. A plain 29-minute IDLE only checks the clock every
                # third window, which drifts to about 87 minutes.
                until_sweep = 3600 - (time.monotonic() - last_sweep)
                if until_sweep <= 0:
                    _log_summary("hourly", runner.run_purge(cfg, reason="hourly"))
                    last_sweep = time.monotonic()
                    continue
                result = watcher.idle(min(29 * 60, until_sweep))
                if result == "exists":
                    stop.wait(3)  # let a burst finish arriving, then one sweep
                    try:
                        incremental = runner.run_new_mail(
                            cfg,
                            last_uidnext,
                            last_uidvalidity,
                            reason="idle",
                        )
                    except Exception:  # noqa: BLE001
                        log.exception("incremental run failed")
                        incremental = {"fallback": True}
                    if incremental.get("fallback"):
                        result = runner.run_purge(cfg, reason="idle")
                        if incremental.get("uidvalidity"):
                            last_uidvalidity = incremental["uidvalidity"]
                        last_uidnext = _fallback_uidnext(
                            incremental, result, last_uidnext
                        )
                    else:
                        result = incremental
                        last_uidnext = _next_uidnext(result, last_uidnext)
                        if result.get("uidvalidity"):
                            last_uidvalidity = result["uidvalidity"]
                    _log_summary("idle", result)
                    last_sweep = time.monotonic()
                else:
                    watcher.noop()
        except Exception as exc:  # noqa: BLE001
            log.warning("idle watcher: %s (retrying in %ss)", exc, backoff)
            try:
                state.update_state(
                    cfg.state_path,
                    watcher="reconnecting",
                    watcher_error=str(exc),
                    heartbeat=state.now_iso(),
                )
            except Exception:
                pass
            # If IDLE is broken, do not let deletion stop: keep sweeping hourly.
            if time.monotonic() - last_sweep > 3600:
                try:
                    _log_summary("fallback", runner.run_purge(cfg, reason="fallback"))
                except Exception:  # noqa: BLE001
                    log.exception("fallback sweep failed")
                last_sweep = time.monotonic()
            stop.wait(backoff)
            backoff = min(backoff * 2, 300)
        finally:
            watcher.logout()


def _poll_loop(cfg, stop):
    while not stop.is_set():
        try:
            state.update_state(cfg.state_path, watcher="polling")
            _log_summary("poll", runner.run_purge(cfg, reason="poll"))
        except Exception:  # noqa: BLE001
            log.exception("poll run failed")
        stop.wait(cfg.poll_interval + random.uniform(0, 30))


def _check_data_dir(cfg):
    """Fail fast, with the fix, instead of a restart loop on Errno 13."""
    try:
        os.makedirs(cfg.data_dir, exist_ok=True)
        probe = os.path.join(cfg.data_dir, ".write-test")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.unlink(probe)
        return True
    except OSError as exc:
        log.error("DATA_DIR %s is not writable: %s", cfg.data_dir, exc)
        log.error("this container runs as uid %d (the image's app user)", os.getuid())
        log.error("on the docker host, give the bind-mounted directory to that uid:")
        log.error("    sudo chown -R 1000:1000 ./data")
        log.error("then: docker compose restart")
        return False


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    cfg = config.load()
    problems = cfg.problems()
    if problems:
        for problem in problems:
            log.error("config: %s", problem)
        log.error(
            "fill in compose.override.yml (see compose.override.yml.example) "
            "and restart"
        )
        return 2

    if not _check_data_dir(cfg):
        return 2
    try:
        blacklist.ensure(cfg.blacklist_path)
        whitelist.ensure(cfg.whitelist_path)
        quarantine.ensure(cfg.quarantine_path)
    except OSError as exc:
        log.error("cannot create list file: %s", exc)
        return 2

    entries, errors = blacklist.load(cfg.blacklist_path, cfg.allow_freemail_domains)
    hidden, hidden_errors = whitelist.load(cfg.whitelist_path)
    held, held_errors = quarantine.load(cfg.quarantine_path)
    log.info(
        "mode=%s dry_run=%s entries=%d whitelisted=%d quarantine=%d "
        "label=%r age=%s abort_over=%d interval=%ss data=%s",
        cfg.mode,
        cfg.dry_run,
        len(entries),
        len(hidden),
        len(held),
        cfg.quarantine_label,
        cfg.quarantine_age.text,
        cfg.quarantine_abort_over,
        cfg.poll_interval,
        cfg.data_dir,
    )
    for error in errors:
        log.warning(
            "blacklist line %s ignored: %s (%s)",
            error["line"],
            error["entry"],
            error["reason"],
        )
    for error in hidden_errors:
        log.warning(
            "whitelist line %s ignored: %s (%s)",
            error["line"],
            error["entry"],
            error["reason"],
        )
    for error in held_errors:
        log.warning(
            "quarantine line %s ignored: %s (%s)",
            error["line"],
            error["entry"],
            error["reason"],
        )

    if "--check" in argv:
        log.info("configuration OK")
        return 0

    stop = threading.Event()

    def _handle_signal(signum, _frame):
        log.info("signal %s: shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        state.update_state(
            cfg.state_path,
            started=state.now_iso(),
            mode=cfg.mode,
            dry_run=cfg.dry_run,
            heartbeat=state.now_iso(),
            version="1.0.0",
        )
    except OSError as exc:
        log.error("cannot write %s: %s", cfg.state_path, exc)
        log.error("check that DATA_DIR is owned by uid %d", os.getuid())
        return 2

    threads = [
        threading.Thread(target=api.serve, args=(cfg, stop), name="api", daemon=True),
        threading.Thread(target=_heartbeat, args=(cfg, stop), name="heartbeat", daemon=True),
        threading.Thread(target=_worker, args=(cfg, stop), name="worker", daemon=True),
    ]
    for thread in threads:
        thread.start()

    while not stop.is_set():
        stop.wait(1)

    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
