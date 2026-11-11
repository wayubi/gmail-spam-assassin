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


def _idle_loop(cfg, stop):
    backoff = 5
    last_sweep = time.monotonic()
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
            while not stop.is_set():
                result = watcher.idle(29 * 60)
                if result == "exists":
                    stop.wait(3)  # let a burst finish arriving, then one sweep
                    _log_summary("idle", runner.run_purge(cfg, reason="idle"))
                    last_sweep = time.monotonic()
                elif time.monotonic() - last_sweep > 3600:
                    _log_summary("hourly", runner.run_purge(cfg, reason="hourly"))
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
