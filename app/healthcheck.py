"""Container healthcheck: is the process actually alive and doing work?

The heartbeat is written every 60 s by the main process. A run in progress can
take a while on a big mailbox, so the threshold is generous (45 minutes).
"""

import sys
from datetime import datetime, timezone

from . import config, state

MAX_AGE = 45 * 60


def main():
    cfg = config.load()
    data = state.read_state(cfg.state_path)
    stamp = data.get("heartbeat") or data.get("updated")
    if not stamp:
        print("unhealthy: no heartbeat yet")
        return 1
    try:
        when = datetime.fromisoformat(stamp)
    except ValueError:
        print("unhealthy: unreadable heartbeat %r" % stamp)
        return 1
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - when).total_seconds()
    if age > MAX_AGE:
        print("unhealthy: last heartbeat %.0fs ago" % age)
        return 1
    print("ok: heartbeat %.0fs ago, watcher=%s" % (age, data.get("watcher")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
