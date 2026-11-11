import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.idle import IdleWatcher  # noqa: E402

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


def read_line(sock, buf):
    while b"\r\n" not in buf[0]:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("closed")
        buf[0] += chunk
    line, _, rest = buf[0].partition(b"\r\n")
    buf[0] = rest
    return line


print("idle: EXISTS wakes the watcher")
left, right = socket.socketpair()
buf = [b""]
seen = []


def server_exists():
    line = read_line(right, buf)
    seen.append(line)
    right.sendall(b"+ idling\r\n")
    right.sendall(b"* 3 EXISTS\r\n")
    line = read_line(right, buf)
    seen.append(line)
    right.sendall(b"W1 OK IDLE terminated\r\n")


thread = threading.Thread(target=server_exists)
thread.start()
watcher = IdleWatcher("u", "p")
watcher.sock = left
result = watcher.idle(5)
thread.join(timeout=5)
check("returns exists", result == "exists", result)
check("sent IDLE", seen[0].endswith(b" IDLE"), seen)
check("sent DONE", seen[1] == b"DONE", seen)

print("idle: window expiry re-issues")
left, right = socket.socketpair()
buf = [b""]
seen = []


def server_timeout():
    line = read_line(right, buf)
    seen.append(line)
    right.sendall(b"+ idling\r\n")
    time.sleep(0.2)
    line = read_line(right, buf)
    seen.append(line)
    right.sendall(b"W1 OK IDLE terminated\r\n")


thread = threading.Thread(target=server_timeout)
thread.start()
watcher = IdleWatcher("u", "p")
watcher.sock = left
started = time.monotonic()
result = watcher.idle(0.3)
elapsed = time.monotonic() - started
thread.join(timeout=5)
check("returns timeout", result == "timeout", result)
check("waited about the window", 0.25 <= elapsed < 3, elapsed)
check("sent DONE after window", seen[1] == b"DONE", seen)

print("idle: BYE is an error")
left, right = socket.socketpair()
buf = [b""]


def server_bye():
    read_line(right, buf)
    right.sendall(b"+ idling\r\n")
    right.sendall(b"* BYE going away\r\n")


thread = threading.Thread(target=server_bye)
thread.start()
watcher = IdleWatcher("u", "p")
watcher.sock = left
try:
    watcher.idle(2)
    check("BYE raises", False)
except Exception as exc:
    check("BYE raises", "BYE" in str(exc), exc)
thread.join(timeout=5)

print("idle: NOOP roundtrip")
left, right = socket.socketpair()
buf = [b""]


def server_noop():
    line = read_line(right, buf)
    tag = line.split(b" ")[0]
    right.sendall(b"* 3 EXISTS\r\n")
    right.sendall(tag + b" OK NOOP completed\r\n")


thread = threading.Thread(target=server_noop)
thread.start()
watcher = IdleWatcher("u", "p")
watcher.sock = left
watcher.noop()
check("noop tolerated untagged EXISTS", True)
thread.join(timeout=5)

print("\n%d passed, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
