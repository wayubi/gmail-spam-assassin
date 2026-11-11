"""whitelist.txt: senders that are never deleted and never listed.

Same syntax as the blacklist: one exact address or `@domain` per line, `#`
comments, blank lines ignored. The file is parsed by the same code, so
validation and atomic edits behave identically.

Two effects, and the first one is the important one:

  * the runner skips these senders even if they also match the blacklist;
  * the web page and the CLI hide them, so they stop cluttering the view.

Free-mail wildcards are allowed here (`@gmail.com`). In the blacklist they are
refused because deleting every Gmail sender could empty a mailbox; hiding them
is harmless.
"""

from . import blacklist

HEADER = (
    "# gmail-spam-assassin whitelist\n"
    "# one entry per line: an exact address (a@b.com) or a whole domain (@b.com)\n"
    "# '#' starts a comment. These senders are never deleted, and are hidden\n"
    "# from the mail and sender lists. A whitelist entry wins over the blacklist.\n"
)

# Hiding is safe, so the free-mail wildcard rule does not apply here.
ALLOW_FREEMAIL = True


def ensure(path):
    blacklist.ensure(path, HEADER)


def load(path):
    return blacklist.load(path, ALLOW_FREEMAIL)


def add(path, addresses):
    return blacklist.add(path, addresses, ALLOW_FREEMAIL, HEADER)


def remove(path, addresses):
    return blacklist.remove(path, addresses)


def matches(address, entries):
    """Which whitelist entry covers this address, or None."""
    return blacklist.matches(address, entries)
