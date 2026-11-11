"""quarantine.txt: senders whose mail is held, then deleted.

Same syntax and validation as the blacklist: one exact address or `@domain`
per line, `#` comments, blank lines ignored. Free-mail wildcards are refused
for the same reason as the blacklist: this list ends in deletion.

What the runner does with an entry:

  * a message younger than QUARANTINE_AGE is labelled and taken out of Inbox;
  * a message already past that age goes straight to Trash;
  * anything in the label is expired once it passes the age, unless the sender
    is on the whitelist.

The label is one shared folder for the whole list (`QUARANTINE_LABEL`).
"""

from . import blacklist

HEADER = (
    "# gmail-spam-assassin quarantine\n"
    "# one entry per line: an exact address (a@b.com) or a whole domain (@b.com)\n"
    "# '#' starts a comment. Mail from these senders is moved to the quarantine\n"
    "# label, then to Trash once it is older than QUARANTINE_AGE.\n"
    "# A whitelist entry always wins.\n"
)

# This list ends in deletion, so a free-mail wildcard is as dangerous here as
# it is in the blacklist.
ALLOW_FREEMAIL = False


def ensure(path):
    blacklist.ensure(path, HEADER)


def load(path):
    return blacklist.load(path, ALLOW_FREEMAIL)


def add(path, addresses):
    return blacklist.add(path, addresses, ALLOW_FREEMAIL, HEADER)


def remove(path, addresses):
    return blacklist.remove(path, addresses)


def matches(address, entries):
    """Which quarantine entry covers this address, or None."""
    return blacklist.matches(address, entries)
