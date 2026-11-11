"""Configuration, read from the environment.

Secrets (GMAIL_APP_PASSWORD, SPAM_API_TOKEN) live in compose.override.yml and
are never logged, never written to the audit log and never returned by the API.
"""

import os
from dataclasses import dataclass

from . import age

PLACEHOLDERS = {
    "",
    "change_me",
    "changeme",
    "change_me_16_chars",
    "paste_16_char_app_password",
    "change_me_long_random",
    "you@example.com",
}


def _str(name, default=""):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _int(name, default):
    raw = _str(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _bool(name, default):
    raw = _str(name)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on", "y")


def _label_problem(label):
    """Refuse anything that is not a plain, ASCII, user-created Gmail label.

    The label reaches an IMAP STORE, and the system folders have meanings this
    app must never apply to a quarantine: filing into Trash would delete, into
    Spam would hide, into All Mail would do nothing. So only user labels.
    """
    if not label:
        return "is empty"
    if len(label) > 128:
        return "is longer than 128 characters"
    if not label.isascii():
        return "must be ASCII (Gmail's IMAP layer is unreliable for others)"
    for char in label:
        if ord(char) < 32 or ord(char) == 127:
            return "contains a control character"
    if '"' in label or "\\" in label:
        return "contains a quote or backslash"
    lowered = label.lower()
    if label.startswith("\\") or lowered in ("inbox", "all mail", "spam", "trash"):
        return "is a system folder, not a user label"
    if lowered.startswith("[gmail]") or lowered.startswith("[google mail]"):
        return "is a system folder, not a user label"
    return None


@dataclass(frozen=True)
class Config:
    gmail_user: str
    gmail_password: str
    api_token: str
    data_dir: str
    mode: str
    poll_interval: int
    dry_run: bool
    max_delete_per_run: int
    max_trash_per_run: int
    list_days: int
    allow_freemail_domains: bool
    quarantine_label: str
    quarantine_age: age.Age
    quarantine_age_error: str
    quarantine_abort_over: int
    api_host: str
    api_port: int

    @property
    def blacklist_path(self):
        return os.path.join(self.data_dir, "blacklist.txt")

    @property
    def whitelist_path(self):
        return os.path.join(self.data_dir, "whitelist.txt")

    @property
    def quarantine_path(self):
        return os.path.join(self.data_dir, "quarantine.txt")

    @property
    def audit_path(self):
        return os.path.join(self.data_dir, "audit.jsonl")

    @property
    def state_path(self):
        return os.path.join(self.data_dir, "state.json")

    def problems(self):
        """Human-readable list of things that must be fixed before running."""
        out = []
        if self.gmail_user.lower() in PLACEHOLDERS or "@" not in self.gmail_user:
            out.append("GMAIL_USER is not a real address")
        if (
            self.gmail_password.lower() in PLACEHOLDERS
            or len(self.gmail_password) < 12
        ):
            out.append(
                "GMAIL_APP_PASSWORD is not set (Google app password, 16 characters)"
            )
        if self.api_token.lower() in PLACEHOLDERS or len(self.api_token) < 16:
            out.append("SPAM_API_TOKEN is not set (16+ random characters)")
        if self.mode not in ("idle", "poll"):
            out.append("MODE must be 'idle' or 'poll'")
        if self.max_delete_per_run < 1:
            out.append("MAX_DELETE_PER_RUN must be at least 1")
        if self.max_trash_per_run < 1:
            out.append("MAX_TRASH_PER_RUN must be at least 1")
        if self.quarantine_age_error:
            out.append(self.quarantine_age_error)
        label_problem = _label_problem(self.quarantine_label)
        if label_problem:
            out.append("QUARANTINE_LABEL %r %s" % (self.quarantine_label, label_problem))
        if self.quarantine_abort_over < 0:
            out.append("QUARANTINE_ABORT_OVER cannot be negative")
        return out


def load():
    age_raw = _str("QUARANTINE_AGE", "14d") or "14d"
    try:
        quarantine_age = age.Age.parse(age_raw)
        age_error = ""
    except ValueError as exc:
        # Keep a usable object so the rest of the config can be inspected; the
        # startup problems list refuses to run until the value is fixed.
        quarantine_age = age.Age(14, "d")
        age_error = "QUARANTINE_AGE %r is not valid: %s" % (age_raw, exc)

    return Config(
        gmail_user=_str("GMAIL_USER"),
        # Google shows app passwords in groups of four; people paste the spaces.
        gmail_password=_str("GMAIL_APP_PASSWORD").replace(" ", ""),
        api_token=_str("SPAM_API_TOKEN"),
        data_dir=_str("DATA_DIR", "/data"),
        mode=_str("MODE", "idle").lower(),
        poll_interval=max(60, _int("POLL_INTERVAL", 900)),
        dry_run=_bool("DRY_RUN", True),
        max_delete_per_run=max(1, _int("MAX_DELETE_PER_RUN", 500)),
        max_trash_per_run=max(1, _int("MAX_TRASH_PER_RUN", 200)),
        list_days=max(1, min(365, _int("LIST_DAYS", 30))),
        allow_freemail_domains=_bool("ALLOW_FREEMAIL_DOMAINS", False),
        quarantine_label=_str("QUARANTINE_LABEL", "Quarantine") or "Quarantine",
        quarantine_age=quarantine_age,
        quarantine_age_error=age_error,
        quarantine_abort_over=max(0, _int("QUARANTINE_ABORT_OVER", 0)),
        api_host=_str("API_HOST", "0.0.0.0"),
        api_port=_int("API_PORT", 8080),
    )
