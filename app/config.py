"""Configuration, read from the environment.

Secrets (GMAIL_APP_PASSWORD, SPAM_API_TOKEN) live in compose.override.yml and
are never logged, never written to the audit log and never returned by the API.
"""

import os
from dataclasses import dataclass

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
    list_days: int
    allow_freemail_domains: bool
    api_host: str
    api_port: int

    @property
    def blacklist_path(self):
        return os.path.join(self.data_dir, "blacklist.txt")

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
        return out


def load():
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
        list_days=max(1, min(365, _int("LIST_DAYS", 30))),
        allow_freemail_domains=_bool("ALLOW_FREEMAIL_DOMAINS", False),
        api_host=_str("API_HOST", "0.0.0.0"),
        api_port=_int("API_PORT", 8080),
    )
