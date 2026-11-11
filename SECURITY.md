# Security

This tool holds a credential that can read and delete every message in a Gmail
account. Treat a deployment as sensitive.

## Never post these in an issue or discussion

- Your `GMAIL_APP_PASSWORD` (16 characters, spaces removed)
- Your `SPAM_API_TOKEN`
- Lines from `data/audit.jsonl`, `data/state.json`, `data/blacklist.txt`,
  `data/whitelist.txt` or `data/quarantine.txt` — they contain sender addresses,
  subjects and UIDs
- Screenshots of the web UI with real mail visible
- The contents of `compose.override.yml`

If an app password is ever exposed, revoke it immediately at Google Account →
Security → App passwords. Deleting a commit or a file does not help: the
credential must be invalidated.

## Reporting a vulnerability

Open a private report with GitHub Security Advisories (repository → Security →
Report a vulnerability). Please do not open a public issue for anything that
could cause mail loss or credential exposure.

## Design guarantees

- `DRY_RUN=true` is the default; nothing is deleted until it is turned off.
- The app never issues `EXPUNGE` or sets `\Deleted`. Deletion is a `COPY` into
  `[Gmail]/Trash`, so mail is recoverable for 30 days.
- A live run refuses to start if `[Gmail]/Trash` is not visible over IMAP.
- A whitelist entry always wins over both delete lists, so a sender you have
  protected is never deleted even if the others match it.
- Quarantine files mail by editing labels (`X-GM-LABELS`), which cannot delete.
  Its only deletion path is the same `COPY` into `[Gmail]/Trash`.
- Quarantine expiry only touches senders still on the quarantine list, so
  removing an entry cancels its queued deletions.
- Message bodies are never fetched, logged or stored; only `From`, `Subject`,
  `Date`, UID and Gmail message ID are used.
