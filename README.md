# gmail-spam-assassin

Deletes Gmail mail from senders you blacklist, over IMAP, and gives you a small
web page / JSON API / CLI to pick those senders and edit the list. A whitelist
does the opposite: senders you never want deleted, hidden from the views so they
stop cluttering it. A third list, quarantine, files mail under a label for a
configurable number of days and then moves it to Trash.

The blacklist is a file in this container. Nothing here touches Gmail's block
list or filters: the script connects to `imap.gmail.com` as your account,
finds matching messages and moves them to Gmail's Trash. Because IMAP *is* the
mailbox, the deletion shows up in Gmail immediately.

**Deletion stops at Trash.** Nothing in this app ever expunges. A match is
*moved* to `[Gmail]/Trash` with an IMAP `COPY`, so everything it removes is
recoverable for 30 days, after which Gmail empties Trash on its own.

---

## How a deletion actually works

Gmail models labels as folders, so "delete" is not one step:

| Step | Where | Result |
|---|---|---|
| 1 | `[Gmail]/All Mail` | search `X-GM-RAW "from:<sender>"` |
| 2 | — | parse the `From:` header, require an exact address (or exact domain) match |
| 3 | `[Gmail]/All Mail` → `[Gmail]/Trash` | `UID COPY` into Trash → the message leaves Inbox/All Mail, 30-day clock starts |
| 4 | `[Gmail]/Spam` | same, for mail that never reached the inbox |
| 5 | `[Gmail]/Trash` | **never written to** — this is the undo window |

Step 2 exists because Gmail's `from:` search is a substring match. Without the
header check, blacklisting `@spam.example` would also delete
`someone@notspam.example`. There is a regression test for exactly that.

**Why `COPY` and not `\Deleted` + `EXPUNGE`.** Gmail does not map expunge to
"delete". What an expunge does is decided by an account setting, *"When a
message is marked as deleted and expunged from the last visible IMAP folder"*,
with three possible values:

| Gmail setting | What an expunge would do here |
|---|---|
| *Archive the message* (**default**) | nothing useful — the message stays in All Mail |
| *Move the message to the Trash* | works, but only because of an invisible account setting |
| *Immediately delete forever* | destroys the mail, no Trash, no recovery |

Two of those three break the "stops at Trash" promise, and the setting is
invisible from inside the container. `COPY` into Trash is a single explicit
instruction that cannot be reinterpreted, so the app never issues `EXPUNGE` and
never depends on that setting.

Because of this, **Trash must be visible over IMAP** (`Show in IMAP` for the
Trash system label). If it is not, a live run refuses to delete anything and
says so; a dry run warns and continues.


---

## Safety rails

| Rail | Behaviour |
|---|---|
| `DRY_RUN=true` (default) | searches, verifies and audit-logs, deletes nothing |
| Trash is terminal | `[Gmail]/Trash` is only ever a `COPY` destination, never opened for writing, so a mistake is recoverable 30 days |
| No expunge, ever | `EXPUNGE` / `\Deleted` are never issued, so Gmail's account-level expunge setting cannot turn this into a permanent delete |
| Fails closed without Trash | if `[Gmail]/Trash` is not visible over IMAP, a live run deletes nothing and reports why |
| `MAX_DELETE_PER_RUN=500` | a bad blacklist line cannot wipe the mailbox in one cycle |
| Whitelist wins | a whitelist entry beats both delete lists; nothing from it is deleted, and the skip is counted |
| Quarantine is reversible until expiry | filing is an `X-GM-LABELS` edit (label + remove Inbox), never a delete |
| Quarantine ages by message date | `INTERNALDATE` first, `Date:` header as fallback; a future date cannot postpone deletion forever |
| Quarantine only touches listed senders | removing a sender stops its queued deletions; leftover mail is reported as stale |
| Free-mail wildcards refused | `@gmail.com`, `@outlook.com`, … are rejected in both delete lists; they are allowed in the whitelist, which cannot delete |
| Strict entry validation | no whitespace, quotes, backslashes or control characters reach an IMAP search |
| Exact-sender verification | parsed `From:` must match the entry, not just the search hit |
| Metadata-only audit | sender, subject, date, uid; message bodies are never fetched or stored |
| `X-GM-EXT-1` required | refuses to run if the server does not advertise Gmail's search extension |

---

## Setup (on the docker host)

### 1. Prerequisites in Gmail

- **IMAP enabled**: Gmail → Settings → Forwarding and POP/IMAP → *Enable IMAP*.
- **Trash visible over IMAP**: Gmail → Settings → Labels → *System labels* →
  **Trash** → *Show in IMAP*. This is off by default. Deletion is a `COPY` into
  `[Gmail]/Trash`, so without it a live run refuses to delete anything.
  (Optional: the same switch on **Spam**, if you also want spam swept.)
- **Quarantine label**: create it in Gmail if you prefer (e.g. `Notifications`),
  or let the first quarantine run create it over IMAP. If you create it
  yourself, Settings → Labels is also where *Show in IMAP* lives; a label the
  app created is visible automatically. Set its name in `QUARANTINE_LABEL`.
- **Leave the expunge setting alone**: *Forwarding and POP/IMAP → "When a
  message is marked as deleted and expunged from the last visible IMAP
  folder"*. This app never expunges, so the setting does not matter to it —
  and *Immediately delete forever* would break any other IMAP client you use.
- **2-Step Verification on** (required before app passwords exist).
- **App password**: Google Account → Security → App passwords → create one for
  "Mail". You get 16 characters; spaces are fine, they are stripped.

### 2. Fill in the secrets

```sh
cd gmail-spam-assassin
cp compose.override.yml.example compose.override.yml
$EDITOR compose.override.yml
```

Set `GMAIL_USER` to the account you want cleaned up, `GMAIL_APP_PASSWORD` to the
16-character app password, and `SPAM_API_TOKEN` to any long random string
(`openssl rand -hex 24`). `TZ` is optional; it only affects timestamps in logs.

`compose.override.yml` is gitignored. It holds a full-mailbox credential — do
not commit it, paste it into an issue, or put it in a README.

### 3. Give the data directory to the container user

The image runs as uid/gid 1000 with a read-only root filesystem; `/data` is the
only writable path and it is a bind mount.

```sh
sudo install -d -m 750 -o 1000 -g 1000 data
sudo chown -R 1000:1000 data
```

### 4. Build and start

```sh
docker compose up -d --build
docker compose ps
docker compose logs -f --tail=50
```

First start is a **dry run**: it logs what it *would* delete and leaves Gmail
untouched.

---

## Verify before enabling deletion

```sh
# what folders this account exposes (Trash must be in the list)
docker exec gmail-spam-assassin spam-assassin mailboxes

# what does it think the state is?
docker exec gmail-spam-assassin spam-assassin status

# force a dry run and look at the result
docker exec gmail-spam-assassin spam-assassin run --dry-run

# the audit log: one JSON line per matched message
docker exec gmail-spam-assassin tail -n 20 /data/audit.jsonl
```

Check that the `from` addresses in the audit lines are the ones you meant. Only
then turn deletion on:

```yaml
# compose.override.yml
services:
  gmail-spam-assassin:
    environment:
      DRY_RUN: "false"
```

```sh
docker compose up -d
docker exec gmail-spam-assassin spam-assassin run --live
```

Then look in Gmail's Trash. That is the whole verification: the message must be
in Trash, not merely missing from the inbox.

---

## Using it

### Web page

`http://gmail-spam-assassin:8080/` from inside the docker network, or publish it
through a reverse proxy. `deploy/nginx.conf` is a template: set your domain and
certificate paths in it, copy it into your nginx `conf.d`, and attach this
container to the proxy's network in `compose.override.yml` (the example file
shows how). Then reload nginx.

```sh
sudo cp deploy/nginx.conf /etc/nginx/conf.d/spam-assassin.example.com.conf
sudo nginx -t && sudo nginx -s reload
```

Then open `https://spam-assassin.example.com/`. The page asks for the API token
once and keeps it in the browser's localStorage.

Five tabs: **Recent mail** (per-message rows, subject + sender), **Senders**
(grouped by address with counts, the fast way to blacklist a bulk sender),
**Blacklist** (add and remove), **Whitelist** (senders you never want deleted,
hidden from both lists), and **Quarantine** (label, hold, then delete). Buttons
on the mail and sender rows add the selection to any of the three lists. "Run
now" triggers a cycle and shows the result.

### CLI

```sh
docker exec gmail-spam-assassin spam-assassin status
docker exec gmail-spam-assassin spam-assassin senders --days 7
docker exec gmail-spam-assassin spam-assassin list --days 30 --limit 50
docker exec gmail-spam-assassin spam-assassin add someone@example.com @spam.example
docker exec gmail-spam-assassin spam-assassin rm someone@example.com
docker exec gmail-spam-assassin spam-assassin blacklist
docker exec gmail-spam-assassin spam-assassin whitelist
docker exec gmail-spam-assassin spam-assassin allow someone@example.com @spam.example
docker exec gmail-spam-assassin spam-assassin disallow someone@example.com
docker exec gmail-spam-assassin spam-assassin quarantine
docker exec gmail-spam-assassin spam-assassin hold someone@example.com @spam.example
docker exec gmail-spam-assassin spam-assassin release someone@example.com
docker exec gmail-spam-assassin spam-assassin mailboxes
docker exec gmail-spam-assassin spam-assassin run --dry-run
docker exec gmail-spam-assassin spam-assassin audit --limit 20
```

Add `--json` for raw output.

### API

Every route except `/` and `/healthz` needs `X-Api-Token` (or
`Authorization: Bearer <token>`).

```sh
T=$(grep SPAM_API_TOKEN compose.override.yml | cut -d'"' -f2)
B=http://gmail-spam-assassin:8080
H="X-Api-Token: $T"

curl -s -H "$H" $B/status | jq .
curl -s -H "$H" "$B/messages?days=7&limit=50" | jq '.messages[:3]'
curl -s -H "$H" "$B/senders?days=30" | jq '.senders[:10]'
curl -s -H "$H" $B/blacklist | jq .

curl -s -H "$H" -H 'Content-Type: application/json' \
  -d '{"addresses":["someone@example.com","@spam.example"]}' \
  $B/blacklist | jq .

curl -s -H "$H" -H 'Content-Type: application/json' \
  -d '{"addresses":["someone@example.com"]}' \
  $B/blacklist/remove | jq .

curl -s -H "$H" -H 'Content-Type: application/json' -d '{"dry_run":true}' $B/run | jq .
curl -s -H "$H" "$B/audit?limit=20" | jq -r '.lines[] | [.ts,.action,.from,.subject] | @tsv'
```

| Route | Purpose |
|---|---|
| `GET /status` | mode, dry-run, watcher state, last run, blacklist size |
| `GET /messages?days=&limit=&folder=all\|inbox\|spam` | per-message rows |
| `GET /senders?days=&limit=` | grouped by address with counts |
| `GET /blacklist` | entries plus any rejected lines |
| `GET /whitelist` | same, for the never-delete / hide list |
| `GET /quarantine` | entries, plus the label, age and current cutoff |
| `GET /mailboxes` | IMAP folders this account exposes, and how All Mail / Spam / the quarantine label resolved |
| `POST /blacklist` | `{"addresses": [...]}` |
| `POST /blacklist/remove` | `{"addresses": [...]}` |
| `DELETE /blacklist/<address>` | remove one (URL-encoded) |
| `POST /whitelist` | add to the never-delete / hide list |
| `POST /whitelist/remove` | `{"addresses": [...]}` |
| `DELETE /whitelist/<address>` | remove one (URL-encoded) |
| `POST /quarantine` | add to the hold-then-delete list |
| `POST /quarantine/remove` | `{"addresses": [...]}` |
| `DELETE /quarantine/<address>` | remove one (URL-encoded) |
| `POST /run` | `{"dry_run": true\|false}`, defaults to `DRY_RUN` |
| `GET /audit?limit=` | recent audit records |

---

## Blacklist, whitelist and quarantine

All three live in `/data` and use the same format, one entry per line:

```
# comments and blank lines are ignored
hello@example.com        exact address
@example.com             every sender at that domain
```

| File | Meaning |
|---|---|
| `blacklist.txt` | senders whose mail is moved to Trash immediately |
| `whitelist.txt` | senders that are **never** deleted, and are hidden from the mail and sender lists |
| `quarantine.txt` | senders whose mail is filed under a label, then deleted once it is older than `QUARANTINE_AGE` |

A whitelist entry wins over everything. If an address is in both a delete list
and the whitelist, nothing from it is deleted, and the run summary says how many
messages it skipped (`suppressed`) so the skip is never silent. The web page and
the CLI also stop listing those senders, and report `N hidden by whitelist` so
the filtering is visible rather than mysterious.

Quarantine wins over the blacklist: a sender in both is held and deleted later
rather than trashed immediately, and the run warns about the overlap.

Edits are picked up on the next read or run; no restart. The API rewrites the
files atomically and preserves your comments and ordering. `@gmail.com`-style
wildcards are refused in both delete lists unless you set
`ALLOW_FREEMAIL_DOMAINS=true`; they are always allowed in the whitelist, where
they can only hide mail, never delete it.

### Quarantine

```yaml
# compose.override.yml
QUARANTINE_LABEL: "Notifications"   # create it in Gmail, Show in IMAP on
QUARANTINE_AGE: "3m"                # 14d, 3 months, 1y ...
```

Each run does three things:

1. **Expire.** The server is asked for messages in the label whose internal
   date is before the cutoff (`UID SEARCH BEFORE`). Only those due messages are
   fetched — the thousands of younger held messages are never transferred or
   walked. The exact timestamp is checked again before anything is copied to
   Trash, because IMAP dates are day-granular.
2. **File.** A matching message younger than the age gets the label and loses
   `\Inbox`, so it leaves the inbox but stays in All Mail under the label.
3. **Delete immediately.** A matching message already older than the age goes
   straight to Trash; it never enters the label. Adding a sender is therefore
   retroactive: an old backlog is cleaned up under `MAX_DELETE_PER_RUN`, while
   recent mail is held normally.

The age is measured from the message itself: `INTERNALDATE` (Gmail's receive
time) first, the `Date:` header as a fallback, future dates clamped to now.
Days are exact 24-hour periods; months and years are calendar arithmetic
clamped to the last valid day, so three months before 31 May is 28/29 February.

The `MAX_DELETE_PER_RUN` cap (500) and a 2,000-message fetch ceiling only come
into play when a large batch becomes due at once — for example after lowering
`QUARANTINE_AGE` from three years to two weeks. Normal runs fetch a handful of
due messages and leave the rest of the label alone.

| Setting | Default | Meaning |
|---|---|---|
| `QUARANTINE_LABEL` | `Quarantine` | one shared label for the whole list |
| `QUARANTINE_AGE` | `14d` | days (`14d`), months (`3m`) or years (`1y`) |
| `QUARANTINE_ABORT_OVER` | `0` (off) | if more than N messages would expire in one run, delete none and report |

Details that follow from the design:

- The label is the waiting room, not a permanent archive: held mail is deleted
  when it crosses the age, so the real lifetime is the age plus Gmail's 30 days
  in Trash.
- Removing a sender stops its **queued** deletions too, because expiry only
  touches senders still on the list. Its mail stays in the label; it is
  reported as stale when it reaches the age, and is never deleted unless the
  sender is added back. Remove the label from those messages if you want it
  gone.
- The label is created automatically on the first run that has a quarantine
  entry, using IMAP `CREATE` (Gmail maps that onto a label). If creation fails,
  the run files and deletes nothing through quarantine and reports the server's
  reason; the blacklist still works.
- Free-mail wildcards are refused, because this list ends in deletion.
- Spam is not quarantined: only All Mail is searched, so mail that Gmail has
  already classified as spam is left to the blacklist (or Gmail's own 30-day
  spam cleanup).

---

## Configuration

Everything in `compose.yml` is generic. Set machine-specific values (credentials,
`TZ`, `hostname`, a private docker network) in `compose.override.yml`, which
Compose merges automatically.

| Variable | Default | Meaning |
|---|---|---|
| `GMAIL_USER` | — | Gmail address |
| `GMAIL_APP_PASSWORD` | — | 16-character app password (spaces stripped) |
| `SPAM_API_TOKEN` | — | required by the API |
| `MODE` | `idle` | `idle` (push) or `poll` (every `POLL_INTERVAL`) |
| `POLL_INTERVAL` | `900` | seconds, poll mode only |
| `DRY_RUN` | `true` | `false` to actually move mail to Trash |
| `MAX_DELETE_PER_RUN` | `500` | messages per cycle |
| `LIST_DAYS` | `30` | default window for listing |
| `ALLOW_FREEMAIL_DOMAINS` | `false` | allow `@gmail.com` and friends |
| `QUARANTINE_LABEL` | `Quarantine` | shared Gmail label for held mail |
| `QUARANTINE_AGE` | `14d` | hold period: `14d`, `3m`, `1y` |
| `QUARANTINE_ABORT_OVER` | `0` | refuse to expire more than N in one run; 0 disables |
| `TZ` | `UTC` | container timezone (affects log timestamps only) |

### IDLE vs poll

`MODE=idle` holds one connection on `INBOX` and reacts to `EXISTS` within
seconds. It re-issues IDLE every 29 minutes (Gmail drops it at 30), backs off
exponentially on disconnect, and still runs a **full reconciliation sweep every
hour** plus one on startup. The sweep is what makes IDLE safe: a missed event
heals itself. `MODE=poll` is the fallback and uses a short connection every
`POLL_INTERVAL`.

Listing and API calls use their own short-lived connections, so a browser
request cannot stall the watcher.

---

## Operations

```sh
docker compose logs -f                 # JSON-ish audit summaries + API access log
docker exec gmail-spam-assassin spam-assassin status
docker inspect --format '{{.State.Health.Status}}' gmail-spam-assassin
docker compose restart                 # picks up blacklist changes anyway, not needed for that
docker compose down                    # never `down -v`: it would delete /data
```

State lives in `./data`:

| File | Contents |
|---|---|
| `blacklist.txt` | the list, hand-editable |
| `whitelist.txt` | never-delete / hidden senders, hand-editable |
| `quarantine.txt` | label-then-delete senders, hand-editable |
| `audit.jsonl` | one line per matched message and one per run; metadata only |
| `state.json` | last run, counts, watcher state, heartbeat |

Healthcheck: the main process writes a heartbeat every 60 s; the container is
unhealthy when it is older than 45 minutes.

**Undo.** Open Gmail → Trash and restore. Deletion never goes past Trash, and
removing an entry from the blacklist stops future matches immediately. For
quarantine, removing an entry also stops its queued deletions; anything already
filed stays in the label, reported as stale, until you clear it.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `config: GMAIL_APP_PASSWORD is not set` | the placeholder in `compose.override.yml` was not replaced |
| `login failed: ... AUTHENTICATIONFAILED` | wrong/revoked app password, or IMAP disabled in Gmail settings, or 2FA off |
| `cannot use DATA_DIR /data: Permission denied` | `sudo chown -R 1000:1000 data` |
| `cannot open [Gmail]/All Mail` | unusual folder naming; the code also tries `[Google Mail]/…`; run `spam-assassin mailboxes` to see what exists |
| `[Gmail]/Spam is not exposed over IMAP` | Gmail → Settings → Labels → System labels → **Spam** → *Show in IMAP*. Without it, spam is not swept (everything else still works) |
| `[Gmail]/Trash is not exposed over IMAP` | Gmail → Settings → Labels → System labels → **Trash** → *Show in IMAP*. A live run refuses to delete until this is on, because there would be no recovery window |
| `quarantine label ... could not be created` | Gmail refused `CREATE` (name clash, reserved name, or IMAP disabled). Create it manually under Settings → Labels and tick *Show in IMAP* |
| quarantine never files anything | `QUARANTINE_AGE` may already have passed for that mail, in which case it goes straight to Trash; check the run summary |
| `QUARANTINE_ABORT_OVER` warning | more messages would expire than the brake allows; raise it deliberately, or leave it as a safety stop |
| run reports `matched` but nothing leaves the inbox | `DRY_RUN=true`, or the messages are already in Trash |
| a sender still appears | different address than the one blacklisted (display name ≠ address), or it arrived in Spam and the hourly sweep has not run yet |
| container unhealthy | check logs; a very large first sweep can take minutes, but the heartbeat runs in its own thread |
| `refusing a free-mail domain wildcard` | add the exact address instead, or set `ALLOW_FREEMAIL_DOMAINS=true` deliberately |

---

## Layout

```
compose.yml            service definition (no published ports)
compose.override.yml   your secrets and host-specific values (gitignored)
compose.override.yml.example  template for the file above
.dockerignore          keeps data/ and the override out of the build context
Dockerfile             python:3.12-alpine, uid 1000, read-only rootfs
app/config.py          environment -> Config, placeholder detection
app/blacklist.py       parse, validate, atomic add/remove
app/whitelist.py       same, for the never-delete / hide list
app/quarantine.py      same, for the label-then-delete list
app/age.py             retention ages: 14d, 3m, 1y, with calendar maths
app/imap.py            imaplib: search, verify, COPY to Trash, parsing
app/idle.py            raw-socket IDLE watcher (imaplib is unsafe for this)
app/listing.py         /messages and /senders, 60 s cache, read-only
app/runner.py          one purge run, caps, audit, state
app/api.py             JSON API + static page
app/static/index.html  the web page (vanilla JS, no build)
app/healthcheck.py     heartbeat freshness
app/main.py            threads: api, heartbeat, worker
tools/cli.py           `spam-assassin` inside the container
deploy/nginx.conf      optional reverse-proxy vhost
data/                  blacklist.txt, whitelist.txt, quarantine.txt, audit.jsonl, state.json
```

Gmail filters are independent of this tool: it never reads, creates or edits
them. A filter that already deletes mail at delivery still runs first, and this
container then finds nothing left to do.
