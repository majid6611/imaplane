# Google Cloud OAuth2 setup for the first live test (Gmail to Dovecot)

Written for: the project owner, who will create a disposable Gmail account and a
Google Cloud OAuth client. **Nothing in this document has been run.** Parts 1 to 3
happen in your browser. Part 4 onward contacts Google (OAuth first, IMAP later) and
waits for your explicit go-ahead. Google's console menus are renamed from time to
time; if a label differs slightly, follow the intent.

## What you will end up with

- A disposable Gmail address, used for nothing else.
- A Google Cloud project containing a **Desktop app** OAuth client, with the consent
  screen in **Testing** mode and the disposable address as the only test user.
- The scope `https://mail.google.com/`, which is what Gmail IMAP requires. It grants
  **full mailbox access**, which is why the account must be disposable.
- `client.json` (the downloaded client, mode 0600) and, later, two token files kept
  fresh by `scripts/oauth_token.py`.

IMAPLANE itself only ever reads a short-lived access token from a file. It never sees
the client secret or the refresh token.

## Part 1: the disposable account (about 10 minutes)

1. Create a new personal Gmail account. Google may ask for a phone number; that is
   between you and Google. Do not reuse an address you care about.
2. Sign in and check IMAP: Gmail, Settings, **See all settings**, **Forwarding and
   POP/IMAP**. If an "IMAP access" switch is shown, set it to enabled and save. (If
   there is no such switch, IMAP is always on.)
3. Use a Workspace (company) account only if you accept that its administrator
   controls whether third-party OAuth apps and IMAP are permitted. A personal account
   avoids that variable for this first test.

## Part 2: the Google Cloud project (about 10 minutes)

The project can belong to the disposable account or to your own account. Owning it
from the disposable account makes cleanup trivial (delete the account, everything
goes), so that is the suggestion here.

1. Open <https://console.cloud.google.com/> signed in as the account that will own the
   project. Accept the terms if asked. **No billing account is needed.**
2. Project picker (top bar), **New project**. Name it `imaplane-test`, **Create**, then
   make sure it is the selected project.
3. You do **not** need to enable the Gmail API for IMAP with OAuth. If a later step
   fails with a message that an API is not enabled, enable "Gmail API" and retry.

## Part 3: consent screen, scope and client (about 15 minutes)

Menu: **APIs & Services**, then **OAuth consent screen** (newer consoles call this
**Google Auth Platform**, with Branding, Audience, Data Access and Clients pages).

1. **Get started / Configure consent screen.**
   - App name: `IMAPLANE test`. User support email: your address.
   - **Audience: External.** (Internal is only for Workspace organizations.)
   - Contact email: your address. Accept the policy, **Create**.
2. **Audience** page: confirm **Publishing status: Testing**. Under **Test users**,
   **Add users** and enter the disposable Gmail address. Only listed addresses can
   authorize an app in Testing. Leave the app unpublished.
3. **Data Access** page: **Add or remove scopes**. In "Manually add scopes" paste
   exactly `https://mail.google.com/`, **Add to table**, **Update**, **Save**. Google
   labels this a *restricted* scope. That is expected; Testing mode lets listed test
   users grant it without Google's verification process.
4. **Clients** page (or **Credentials**, **Create credentials**, **OAuth client ID**):
   - Application type: **Desktop app**. Name: `imaplane-test-desktop`. **Create**.
   - **Download JSON**. Move it to a private directory and lock it down:

     ```sh
     mkdir -m 700 ~/imaplane-live
     mv ~/Downloads/client_secret_*.json ~/imaplane-live/client.json
     chmod 600 ~/imaplane-live/client.json
     ```

   Desktop clients accept loopback redirects (`http://127.0.0.1:<port>`) automatically,
   so no redirect URI needs to be registered.

### What to expect from Testing mode

- When you authorize, Google shows "Google hasn't verified this app". Choose
  **Advanced**, then **Go to IMAPLANE test (unsafe)**. That is normal for your own
  unpublished test app.
- The consent text will say the app can read, compose, send and permanently delete
  email. That is the `mail.google.com` scope; IMAPLANE only reads from a Gmail
  source, but the grant is broader than its behavior.
- **Refresh tokens issued for an External app in Testing expire after 7 days.** Plan
  the test inside that window or authorize again.
- Anything unusual (a security alert, a temporarily locked account) is a result to
  report, not something to work around.

## Part 4: obtain tokens (first contact with Google; wait for the go-ahead)

Run on the same machine as your browser, because the helper listens on a loopback port
only for the redirect.

```sh
cd ~/imaplane-live
python3 /path/to/imaplane/scripts/oauth_token.py authorize --provider google \
    --client-json client.json --login-hint DISPOSABLE@gmail.com \
    --refresh-token-file refresh.token --access-token-file access.token
```

The helper prints one URL. Open it in a browser signed in as the **disposable**
account, approve, and the page will say you can close the tab. The helper then writes
`refresh.token` and `access.token` (both mode 0600) and prints no token.

Keep the access token fresh for the length of a run (it lasts about an hour). Leave
this running in its own terminal:

```sh
python3 /path/to/imaplane/scripts/oauth_token.py refresh --provider google \
    --client-json client.json --refresh-token-file refresh.token \
    --access-token-file access.token --loop
```

IMAPLANE re-reads `access.token` every time it opens a connection, and the file is
replaced atomically, so a reconnect always sees a complete token. If the refresh ever
fails with `invalid_grant`, the refresh token was revoked or expired; authorize again.

If the browser is on another machine, run `authorize` with `--port 8765` and forward it:
`ssh -L 8765:127.0.0.1:8765 <host>`.

## Part 5: first live test, Gmail to Dovecot (needs your go-ahead)

Populate the disposable Gmail inbox with **3 to 5 harmless messages** you create
yourself (send them from another throwaway address, or compose them in Gmail). Do not
import real mail. The full synthetic corpus is loaded into Gmail later, by the
Dovecot-to-Gmail test.

```sh
SCRIPTS=/path/to/imaplane/scripts; BIN=/path/to/imaplane   # a committed, tested build
cd ~/imaplane-live

# 1. Local destination Dovecot (loopback only) and a generated config.
python3 $SCRIPTS/provider_lab.py up --dir lab --roles destination
python3 $SCRIPTS/provider_lab.py config --dir lab --direction gmail-to-dovecot \
    --provider-user DISPOSABLE@gmail.com --token-file access.token \
    --state-dir state --out gmail-to-dovecot.toml

# 2. Read-only look at Gmail: folder names exactly as Gmail reports them.
python3 $SCRIPTS/imap_snapshot.py list --host imap.gmail.com --user DISPOSABLE@gmail.com --token-file access.token

# 3. Independent BEFORE snapshot of the Gmail source.
python3 $SCRIPTS/imap_snapshot.py capture --host imap.gmail.com --user DISPOSABLE@gmail.com \
    --token-file access.token --folder INBOX --out src-before.json

# 4. Migrate, with sanitized diagnostics on.
$BIN --diagnostics-file diag.jsonl migrate --config gmail-to-dovecot.toml --json > report.json

# 5. AFTER snapshots, then the two comparisons.
python3 $SCRIPTS/imap_snapshot.py capture --host imap.gmail.com --user DISPOSABLE@gmail.com \
    --token-file access.token --folder INBOX --out src-after.json
python3 $SCRIPTS/imap_snapshot.py capture --host localhost --port $(python3 -c "import json;print(json.load(open('lab/lab.json'))['ports']['destination'])") \
    --user lab --password-file lab/password --ca-file lab/tls.crt --folder INBOX --out dst.json
python3 $SCRIPTS/imap_snapshot.py same src-before.json src-after.json      # source unchanged?
python3 $SCRIPTS/imap_snapshot.py copy src-before.json dst.json --map INBOX=INBOX

# 6. Rerun must add nothing; verify must agree.
$BIN migrate --config gmail-to-dovecot.toml --json
$BIN verify  --config gmail-to-dovecot.toml --json
```

Pass criteria: `complete` true, exit 0; `same` prints `IDENTICAL`; `copy` prints
`MATCH`; the rerun performs zero APPENDs. Anything else is a finding: stop, keep
`report.json`, `diag.jsonl`, both snapshots and the journal, and do not retry.

`diag.jsonl` is safe to share after a glance: it holds only statuses, response-code
names, timings and counts (see the provider guide for the exact field list). The
snapshots and journal hold hashes, sizes and folder names; keep those private.

## Cleanup

1. `provider_lab.py down --dir lab`, and delete `~/imaplane-live` (client file, tokens,
   state, backups).
2. Revoke the app: <https://myaccount.google.com/permissions> as the disposable
   account, remove `IMAPLANE test`.
3. In Google Cloud, delete the `imaplane-test` project (or delete the whole disposable
   account).
