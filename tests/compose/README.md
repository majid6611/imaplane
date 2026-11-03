# Isolated IMAPLANE Compose lab

Two real Dovecot IMAP servers, synthetic mail, private storage, a test CA and the
current IMAPLANE CLI. No production configuration or credentials are used. The
migration code is unchanged; this lab builds the current source in the existing
Rust build stage and adds a separate disposable tools image.

## Requirements

- Linux amd64 with a local Unix-socket Docker daemon and Docker Compose/buildx.
- Python 3.11+ and OpenSSL on the host. No host Rust installation or Python
  packages are required for this lab.
- Docker access for your user. The first image/build needs internet access to
  download images, Rust and build dependencies; runtime IMAP traffic stays on an
  internal Docker network. Native arm64 and other hosts have not been tested here.

From the repository root:

```sh
# Offline checks of dataset generation and harness safety guards:
python3 -m unittest discover -s tests/compose -p 'test_*.py'

# Create/build the two servers, generate test certificates, seed all messages:
./scripts/lab.sh up
./scripts/lab.sh status

# Read-only discovery and preflight:
./scripts/lab.sh cli inspect
./scripts/lab.sh cli migrate --dry-run

# Actual migration, independent verification, and safe resume:
./scripts/lab.sh cli migrate
./scripts/lab.sh cli verify
./scripts/lab.sh cli migrate
./scripts/lab.sh check

# Historical journal status (exits 2 by CLI design, not a live verification):
./scripts/lab.sh cli status --json
```

`up` is idempotent: it checks an existing source manifest instead of adding the
same seed messages again. The host wrapper runs the CLI **inside** the isolated
client container, using `/lab/migration.toml`. It pins the lab config and only
accepts `--json` and `--dry-run` where applicable. It refuses endpoint/config
argument overrides and validates the test hosts, credentials, TLS policy and
state paths before executing the CLI. Do not replace these files with real data.

The ready-to-use configuration on your host is:

```
tests/compose/.runtime/client/migration.toml
```

It uses the existing IMAPLANE schema: source/destination sections, private
password files, `ca_file`, implicit TLS on container port 993, explicit Unicode
folder mappings and `state_dir = "./state/migration"`. The names `source` and
`destination` resolve inside Compose, not on your host. Use the wrapper commands;
do not point a host CLI at production endpoints to test this lab.

## Dataset and identities

| Item | Fixture |
| --- | --- |
| Source login | `source@imaplane.test` / `test-only-source-password` |
| Destination login | `destination@imaplane.test` / `test-only-destination-password` |
| Initial source | 120 messages across 6 selectable folders, 20 per folder |
| Bodies | Multipart plain text + HTML; multilingual subjects and display names |
| Attachments | 360 instances: PDF invoices, UTF-8 CSV with Unicode filename, PNG |
| Read/unread | 60 read, 60 unread; also Answered, Flagged, Draft and a keyword |
| Duplicates | 24 intentional extra instances (4 per folder); 96 distinct RFC822 bodies |
| Initial destination | 3 pre-existing synthetic messages in INBOX |
| Normal result | 123 destination messages; original 3 preserved |

Folders include `旅行/日本語`, `Archiv/Grüße`, `رسائل/العمل`, and a folder containing
an emoji, ampersand, quotes and a backslash. Nonselectable hierarchy parents are
created by Dovecot as needed. Duplicate messages are byte-identical with matching
metadata but different source UIDs. They must remain separate instances.

Messages have deterministic MIME boundaries and dates; regenerating the fixture
produces the same message bodies. UIDVALIDITY/UID values are server data and can
change after reset. Credentials are deliberately public **test-only** values;
never reuse them for another purpose. Dovecot's passwd files allow only their
respective fixture account. No SMTP sender, relay, real mailbox account or
provider token is configured.

## Automated integration and recovery tests

For a complete repeatable run from a clean dataset:

```sh
./scripts/lab.sh reset
./scripts/lab.sh test
./scripts/lab.sh recovery
./scripts/lab.sh check
```

`test` checks:

- TLS folder discovery and a read-only dry-run.
- Rejection of the test servers when their private CA is not trusted.
- All 120 transfers confirmed by the real CLI.
- Exact message content hashes, sizes, INTERNALDATE and persistent flags.
- Duplicate multiplicity, unchanged source UIDs/UIDVALIDITY/content/flags,
  unchanged selectable source folders and preservation of destination baseline.
- Live verification and a repeated migration that adds no duplicate messages.

`recovery` runs two deterministic scenarios, without relying on how quickly 120
small messages copy. A temporary loopback TLS proxy in the client container
forwards to Dovecot and pauses after the destination commits APPEND but before its
confirmation reaches the CLI. The source and destination TLS hops both validate
the generated CA and hostname; there is no plaintext credential forwarding.

1. **SIGINT:** signal the real CLI, release the confirmation, confirm it stopped
   with exit 2, then rerun the same job and verify all 120 messages.
2. **SIGKILL:** kill the real CLI while that confirmation is withheld. Confirm a
   durable uncertain record; resume twice and check no blind retry occurred.
   The fixture knows which gated upload committed in the fresh destination
   namespace. It uses the existing audited `resolve` command for that known UID,
   then completes and verifies the migration. A candidate hash match is never
   automatically treated as sufficient attribution.

Recovery uses separate folders prefixed `Recovery-interrupt/` and
`Recovery-crash/`, and separate journals. After normal migration plus both
recovery scenarios, the destination has **363 messages** across the test
namespaces; the source still has **120**. Recovery configs reference the
short-lived proxy at container-local `localhost:19993`; they are not directly
usable after the recovery command exits. Reports remain available. Reset before
repeating recovery; the harness refuses to discard an existing recovery journal
silently. The ordinary migration/test commands can be repeated without reset.

Manual Ctrl-C during a normal `cli migrate` is also possible, followed by the
same migrate command. On this small local dataset, copying may finish before you
can interrupt it; use `recovery` for deterministic crash-boundary coverage.

## Stop, restart and reset

```sh
# Remove lab containers/network, KEEP mail volumes, certificates and journals:
./scripts/lab.sh down

# Recreate servers using the preserved mail and state, without reseeding:
./scripts/lab.sh up
./scripts/lab.sh cli verify

# DESTRUCTIVE TO THIS LAB ONLY: remove its two mail volumes and .runtime,
# generate new certificates, rebuild/recreate and seed a clean dataset:
./scripts/lab.sh reset

# Diagnostics (available while a test/migration is running):
./scripts/lab.sh status
./scripts/lab.sh logs
```

`reset` never runs global Docker prune or removes another Compose project's
volumes/containers. The fixed project name `imaplane-lab` is reserved for this
lab; do not reuse it for unrelated stacks. A lifecycle lock prevents reset from
racing a migration/test. Remote Docker contexts, symlinked runtime paths,
published host ports, external networks and external/host-backed mail volumes
are refused by the wrapper. If you see a safety-check error, fix the lab setup
rather than weakening these checks.

The one-time request to stop all existing Docker containers was performed before
creating this lab. The reusable scripts themselves do not stop unrelated Docker
projects. They also do not restart those previously stopped projects.

## Isolation, storage and certificates

- Compose network `imaplane-lab_lab` has `internal: true`; services attach only to
  that network. No IMAP ports are published to the host. `docker ps` may display
  image EXPOSE metadata such as `993/tcp`; that is not a host port binding.
- Source and destination use distinct named volumes
  `imaplane-lab_source-mail` and `imaplane-lab_destination-mail`.
- `.runtime/` is ignored by Git and private to the host user. Only generated
  lab files and the two harness scripts are mounted into the tools container;
  there is no Docker socket, host home, real config or production credential mount.
- Tools run under your host UID/GID with a read-only root filesystem, no Linux
  capabilities and no-new-privileges. Dovecot uses a read-only root filesystem,
  ephemeral run/cache directories, dedicated mail volumes and the capabilities
  needed by its local login workers. Nothing runs privileged or on host networking.
- A 30-day test CA signs separate source, destination and loopback-proxy leaf
  certificates with matching SANs. The CA is passed through `ca_file`; it is never
  installed into your host's trust store. No certificate-validation bypass exists.
  Use `reset` when certificates expire; system/container clocks must be correct.
- Seeding necessarily writes synthetic mail into the source before testing.
  Migration/verification then prove the source's logical message data and flags
  remain unchanged. Dovecot may update its own indexes/access logs as usual.

## Reports and observed local results

Generated configuration, manifest, journals and reports are under:

```
tests/compose/.runtime/client/
  migration.toml
  manifest.json
  source.password / destination.password / ca.pem
  state/migration/journal.sqlite3
  state/interrupt/journal.sqlite3
  state/crash/journal.sqlite3
  reports/migration-test.json
  reports/recovery-test.json
  reports/*.stdout.json
  reports/*.stderr.log
```

Manual CLI reports can be saved without credential exposure:

```sh
./scripts/lab.sh cli migrate --json > /tmp/imaplane-lab-migration.json
./scripts/lab.sh cli verify --json > /tmp/imaplane-lab-verification.json
```

Validated locally on Linux amd64 with Docker Compose v5.3.1 and the pinned
Dovecot 2.3.21 image: 120-message migration, verification, duplicate-free resume,
SIGINT and SIGKILL recovery, source/baseline integrity, untrusted-CA rejection,
and reset/reseeding. Five offline harness tests cover realistic MIME generation,
endpoint/state/credential guards, symlink refusal, network/volume restrictions and refusal of optimized Python.
Rootless/user-namespace-mapped Docker has not been validated.
This lab does not establish live provider compatibility, native arm64 support,
production readiness, million-message behavior, every storage failure, or a
complete security boundary against a Docker administrator.
