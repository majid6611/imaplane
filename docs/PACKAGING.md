# Linux package builds and releases

The build scripts target DEB (Debian bookworm userland, glibc 2.36+) and RPM
(Rocky Linux 9 userland, glibc 2.34+) with OpenSSL 3 runtime dependencies.
They compile natively inside each package family's container, test the code with
Rust 1.85.1, verify the ELF machine before applying an architecture label, and
package with checksum-pinned nFPM 2.48.0. amd64 maps to RPM x86_64; arm64 maps to
RPM aarch64. These are build targets, not claims of universal distro support.

From a source checkout, run on a matching native amd64 or arm64 Linux machine with Docker/buildx,
Python 3.11+, Bash and network access:

```sh
scripts/build-packages.sh deb amd64
scripts/build-packages.sh rpm amd64
scripts/test-package.sh dist/packages/imaplane_0.1.0_amd64.deb
scripts/test-package.sh dist/packages/imaplane_0.1.0_amd64.rpm
# On a native arm64 runner, use arm64 instead of amd64.
```

Outputs go to `dist/packages/`. The scripts refuse architecture mismatches rather
than emitting an amd64 executable with an arm64 package label. Installation tests
use disposable clean containers, not your host package database. The DEB test resolves runtime dependencies; the RPM test verifies its declared
dependencies against the clean Rocky base without silently upgrading that base.
They run the executable, check the sample config, and uninstall.
No maintainer scripts, system service, credentials or live migration are installed.
The executable is `/usr/bin/imaplane`; examples and docs live under
`/usr/share/doc/imaplane`. User-owned migration state is never removed by uninstall.

`.github/workflows/release.yml` builds four format/architecture combinations on
native GitHub-hosted amd64 and arm64 runners. Each must pass unit tests, clean
install/execute/uninstall checks and local TLS/STARTTLS/XOAUTH2 fixtures. The amd64
DEB build additionally runs the full two-server Dovecot migration/crash suite.
Runner availability depends on the repository's GitHub Actions plan/settings.
Pull requests touching package inputs and manual dispatch build artifacts without
publishing. All four jobs must pass before a matching `v<Cargo.toml version>` tag
publishes package files and SHA256SUMS as a GitHub **prerelease**. Upload starts as
a draft; it becomes visible only after successful upload. Publication requires
the repository token's contents-write permission; build jobs are read-only.
The workflow does not overwrite an existing release's assets on rerun.

Packages are unsigned; SHA256SUMS provides integrity checking, not publisher
signature verification. Container distro repositories and base image tags evolve,
so these are repeatable build instructions rather than bit-for-bit reproducible
builds. Rust and nFPM are pinned, Cargo dependencies use the committed lock file,
and the bundled parser patch retains upstream licenses. Collected dependency and Rust toolchain notices are included in the package;
missing crate notice files fail the build. An independent license compatibility
review, SBOM generation, package signing and published apt/yum repositories remain outside
this increment.

Local platform validation results are recorded in RELIABILITY_AUDIT.md. Native
arm64 execution and the hosted release workflow must pass before claiming tested
arm64 support. No release was published during the local development session.
