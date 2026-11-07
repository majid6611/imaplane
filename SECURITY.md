# Security policy

IMAPLANE is a technical preview (v0.1.x). It handles mailbox credentials and mail
content, so please report security problems privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability**). Please do not open a public issue for a
suspected vulnerability. Include the version (`imaplane --version`), what you did,
what you expected and what happened. **Never include real credentials, tokens or
mail content**; sanitize logs first (`--diagnostics-file` output is already free of
credentials, usernames, folder names and message content).

This is a volunteer project; there is no response-time guarantee. Reports are
acknowledged on a best-effort basis and fixes are released as new versions.

## What is in scope

- Anything that could expose or misuse credentials or OAuth tokens (argv, logs,
  reports, journals, file permissions).
- Anything that could modify, delete or flag the source mailbox.
- Anything that could lose or duplicate messages, or report a copy as verified
  when it is not (the journal, the pre-literal authorization fence, recovery).
- Weaknesses in TLS/STARTTLS validation or XOAUTH2 handling.

## Supported versions

Only the latest 0.1.x preview release receives fixes.

## Known limits

See "Preservation policy and limitations" in the README and
`docs/RELIABILITY_AUDIT.md`. Gmail and Microsoft 365 have not been tested with live
accounts; packages are unsigned (verify `SHA256SUMS`).
