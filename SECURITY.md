# Security Policy

## Supported Versions

Security fixes are provided for the latest release. Reports affecting an older
release should state whether the issue also reproduces on the current version.

## Reporting a Vulnerability

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/metaneutrons/cnlman/security/advisories/new).

Please include the affected version, the platform, reproduction steps, the
impact and any known mitigation. Remove API keys, decrypted links and other
personal data before submitting the report.

You should receive an acknowledgement within three business days. Status
updates follow at least every seven days until the report is resolved or
closed. Please do not disclose the issue publicly before a coordinated release.

## Scope

cnlman runs a local HTTP listener that any page open in the browser can post
to, and it forwards links to pyLoad with an API key. In scope are, among
others: the listener accepting connections from other machines without
`--allow-remote`, the pyLoad API key leaving the machine over an unencrypted
connection to a non-local host, crashes or unbounded resource use triggered by
a crafted request or page, and links reaching pyLoad that the user did not
send.

Out of scope is the Click'n'Load protocol itself: by design, any page the user
visits can post a package to the listener while it runs. Run `cnlman listen`
only for as long as you need it, and use `--once` or `--timeout`.
