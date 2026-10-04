# Security

This is an experimental Windows passkey provider. It has not received an
independent security audit. Build checks are not proof of end-to-end security.

Do not post exploit details, databases or secrets in public issues. If private
vulnerability reporting is available on this repository, use the Security tab's
private reporting feature. Otherwise ask the maintainer for a private reporting
channel without publishing sensitive details.

The application reads an existing KDBX database without saving changes. Unlocked
passkey private keys are held in memory. The optional session password cache uses
process-scoped Windows encrypted memory; it is not saved to disk and is discarded
when the app exits. Temporary managed-memory copies can exist during use. This
does not protect against a compromised Windows account or operating system.

Only the public signing certificate may accompany a release. PFX/P12/private
keys and DPAPI signing material must never be published. A self-signed test release
requires explicit certificate trust; do not silently modify users' trust stores.

Uninstalling an MSIX is not a promise to erase all traces. A manually installed
certificate, downloaded installer, system logs and user-owned database are
separate from the application. See [distribution notes](docs/DISTRIBUTION.md).
