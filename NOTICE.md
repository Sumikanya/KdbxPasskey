# Attribution and modifications

KDBX Passkey is distributed under GPL-3.0-or-later; see LICENSE.

The Windows passkey provider and shared protocol derive from
[KeePassPasskey](https://github.com/yusei36/KeePassPasskey), copyright 2026 Uwe Koegel,
GPL-3.0-or-later. The imported source reports version 1.4.0; the exact import commit
was not recorded. The modified source is included in `source/upstream`, retaining
its license, notices and original source headers. Icons and branding assets also
come from that source tree. This is an independent project, not an official
KeePass, KeePassXC or Microsoft product.

Local modifications include a WPF interface, a read-only Python KDBX backend,
application-specific IPC and identifiers, Windows Hello verification policy,
credential synchronization, and a smaller provider entry point. Modified upstream
files are included as source rather than downloaded during builds.

WPF UI is MIT-licensed; its license is included in
`source/desktop/LICENSE-WPF-UI.txt`. Python, .NET and their libraries retain their
respective licenses. Builds collect distribution notices into the MSIX's
`ThirdPartyLicenses` directory. Release downloads must include the corresponding
source archive alongside the installation package.
