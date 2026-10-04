# Distribution and uninstall

The current 0.2.7 MSIX is a self-signed development release. Users must explicitly
trust its public certificate before installing it. The private signing key stays
with the publisher and must never be distributed. Importing a public certificate
is a trust decision, not a step the app should silently perform.

For general users, Microsoft Store distribution avoids manual certificate import:
after certification, Microsoft signs the submitted MSIX. Store acceptance and
passkey-provider compatibility still need testing. GitHub can host the source
regardless of the chosen binary distribution channel.

For direct GitHub downloads, a publicly trusted code-signing certificate or
eligible signing service avoids trusting a development certificate manually.
Eligibility, cost and platform support must be checked before choosing a service.
Normal installation consent and platform security checks can still appear.

Uninstall acceptance criteria for a future public release:

- Store application-owned settings and caches in package-managed data locations.
- Verify removal of the package, COM registration and Windows passkey-provider
  metadata on a clean test machine, including uninstall while running.
- Check application data paths after uninstall instead of assuming redirection.
- Never remove the user's KDBX database or key file.
- A manually imported development certificate is managed separately from MSIX
  removal. Never delete unrelated certificates; shared certificate use must be
  considered before removing it.

The current version has not passed a clean-machine install/uninstall audit and
does not claim zero residual data. Downloaded files, Windows event logs and other
OS-managed history are outside the application's cleanup guarantee.

References:
- [Microsoft MSIX signing guide](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide)
- [Microsoft Store publishing](https://learn.microsoft.com/en-us/windows/apps/publish/get-started)
- [MSIX troubleshooting and data locations](https://learn.microsoft.com/en-us/windows/msix/msix-troubleshooting-guide)
