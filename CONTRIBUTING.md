# Contributing

Please describe the problem and expected behavior before proposing large changes.
Keep changes focused and include relevant tests. Contributions are distributed
under the project's GPL-3.0-or-later license; retain upstream attribution.

See [BUILDING.md](BUILDING.md) for Windows build prerequisites and commands.
Use temporary test databases only. Never attach a real KDBX database, key file,
password, credential private key, signing key, or authentication token to an issue
or pull request. Screenshots should use example accounts.

Authentication changes must preserve cancellation, database-lock behavior, caller
validation and Windows Hello verification. Report which tests ran and distinguish
local tests from installed-package and real-site verification.
