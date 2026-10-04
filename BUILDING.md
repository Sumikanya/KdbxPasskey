# Build on Windows

Prerequisites: Windows x64, Python 3.11, .NET 10 SDK, and Windows SDK packaging tools
(`makeappx.exe`). NuGet and PyPI access is needed for the first build. Put the SDK
packaging tools on PATH if they are not discovered automatically.

```powershell
.\Build.ps1 -SkipSigning
```

The script creates `work/venv`, restores dependencies, runs backend and pipe tests,
publishes both .NET applications, checks UI layouts, freezes the Python backend
and creates `dist/KdbxPasskey-0.2.7-x64.msix`. The unsigned package cannot be installed
as a normal MSIX until signed. `-Offline` uses already populated local caches.
UI checks require a Windows desktop session; a headless runner may only perform
the separate tests and compilation in CI.

For a locally signed development build, omit `-SkipSigning`. This creates or
reuses a developer-only signing certificate, protected by the current Windows
user's DPAPI. A temporary PFX is deleted after signing. The script does not install
the application or trust the certificate. Each developer uses their own key;
the publisher's private signing material is never included in this repository.

The manifest's Publisher must match the signing certificate. Store or CA-backed
distribution requires a separate signing configuration; see
[distribution notes](docs/DISTRIBUTION.md). Do not use the development key as a
shared CI secret or commit it to Git.

Run backend tests independently after installing the pinned requirements:

```powershell
python -m unittest discover -s source/backend -p 'test_*.py'
dotnet run --project source/tests/PipeClientChecks/PipeClientChecks.csproj -c Release
```

Directory map: `source/desktop` is the WPF application; `source/backend` reads KDBX
and signs assertions; `source/provider` hosts the Windows provider;
`source/upstream` contains its modified upstream dependencies. `work/*.py` files
tracked in Git are build helpers; all other work output is ignored.
