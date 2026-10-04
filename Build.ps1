param([switch]$Offline, [switch]$SkipSigning)
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
Set-Location -LiteralPath $taskRoot
# All build state stays inside the project. No application/certificate installation.
$env:DOTNET_CLI_HOME = Join-Path $taskRoot 'work\dotnet-home'
$env:APPDATA = Join-Path $taskRoot 'work\build-appdata'
$env:LOCALAPPDATA = Join-Path $taskRoot 'work\build-localappdata'
$env:NUGET_PACKAGES = Join-Path $taskRoot 'work\nuget-packages'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$taskPython = Join-Path $taskRoot 'work\venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    & python -m venv (Join-Path $taskRoot 'work\venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python venv creation failed' }
}
$taskPipArgs = @()
$taskRestoreArgs = @('--configfile', (Join-Path $taskRoot 'NuGet.Config'))
if ($Offline) {
    $taskPipArgs += '--no-index'
    $taskRestoreArgs += @('--source', $env:NUGET_PACKAGES, '-p:NuGetAudit=false')
}
& $taskPython -m pip install @taskPipArgs -r (Join-Path $taskRoot 'source\backend\requirements-lock.txt')
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed' }
& $taskPython -m unittest discover -s source/backend -p 'test_*.py'
if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed' }
$taskDotnet = Join-Path $taskRoot 'work\dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $taskDotnet)) { $taskDotnet = (Get-Command dotnet -ErrorAction Stop).Source }
& $taskDotnet restore source/tests/PipeClientChecks/PipeClientChecks.csproj @taskRestoreArgs
if ($LASTEXITCODE -ne 0) { throw 'IPC test restore failed' }
& $taskDotnet run --project source/tests/PipeClientChecks/PipeClientChecks.csproj -c Release --no-restore
if ($LASTEXITCODE -ne 0) { throw 'IPC tests failed' }
# Clean only known publish directories so removed dependencies cannot enter a new package.
foreach ($taskRelative in @('work\package\Provider', 'work\native-ui', 'work\backend-python\KdbxBackend')) {
    $taskOutput = [IO.Path]::GetFullPath((Join-Path $taskRoot $taskRelative))
    $taskWork = [IO.Path]::GetFullPath((Join-Path $taskRoot 'work')) + '\'
    if (-not $taskOutput.StartsWith($taskWork, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe publish path' }
    if (Test-Path -LiteralPath $taskOutput) {
        $taskResolved = (Resolve-Path -LiteralPath $taskOutput).Path
        if ($taskResolved -ne $taskOutput) { throw 'Unexpected publish path' }
        if ((Get-Item -LiteralPath $taskOutput).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked publish directory rejected' }
        Remove-Item -LiteralPath $taskOutput -Recurse -Force
    }
}
& $taskDotnet publish '.\source\provider\KdbxProvider.csproj' -c Release -p:UseSharedCompilation=false -o '.\work\package\Provider' @taskRestoreArgs
if ($LASTEXITCODE -ne 0) { throw 'Windows provider build failed' }
& $taskDotnet publish '.\source\desktop\KdbxPasskey.csproj' -c Release -p:UseSharedCompilation=false -o '.\work\native-ui' @taskRestoreArgs
if ($LASTEXITCODE -ne 0) { throw 'Native WPF UI build failed' }
& $taskPython work/check_desktop.py
if ($LASTEXITCODE -ne 0) { throw 'Native UI or provider check failed' }
& $taskPython -m PyInstaller --noconfirm --console --onedir --name KdbxBackend --distpath work/backend-python --workpath work/backend-pyinstaller --specpath work --collect-all pykeepass source/backend/desktop_service.py
if ($LASTEXITCODE -ne 0) { throw 'Backend build failed' }
& $taskPython work/check_frozen_backend.py
if ($LASTEXITCODE -ne 0) { throw 'Frozen backend check failed' }
& $taskPython work/assemble.py
if ($LASTEXITCODE -ne 0) { throw 'Package assembly failed' }
& $taskPython work/collect_notices.py
if ($LASTEXITCODE -ne 0) { throw 'Package assembly failed' }
$taskMakeAppx = Join-Path $taskRoot 'work\sdk-tools\bin\10.0.28000.0\x64\makeappx.exe'
if (-not (Test-Path -LiteralPath $taskMakeAppx)) {
    $taskSdkBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $taskSdkTool = Get-ChildItem -LiteralPath $taskSdkBin -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'x64\makeappx.exe' } |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $taskMakeAppx = if ($taskSdkTool) { $taskSdkTool } else { (Get-Command makeappx.exe -ErrorAction Stop).Source }
}
New-Item -ItemType Directory -Force -Path (Join-Path $taskRoot 'dist') | Out-Null
& $taskMakeAppx pack /d '.\work\package-native' /p '.\dist\KdbxPasskey-0.2.7-x64.msix' /o /l
if ($LASTEXITCODE -ne 0) { throw 'MSIX packaging failed' }
# Remove only this build's temporary private signing key; .cer contains no private key.
$taskKey = [IO.Path]::GetFullPath((Join-Path $taskRoot 'work\signing.pfx'))
if (-not $taskKey.StartsWith([IO.Path]::GetFullPath((Join-Path $taskRoot 'work')) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe signing-key path' }
if (-not $SkipSigning) { try {
    & $taskPython work/create_certificate.py
    if ($LASTEXITCODE -ne 0) { throw 'Certificate generation failed' }
    & $taskPython work/sign_ephemeral.py
    if ($LASTEXITCODE -ne 0) { throw 'MSIX signing failed' }
    & $taskPython work/verify_package.py
    if ($LASTEXITCODE -ne 0) { throw 'Package verification failed' }
} finally {
    if (Test-Path -LiteralPath $taskKey) { Remove-Item -LiteralPath $taskKey -Force }
} }
& $taskPython work/finalize.py
if ($LASTEXITCODE -ne 0) { throw 'Source kit and checksums failed' }
if ($SkipSigning) { Write-Host 'Built unsigned dist\KdbxPasskey-0.2.7-x64.msix; signing is required before installation.' }
else { Write-Host 'Built and verified dist\KdbxPasskey-0.2.7-x64.msix. Nothing installed.' }
