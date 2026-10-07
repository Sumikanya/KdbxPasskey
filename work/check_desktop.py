from pathlib import Path
import subprocess
import json

root = Path(__file__).resolve().parents[1]
provider = root / 'work/package/Provider/KeePassPasskeyProvider.exe'
checked = subprocess.run([str(provider), '/runtime_check'], capture_output=True, text=True, timeout=15, check=True)
checks = json.loads(checked.stdout)
assert checks['helloRequired'] and not checks['avalonia']
for args in [[], ['0'], ['not-a-window']]:
    result = subprocess.run([str(provider), '/verify_session', *args], capture_output=True, timeout=15)
    assert result.returncode == 2 and b'HELLO verified' not in result.stdout
for scenario in ['unlocked-many-keys-dark', 'compact-unlocked-many-keys-light',
                 'unlocked-details-many-keys-dark', 'compact-unlocked-details-many-keys-light',
                 'unlocked-search-keys-dark', 'empty-keys-light', 'keys-dark',
                 'login-unlock-dark', 'login-unlock-session-light', 'session-dark', 'session-light', 'compact-settings-dark', 'about-light']:
    output = root / ('work/027-' + scenario + '.png')
    result = subprocess.run([str(root / 'work/native-ui/KdbxPasskey.exe'), '--ui-check', str(output)], timeout=20)
    if result.returncode:
        raise RuntimeError(output.with_suffix('.png.error.txt').read_text())
    assert output.is_file()
    print('UI passed:', scenario)
print('Provider resources, required Hello and invalid session requests passed')
