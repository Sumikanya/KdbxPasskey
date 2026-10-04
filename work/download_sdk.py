import concurrent.futures
import hashlib
import os
import time
import urllib.request
from pathlib import Path

os.environ['NO_PROXY'] = ''
root = Path(__file__).parent
url = 'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.401/dotnet-sdk-10.0.401-win-x64.zip'
size = 300608304
expected = '24b670ad3d923bfcf47df6c3b034152398b42f6dbc388e10d783aee1cfb5e5817d399fc0ae2a12cfa822a55e61d34830ccb15c50ef6efee437ab874bb7c79430'
chunk = 4 * 1024 * 1024
parts = root / 'sdk-parts'
parts.mkdir(exist_ok=True)

def fetch(i):
    start = i * chunk
    end = min(size, start + chunk) - 1
    path = parts / str(i)
    if path.exists() and path.stat().st_size == end - start + 1:
        return i
    for attempt in range(4):
        try:
            req = urllib.request.Request(url + '?part=' + str(i), headers={'Range': f'bytes={start}-{end}'})
            with urllib.request.urlopen(req, timeout=40) as r:
                if r.headers.get('Content-Range') != f'bytes {start}-{end}/{size}':
                    raise ValueError('Unexpected range')
                data = r.read()
                if len(data) != end - start + 1:
                    raise ValueError('Truncated download')
            path.write_bytes(data)
            return i
        except Exception:
            if attempt == 3:
                raise
            time.sleep(1)

count = (size + chunk - 1) // chunk
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
    for done, future in enumerate(concurrent.futures.as_completed([pool.submit(fetch, i) for i in range(count)]), 1):
        future.result()
        if done % 8 == 0 or done == count:
            print(f'SDK download {done}/{count}', flush=True)
archive = root / 'dotnet-sdk.zip'
with archive.open('wb') as out:
    for i in range(count):
        out.write((parts / str(i)).read_bytes())
actual = hashlib.sha512(archive.read_bytes()).hexdigest()
if actual != expected:
    raise ValueError('SDK checksum mismatch')
print('Official SDK SHA512 verified', flush=True)
