#!/usr/bin/env python3
"""Download artifact with requests library"""
import subprocess, os, json

result = subprocess.run(['gh', 'auth', 'token'], capture_output=True, text=True)
token = result.stdout.strip()

import urllib.request

# Get the redirect URL first
url = 'https://api.github.com/repos/situfeng2026/data-safety-scanner/actions/artifacts/7814065091/zip'
req = urllib.request.Request(url)
req.add_header('Accept', 'application/vnd.github+json')
req.add_header('Authorization', f'Bearer {token}')
req.add_header('User-Agent', 'Hermes-dl')

# Don't follow redirect - get the redirect URL first
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect)
resp = opener.open(req, timeout=30)
redirect_url = resp.headers.get('Location')
print(f'Redirect URL: {redirect_url[:80]}...')

# Now download from the redirect URL directly
req2 = urllib.request.Request(redirect_url)
req2.add_header('User-Agent', 'Hermes-dl')
resp2 = urllib.request.urlopen(req2, timeout=300)
data = resp2.read()
print(f'Downloaded: {len(data)} bytes')

out = os.path.expanduser('~/Desktop/Hermes文件/数据安全检查工具/new_artifact.zip')
with open(out, 'wb') as f:
    f.write(data)
print(f'Saved: {out}')
