#!/usr/bin/env python3
"""Download latest artifact via direct API"""
import urllib.request, subprocess, os, json, sys

# Get token
result = subprocess.run(['gh', 'auth', 'token'], capture_output=True, text=True)
token = result.stdout.strip()

# Get latest successful run's artifact
url = 'https://api.github.com/repos/situfeng2026/data-safety-scanner/actions/runs/28009444210/artifacts'
req = urllib.request.Request(url)
req.add_header('Accept', 'application/vnd.github+json')
req.add_header('Authorization', f'Bearer {token}')
req.add_header('User-Agent', 'Hermes-dl')

resp = urllib.request.urlopen(req, timeout=30)
data = json.loads(resp.read())
artifact = data['artifacts'][0]
print(f'Artifact: {artifact["name"]}, size: {artifact["size_in_bytes"]}')

# Download artifact zip
dl_url = artifact['archive_download_url']
req2 = urllib.request.Request(dl_url)
req2.add_header('Accept', 'application/vnd.github+json')
req2.add_header('Authorization', f'Bearer {token}')
req2.add_header('User-Agent', 'Hermes-dl')

import ssl
ctx = ssl.create_default_context()
resp2 = urllib.request.urlopen(req2, timeout=300, context=ctx)
zip_data = resp2.read()
print(f'Downloaded: {len(zip_data)} bytes')

out = os.path.expanduser('~/Desktop/Hermes文件/数据安全检查工具/new_artifact.zip')
with open(out, 'wb') as f:
    f.write(zip_data)
print(f'Saved: {out}')
