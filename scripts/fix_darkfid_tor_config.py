#!/usr/bin/env python3
from pathlib import Path
import re

p = Path.home() / ".config/darkfi/darkfid_config.toml"
bak = Path(str(p) + ".bak-tor")
text = bak.read_text() if bak.exists() else p.read_text()
Path(str(p) + ".bak-before-socks").write_text(p.read_text() if p.exists() else text)

# Force testnet net active_profiles + tor proxy (first occurrence = testnet)
text2, n = re.subn(
    r'(?m)^active_profiles = \[.*?\]\n',
    'active_profiles = ["socks5+tls"]\n',
    text,
    count=1,
)
print("active_profiles replacements:", n)

text2 = text2.replace(
    '#tor_socks5_proxy = "socks5://127.0.0.1:9050"',
    'tor_socks5_proxy = "socks5://127.0.0.1:9050"',
    1,
)

# Clear tcp+tls peers/seeds for testnet
text2 = re.sub(
    r'(\[network_config\."testnet"\.net\.profiles\."tcp\+tls"\]\n)(.*?)(\n\[network_config\."testnet"\.net\.profiles\."tor"\])',
    r'''\1# Seeds unused (clearnet IP banned on full nodes)
seeds = []
peers = []
#inbound = []
#external_addrs = []
\3''',
    text2,
    count=1,
    flags=re.S,
)

# socks5+tls peers via local tor
text2, n = re.subn(
    r'(\[network_config\."testnet"\.net\.profiles\."socks5\+tls"\]\n)(.*?)(\n\[network_config\."testnet"\.net\.profiles\."tor\+tls"\])',
    r'''\1# Manual peers via Tor SOCKS (avoid clearnet IP ban)
seeds = []
peers = [
    "socks5+tls://127.0.0.1:9050/node0.testnet.dark.fi:18340",
    "socks5+tls://127.0.0.1:9050/node1.testnet.dark.fi:18340",
    "socks5+tls://127.0.0.1:9050/neo.not.org:18340",
    "socks5+tls://127.0.0.1:9050/195.3.221.59:18340",
]
#inbound = []
#external_addrs = []
\3''',
    text2,
    count=1,
    flags=re.S,
)
print("socks5+tls replacements:", n)
if n != 1:
    raise SystemExit("failed socks5+tls rewrite")

# outbound connections
text2, n = re.subn(
    r'(?m)^#?outbound_connections\s*=\s*\d+\n',
    'outbound_connections = 8\n',
    text2,
    count=1,
)
print("outbound replacements:", n)

p.write_text(text2)
print("wrote", p)
for i, line in enumerate(p.read_text().splitlines(), 1):
    if i < 220 and any(
        k in line
        for k in (
            "active_profiles",
            "tor_socks",
            "seeds",
            "peers",
            "socks5+tls",
            "outbound_conn",
            'profiles."tcp',
            'profiles."socks',
        )
    ):
        print(f"{i}:{line}")
