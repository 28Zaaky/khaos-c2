<div align="center">
  <img src="https://khaos.khaotic.fr/logo.png" alt="KHAØS C2" width="200" />
  <h1>KHAØS C2</h1>
  <p>KHAØS is a modern post-exploitation C2 framework with 5 covert channels and full evasion built in, created by <a href="https://github.com/28Zaaky/">@28Zaaky</a>.</p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white)](https://discord.gg/qNeK6cvwSq)
  [![Website](https://img.shields.io/badge/Website-khaos.khaotic.fr-0a0a0a)](https://khaos.khaotic.fr)
</div>

--- 

<!-- <div align="center">
  <img src="https://khaos.khaotic.fr/preview.png" alt="KHAØS C2 UI" width="800" />
</div> -->

<img width="1395" height="897" alt="image" src="https://github.com/user-attachments/assets/4b20ebc7-afb7-442c-9bf6-e173c1886dee" />


---
See the [documentation](https://khaos.khaotic.fr/docs.html) for full instructions.
---

## Why KHAØS

Most open-source C2s have one thing in common: they're already in every EDR vendor's database. KHAØS was built with that in mind from day one.

The agent is written in C. It uses indirect syscalls, unhooks ntdll from a fresh disk copy, patches ETW and AMSI through hardware breakpoints rather than byte-patching, and obfuscates its stack during sleep. Every build regenerates its string encoding key and credential XOR, so two compiled binaries from the same config never share a static signature.

On the network side there are five channels: Microsoft Teams, GitHub Gist, DNS-over-HTTPS, HTTP/S, and SMB named pipe. The idea is that at least one of them already looks like normal traffic in whatever environment you're working in.

Post-exploitation covers the usual ground: shell, execute-assembly (.NET CLR in-process), BOF/COFF loading, four injection techniques, token theft and impersonation, LSASS dump via direct syscall, Kerberoasting, AS-REP roasting, SOCKS5, reverse port forward, and WMI lateral movement. A separate crypter/loader handles in-memory PE mapping if you need to go stageless.

The operator UI is a React app with a built-in payload builder, live network map, credential store, and screenshot gallery. Everything updates over WebSocket in real time.

---

## Features

<img width="934" height="1066" alt="image" src="https://github.com/user-attachments/assets/a1b331a3-eedc-4654-85ed-7e26cd834ffd" />

### Channels

| Channel | Transport | Blends into |
|---------|-----------|-------------|
| Microsoft Teams | HTTPS `*.office.com` | O365 enterprise traffic |
| GitHub Gist | REST `api.github.com` | Developer activity |
| DNS-over-HTTPS | DoH `1.1.1.1` | Encrypted DNS queries |
| HTTP/S | HTTPS | Generic web traffic |
| SMB Named Pipe | SMB | Internal lateral movement |

Traffic is encrypted with ChaCha20-Poly1305, key exchange via X25519, unique per agent, per session.

### Post-exploitation

| Category | Capabilities |
|----------|-------------|
| Execution | Shell, execute-assembly (.NET CLR in-process), BOF/COFF loader, screenshot |
| Injection | Remote thread, thread hijack, EarlyBird APC, module stomp, self-injection |
| Identity | Token steal / make / revert, `getsystem` (3 techniques), UAC bypass (ICMLuaUtil / fodhelper / sdclt) |
| Credentials | LSASS dump (custom minidump), SAM/SYSTEM hive via SeBackupPrivilege, Kerberoast, AS-REP roast |
| Network | SOCKS5 proxy, reverse port forward, SMB pivot, WMI lateral movement |
| Persistence | Registry run key, scheduled task (XML) |

### Crypter

Loader that decrypts and reflectively maps the agent PE in memory.

```bash
cd crypter
python build.py                            # bake agent + build loader
python build.py --stager-url https://...   # with network stager
```

---

## Quick Start

### Linux (Kali / Ubuntu / Debian)

```bash
git clone https://github.com/28Zaaky/khaos-c2
cd khaos-c2
python3 -m venv venv && source venv/bin/activate
pip3 install -r server/requirements.txt

# install Node.js if missing
sudo apt update && sudo apt install nodejs npm -y
cd ui && npm install && npm run build && cd ..

# TLS cert
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout server/cert.key -out server/cert.pem -subj "/CN=khaos-c2"

cp server/config.example.yaml server/config.yaml
# edit config.yaml: jwt_secret + http.beacon_url
python3 server/main.py
```

Agent compiled on Windows (see below), then dropped on target.

### Windows

Requires [MSYS2](https://www.msys2.org/) with MinGW-w64.

```bash
git clone https://github.com/28Zaaky/khaos-c2
cd khaos-c2
```

```bash
# MSYS2 shell — install build deps once
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-mbedtls
```

```bash
# Server
cd server
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy config.example.yaml config.yaml
python main.py
```

```bash
# UI (separate terminal)
cd ui && npm install && npm run dev   # → http://localhost:5173
```

```powershell
# Agent
.\agent\rebuild_agent.ps1        # runs make config + make lean, kills running agent first
# or: cd agent && make config && make standalone
```

Default login: `operator` / `changeme`

---

## Community

Discord: https://discord.gg/qNeK6cvwSq

---

## Legal

For authorized security testing only. Using this tool against systems you do not own or have explicit written permission to test is illegal.

---

*Built by [28Zaaky](https://github.com/28Zaaky/)*
