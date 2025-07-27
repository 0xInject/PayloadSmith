# ☣️ PayloadSmith

**PayloadSmith** is a powerful and flexible reverse shell payload generator for offensive security professionals, CTF players, and red teamers. Generate, obfuscate, encode, encrypt, and export payloads in a matter of seconds — straight from your terminal.

![Python](https://img.shields.io/badge/Made%20with-Python-blue.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 💣 Features

- 🎯 Generate payloads for multiple platforms: Bash, Python, PHP, Netcat, PowerShell, Python HTTPS
- 🌀 Obfuscate payloads with random whitespace & junk
- 🔒 Encode using Base64
- 🔐 XOR encrypt payloads with custom stub decoder
- 📎 Bind your payload with any script/file
- 📂 Export payload to ZIP or custom output file
- 🔁 Multi-mode: Generate **all** shell types in one command
- 🚫 `--no-copy`: Skip clipboard copy if needed
- 🔎 `--list`: View available shell types instantly

---

## ⚙️ Installation

```bash
git clone https://github.com/0xInject/PayloadSmith.git
cd PayloadSmith
pip install -r requirements.txt
