"""
Firmware analyzer module for hackebds.
Extracts and analyzes firmware to detect architecture, bootloader, kernel, and filesystem info.
"""

import os
import struct
import subprocess
import tempfile
import shutil
import re
import math
from pwn import log
from colorama import Fore, Style

# ELF magic and architecture detection
ELF_MAGIC = b'\x7fELF'

# ELF e_machine values
ELF_MACHINES = {
    0x02: ('sparc', 32),
    0x03: ('x86', 32),
    0x08: ('mips', 32),      # MIPS
    0x0A: ('mips', 32),      # MIPS RS3000
    0x14: ('powerpc', 32),
    0x15: ('powerpc64', 64),
    0x28: ('arm', 32),
    0x2B: ('sparc', 64),
    0x3E: ('x64', 64),
    0xB7: ('aarch64', 64),
    0xF3: ('riscv64', 64),
}

# MIPS ISA level from ELF flags (e_flags & 0xf0000000)
MIPS_ISA_FLAGS = {
    0x00000000: ('mips1', 'MIPS I'),
    0x10000000: ('mips2', 'MIPS II'),
    0x20000000: ('mips3', 'MIPS III'),
    0x30000000: ('mips4', 'MIPS IV'),
    0x40000000: ('mips5', 'MIPS V'),
    0x50000000: ('mips32', 'MIPS32'),
    0x60000000: ('mips64', 'MIPS64'),
    0x70000000: ('mips32r2', 'MIPS32 Release 2'),
    0x80000000: ('mips64r2', 'MIPS64 Release 2'),
    0x90000000: ('mips32r6', 'MIPS32 Release 6'),
    0xa0000000: ('mips64r6', 'MIPS64 Release 6'),
}

# Architecture mapping to hackebds arch names
ARCH_MAPPING = {
    ('mips', 32, 'big'): 'mips',
    ('mips', 32, 'little'): 'mipsel',
    ('mips', 64, 'big'): 'mips64',
    ('mips', 64, 'little'): 'mips64el',
    ('arm', 32, 'little'): 'armelv7',
    ('arm', 32, 'big'): 'armebv7',
    ('aarch64', 64, 'little'): 'aarch64',
    ('x86', 32, 'little'): 'x86',
    ('x64', 64, 'little'): 'x64',
    ('powerpc', 32, 'big'): 'powerpc',
    ('powerpc64', 64, 'big'): 'powerpc64',
    ('powerpc64', 64, 'little'): 'powerpc64le',
    ('sparc', 32, 'big'): 'sparc',
    ('sparc', 64, 'big'): 'sparc64',
    ('riscv64', 64, 'little'): 'riscv64',
}


def check_binwalk_installed():
    """Check if binwalk is installed."""
    try:
        result = subprocess.run(['binwalk', '--help'], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy


def check_firmware_encrypted(filepath: str) -> tuple:
    """
    Check if firmware appears to be encrypted.

    Returns:
        tuple: (is_encrypted: bool, entropy: float, reason: str)
    """
    try:
        with open(filepath, 'rb') as f:
            # Read multiple sections
            header = f.read(4096)
            f.seek(len(header))
            middle = f.read(4096)

        # Calculate entropy
        entropy = calculate_entropy(header + middle)

        # Check for common firmware signatures
        signatures = [
            (b'\x27\x05\x19\x56', 'U-Boot header'),
            (b'hsqs', 'SquashFS (little-endian)'),
            (b'sqsh', 'SquashFS (big-endian)'),
            (b'\x85\x19\x01\x20', 'JFFS2 (little-endian)'),
            (b'\x20\x01\x19\x85', 'JFFS2 (big-endian)'),
            (b'\x1f\x8b', 'gzip compressed'),
            (b'\xfd7zXZ', 'xz compressed'),
            (b'PK', 'ZIP archive'),
            (ELF_MAGIC, 'ELF binary'),
            (b'UBI#', 'UBI filesystem'),
            (b'\xde\xad\xc0\xde', 'Firmware header'),
        ]

        found_sigs = []
        for sig, name in signatures:
            if sig in header:
                found_sigs.append(name)

        if found_sigs:
            return (False, entropy, f"Found signatures: {', '.join(found_sigs)}")

        # High entropy without signatures suggests encryption
        if entropy > 7.9:
            return (True, entropy, "Very high entropy, likely encrypted or compressed")
        elif entropy > 7.5:
            return (True, entropy, "High entropy without known signatures")

        return (False, entropy, "Normal entropy")

    except Exception as e:
        return (False, 0.0, f"Error: {e}")


def run_binwalk_scan(filepath: str) -> dict:
    """
    Run binwalk scan on firmware file.

    Returns:
        dict with 'output', 'uboot', 'kernel', 'filesystem', 'compressed'
    """
    result = {
        'output': '',
        'uboot': None,
        'uboot_version': None,
        'kernel': None,
        'kernel_version': None,
        'filesystem': [],
        'compressed': [],
    }

    try:
        proc = subprocess.run(
            ['binwalk', filepath],
            capture_output=True,
            text=True,
            timeout=60
        )
        result['output'] = proc.stdout

        # Parse binwalk output
        for line in proc.stdout.split('\n'):
            line_lower = line.lower()

            # U-Boot detection
            if 'u-boot' in line_lower or 'uboot' in line_lower:
                result['uboot'] = line.strip()
                # Try to extract version
                ver_match = re.search(r'u-boot\s*([\d.]+)', line_lower)
                if ver_match:
                    result['uboot_version'] = ver_match.group(1)

            # Kernel detection
            if 'linux kernel' in line_lower or 'kernel' in line_lower:
                result['kernel'] = line.strip()
                # Try to extract version
                ver_match = re.search(r'(\d+\.\d+\.\d+)', line)
                if ver_match:
                    result['kernel_version'] = ver_match.group(1)

            # Filesystem detection
            if 'squashfs' in line_lower:
                result['filesystem'].append(('SquashFS', line.strip()))
            elif 'jffs2' in line_lower:
                result['filesystem'].append(('JFFS2', line.strip()))
            elif 'cramfs' in line_lower:
                result['filesystem'].append(('CramFS', line.strip()))
            elif 'ubifs' in line_lower or 'ubi ' in line_lower:
                result['filesystem'].append(('UBIFS', line.strip()))
            elif 'romfs' in line_lower:
                result['filesystem'].append(('RomFS', line.strip()))
            elif 'ext2' in line_lower or 'ext3' in line_lower or 'ext4' in line_lower:
                result['filesystem'].append(('EXT', line.strip()))

            # Compressed sections
            if 'gzip' in line_lower:
                result['compressed'].append(('gzip', line.strip()))
            elif 'lzma' in line_lower:
                result['compressed'].append(('LZMA', line.strip()))
            elif 'xz' in line_lower:
                result['compressed'].append(('XZ', line.strip()))
            elif 'zlib' in line_lower:
                result['compressed'].append(('zlib', line.strip()))

    except subprocess.TimeoutExpired:
        result['output'] = "Scan timed out"
    except Exception as e:
        result['output'] = f"Error: {e}"

    return result


def extract_firmware(filepath: str, output_dir: str) -> bool:
    """
    Extract firmware using binwalk -Me (matryoshka extraction).

    Returns:
        True if extraction successful
    """
    if not check_binwalk_installed():
        return False

    try:
        log.info("Extracting firmware with binwalk -Me...")
        result = subprocess.run(
            ['binwalk', '-Me', '-C', output_dir, filepath],
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes timeout for deep extraction
        )

        # Check if anything was extracted
        for item in os.listdir(output_dir):
            item_path = os.path.join(output_dir, item)
            if os.path.isdir(item_path):
                return True

        return False

    except subprocess.TimeoutExpired:
        log.warning("Extraction timed out")
        return False
    except Exception as e:
        log.warning(f"Extraction error: {e}")
        return False


def find_busybox(directory: str) -> str:
    """Find busybox binary in extracted filesystem."""
    busybox_names = ['busybox', 'busybox.nosuid', 'busybox-smp']

    for root, dirs, files in os.walk(directory):
        for name in busybox_names:
            if name in files:
                filepath = os.path.join(root, name)
                if not os.path.islink(filepath):
                    return filepath

    return None


def find_elf_binaries(directory: str, max_files: int = 20) -> list:
    """Find ELF binaries in extracted filesystem, prioritizing common binaries."""
    elf_files = []
    priority_names = ['busybox', 'httpd', 'lighttpd', 'nginx', 'dropbear', 'sshd',
                      'telnetd', 'boa', 'goahead', 'mini_httpd', 'uhttpd',
                      'nvram', 'mtd', 'flash', 'upgrade', 'rc', 'init']

    # First pass: find priority binaries
    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.islink(filepath):
                continue

            try:
                with open(filepath, 'rb') as f:
                    magic = f.read(4)
                    if magic == ELF_MAGIC:
                        if filename in priority_names:
                            elf_files.insert(0, filepath)
                        else:
                            elf_files.append(filepath)

                        if len(elf_files) >= max_files:
                            return elf_files
            except:
                continue

    return elf_files


def analyze_elf_detailed(filepath: str) -> dict:
    """
    Detailed ELF analysis to extract arch, bits, endian, and mcpu.

    Returns:
        dict with 'arch', 'bits', 'endian', 'mcpu', 'mcpu_name' or None
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(64)
    except:
        return None

    if len(data) < 52 or data[:4] != ELF_MAGIC:
        return None

    result = {}

    # ELF class (32/64 bit)
    ei_class = data[4]
    result['bits'] = 32 if ei_class == 1 else 64

    # Endianness
    ei_data = data[5]
    result['endian'] = 'little' if ei_data == 1 else 'big'

    # e_machine and e_flags
    if result['endian'] == 'little':
        e_machine = struct.unpack('<H', data[18:20])[0]
        e_flags = struct.unpack('<I', data[36:40])[0] if len(data) >= 40 else 0
    else:
        e_machine = struct.unpack('>H', data[18:20])[0]
        e_flags = struct.unpack('>I', data[36:40])[0] if len(data) >= 40 else 0

    if e_machine not in ELF_MACHINES:
        return None

    base_arch, _ = ELF_MACHINES[e_machine]
    result['arch'] = base_arch
    result['mcpu'] = None
    result['mcpu_name'] = None

    # Detect mcpu based on architecture
    if base_arch == 'mips':
        mips_isa = e_flags & 0xf0000000
        if mips_isa in MIPS_ISA_FLAGS:
            result['mcpu'], result['mcpu_name'] = MIPS_ISA_FLAGS[mips_isa]
        else:
            result['mcpu'] = 'mips32r2'
            result['mcpu_name'] = 'MIPS32 Release 2 (default)'

    elif base_arch == 'arm':
        arm_eabi = (e_flags >> 24) & 0xff
        if arm_eabi >= 5:
            result['mcpu'] = 'cortex-a7'
            result['mcpu_name'] = 'ARM Cortex-A (EABI5+)'
        else:
            result['mcpu'] = 'arm926ej-s'
            result['mcpu_name'] = 'ARM9 family'

    elif base_arch == 'aarch64':
        result['mcpu'] = 'cortex-a53'
        result['mcpu_name'] = 'ARM Cortex-A53'

    elif base_arch == 'x86':
        result['mcpu'] = 'i686'
        result['mcpu_name'] = 'x86 (i686)'

    elif base_arch == 'x64':
        result['mcpu'] = 'x86-64'
        result['mcpu_name'] = 'x86-64'

    elif base_arch == 'powerpc':
        result['mcpu'] = 'powerpc'
        result['mcpu_name'] = 'PowerPC'

    return result


def map_to_hackebds_arch(arch_info: dict) -> str:
    """Map detected architecture info to hackebds arch name."""
    if not arch_info:
        return None

    arch = arch_info['arch']
    bits = arch_info['bits']
    endian = arch_info['endian']
    mcpu = arch_info.get('mcpu', '')

    # Special handling for ARM to distinguish v5 vs v7
    if arch == 'arm':
        # Determine ARM version based on mcpu
        arm_version = 'v7'  # Default to v7
        if mcpu:
            mcpu_lower = mcpu.lower()
            # ARMv5 or earlier CPUs
            if any(x in mcpu_lower for x in ['arm9', 'arm7', 'arm926', 'xscale', 'iwmmxt']):
                arm_version = 'v5'
            # ARMv6 CPUs (map to v5 for compatibility)
            elif any(x in mcpu_lower for x in ['arm11', '1136', '1176', '1156']):
                arm_version = 'v5'
            # ARMv7+ CPUs
            elif 'cortex' in mcpu_lower:
                arm_version = 'v7'

        if endian == 'little':
            return f'armel{arm_version}'
        else:
            return f'armeb{arm_version}'

    # Standard lookup for other architectures
    key = (arch, bits, endian)

    if key in ARCH_MAPPING:
        return ARCH_MAPPING[key]

    # Fallback
    for k, v in ARCH_MAPPING.items():
        if k[0] == arch and k[2] == endian:
            return v

    return None


def print_firmware_info(info: dict):
    """Print firmware analysis results in formatted output."""
    print()
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}         FIRMWARE ANALYSIS RESULTS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print()

    # File info
    if info.get('filename'):
        print(f"{Fore.GREEN}File:{Style.RESET_ALL} {info['filename']}")
    if info.get('filesize'):
        size_mb = info['filesize'] / (1024 * 1024)
        print(f"{Fore.GREEN}Size:{Style.RESET_ALL} {info['filesize']:,} bytes ({size_mb:.2f} MB)")
    print()

    # Encryption check
    print(f"{Fore.YELLOW}[Encryption Check]{Style.RESET_ALL}")
    if info.get('entropy'):
        print(f"  Entropy: {info['entropy']:.2f}/8.0")
    if info.get('encrypted'):
        print(f"  {Fore.RED}Status: LIKELY ENCRYPTED{Style.RESET_ALL}")
        print(f"  {info.get('encrypt_reason', '')}")
    else:
        print(f"  {Fore.GREEN}Status: Not encrypted{Style.RESET_ALL}")
    print()

    # Bootloader
    print(f"{Fore.YELLOW}[Bootloader]{Style.RESET_ALL}")
    if info.get('uboot'):
        print(f"  Type: U-Boot")
        if info.get('uboot_version'):
            print(f"  Version: {info['uboot_version']}")
    else:
        print(f"  Not detected or custom bootloader")
    print()

    # Kernel
    print(f"{Fore.YELLOW}[Kernel]{Style.RESET_ALL}")
    if info.get('kernel'):
        print(f"  Type: Linux Kernel")
        if info.get('kernel_version'):
            print(f"  Version: {info['kernel_version']}")
    else:
        print(f"  Not detected")
    print()

    # Filesystem
    print(f"{Fore.YELLOW}[Filesystem]{Style.RESET_ALL}")
    if info.get('filesystem'):
        for fs_type, detail in info['filesystem']:
            print(f"  Type: {fs_type}")
    else:
        print(f"  Not detected")
    print()

    # Compression
    if info.get('compressed'):
        print(f"{Fore.YELLOW}[Compression]{Style.RESET_ALL}")
        compression_types = set(c[0] for c in info['compressed'])
        print(f"  Methods: {', '.join(compression_types)}")
        print()

    # Architecture
    print(f"{Fore.YELLOW}[Architecture]{Style.RESET_ALL}")
    if info.get('arch_detected'):
        print(f"  Architecture: {info['arch']}")
        print(f"  Bits: {info.get('bits', 'Unknown')}")
        print(f"  Endian: {info.get('endian', 'Unknown')}")
        if info.get('mcpu'):
            print(f"  CPU Type: {info['mcpu']}")
        if info.get('mcpu_name'):
            print(f"  CPU Name: {info['mcpu_name']}")
        if info.get('hackebds_arch'):
            print(f"  {Fore.GREEN}hackebds arch:{Style.RESET_ALL} {info['hackebds_arch']}")
    else:
        print(f"  {Fore.RED}Could not detect architecture{Style.RESET_ALL}")
    print()

    # Analyzed binary
    if info.get('analyzed_binary'):
        print(f"{Fore.YELLOW}[Analyzed Binary]{Style.RESET_ALL}")
        print(f"  File: {os.path.basename(info['analyzed_binary'])}")
        print()

    # Usage hint
    if info.get('hackebds_arch'):
        print(f"{Fore.CYAN}[Usage Example]{Style.RESET_ALL}")
        endian_flag = '-li' if info.get('endian') == 'little' else '-bi'

        # Show -arch based command first (compatible with older versions)
        print(f"  {Fore.GREEN}[Compatible Command - Recommended for General Use]{Style.RESET_ALL}")
        print(f"  hackebds -arch {info['hackebds_arch']} {endian_flag} -reverse_ip <IP> -reverse_port <PORT> -res reverse_shell_file")
        print()

        # Show -mcpu based command if mcpu is available (more precise)
        if info.get('mcpu'):
            print(f"  {Fore.YELLOW}[Precise Command - For Best Compatibility with Target Device]{Style.RESET_ALL}")
            print(f"  hackebds -mcpu {info['mcpu']} {endian_flag} -reverse_ip <IP> -reverse_port <PORT> -res reverse_shell_file")
            print()
            print(f"  {Fore.RED}Note:{Style.RESET_ALL} Using -mcpu {info['mcpu']} ensures the generated binary matches")
            print(f"        the exact CPU type detected from the firmware. This provides better")
            print(f"        compatibility but requires the target device to have the detected CPU.")
        print()

    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print()


def analyze_firmware(filepath: str) -> dict:
    """
    Analyze a firmware file to detect architecture and display detailed info.

    Args:
        filepath: Path to firmware file

    Returns:
        dict with analysis results
    """
    if not os.path.exists(filepath):
        log.error(f"Firmware file not found: {filepath}")
        return None

    log.info(f"Analyzing firmware: {filepath}")

    result = {
        'filename': os.path.basename(filepath),
        'filesize': os.path.getsize(filepath),
        'arch_detected': False,
    }

    # Step 1: Read file header
    try:
        with open(filepath, 'rb') as f:
            header_data = f.read(4096)
    except Exception as e:
        log.error(f"Failed to read firmware: {e}")
        return None

    # Step 2: Check encryption
    is_encrypted, entropy, reason = check_firmware_encrypted(filepath)
    result['encrypted'] = is_encrypted
    result['entropy'] = entropy
    result['encrypt_reason'] = reason

    if is_encrypted:
        log.warning("Firmware appears to be encrypted!")
        print_firmware_info(result)
        log.error("Cannot analyze encrypted firmware. Decrypt first or specify -arch and -mcpu manually.")
        return None

    # Step 3: Check if it's a simple ELF file
    if header_data[:4] == ELF_MAGIC:
        log.info("Firmware is an ELF binary")
        arch_info = analyze_elf_detailed(filepath)
        if arch_info:
            result['arch'] = arch_info['arch']
            result['bits'] = arch_info['bits']
            result['endian'] = arch_info['endian']
            result['mcpu'] = arch_info.get('mcpu')
            result['mcpu_name'] = arch_info.get('mcpu_name')
            result['hackebds_arch'] = map_to_hackebds_arch(arch_info)
            result['arch_detected'] = True
            result['analyzed_binary'] = filepath

        print_firmware_info(result)
        return result

    # Step 4: Run binwalk scan
    if not check_binwalk_installed():
        log.error("binwalk is required for firmware analysis")
        log.info("Install: pip install binwalk  or  apt install binwalk")
        print_firmware_info(result)
        return None

    log.info("Running binwalk scan...")
    scan_result = run_binwalk_scan(filepath)

    result['uboot'] = scan_result.get('uboot')
    result['uboot_version'] = scan_result.get('uboot_version')
    result['kernel'] = scan_result.get('kernel')
    result['kernel_version'] = scan_result.get('kernel_version')
    result['filesystem'] = scan_result.get('filesystem', [])
    result['compressed'] = scan_result.get('compressed', [])

    # Step 5: Extract firmware
    temp_dir = tempfile.mkdtemp(prefix='hackebds_fw_')

    try:
        if not extract_firmware(filepath, temp_dir):
            log.warning("Could not extract firmware filesystem")
            print_firmware_info(result)
            return result

        # Step 6: Find and analyze binaries
        busybox = find_busybox(temp_dir)
        if busybox:
            log.info(f"Found busybox: {busybox}")
            arch_info = analyze_elf_detailed(busybox)
            if arch_info:
                result['arch'] = arch_info['arch']
                result['bits'] = arch_info['bits']
                result['endian'] = arch_info['endian']
                result['mcpu'] = arch_info.get('mcpu')
                result['mcpu_name'] = arch_info.get('mcpu_name')
                result['hackebds_arch'] = map_to_hackebds_arch(arch_info)
                result['arch_detected'] = True
                result['analyzed_binary'] = busybox
        else:
            # Find other ELF binaries
            elf_files = find_elf_binaries(temp_dir)
            if elf_files:
                log.info(f"Analyzing {len(elf_files)} ELF binaries...")

                arch_votes = {}
                for elf_path in elf_files[:10]:
                    arch_info = analyze_elf_detailed(elf_path)
                    if arch_info:
                        key = (arch_info['arch'], arch_info['bits'], arch_info['endian'])
                        arch_votes[key] = arch_votes.get(key, 0) + 1

                        if not result.get('arch_detected'):
                            result['arch'] = arch_info['arch']
                            result['bits'] = arch_info['bits']
                            result['endian'] = arch_info['endian']
                            result['mcpu'] = arch_info.get('mcpu')
                            result['mcpu_name'] = arch_info.get('mcpu_name')
                            result['hackebds_arch'] = map_to_hackebds_arch(arch_info)
                            result['arch_detected'] = True
                            result['analyzed_binary'] = elf_path

                # Use most common architecture
                if arch_votes:
                    best_key = max(arch_votes, key=arch_votes.get)
                    log.info(f"Most common arch: {best_key} ({arch_votes[best_key]} files)")

    finally:
        # Cleanup
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

    print_firmware_info(result)
    return result
