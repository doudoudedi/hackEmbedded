from pwn import context,asm,pwnlib,log
import my_package

def loongarch64_backdoor():
    context.architectures['loongarch64'] = {'endian': 'little', 'bits': 64}
    context.arch = 'loongarch64'
    shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:

ori	$r11,$r0,0xc6
syscall 0x0
    '''
    my_package.my_make_loongarch64_elf(shellcode)

loongarch64_backdoor()