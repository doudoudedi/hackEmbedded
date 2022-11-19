from pwn import *
'''
11.17 add sparc32 ,powerpc don't exam
socket 0xce like x86
connect 0xce like x86
dup2  0x5A
execve  0x3B
'''


def sparc_backdoor(reverse_ip, reverse_port, filename = None):
    context.arch = 'sparc'
    context.endian = 'big'
    context.bits = '32'
    log.success("reverse_ip is: "+ reverse_ip)
    log.success("reverse_port is: "+str(reverse_port))

def sparcle_backdoor(reverse_ip, reverse_port, filename = None):
    context.arch = 'sparc'
    context.endian = 'little'
    context.bits = '32'
    log.success("reverse_ip is: "+ reverse_ip)
    log.success("reverse_port is: "+str(reverse_port))

