from pwn import shellcraft,context,log,sleep,make_elf,asm
import os
from colorama import Fore,Back,Style
from . import my_package
import string
import re

chars = string.ascii_letters
'''
add 12.22 
mipsel_shell_cmd
mips_shell_cmd
armelv5_shell_cmd
'''

def handle_quotation_mark(str1):
	sub = "'|\""
	mark_list  = [substr.start() for substr in re.finditer(sub, str1)]
	mark_list.insert(0,0)
	len_mark_list  = len(mark_list)
	mark_list.insert(len_mark_list, len(str1))
	print(mark_list)
	if (len(mark_list)%2!=0):
		log.info("maybe command error")
		return 
	cmd = []
	for i in range(len(mark_list)):
		try:
			if (i==0):
				cmd = cmd + str1[mark_list[i]:mark_list[i+1]].split(" ")
			else:
				cmd = cmd + str1[mark_list[i]+1:mark_list[i+1]].split(" ")
		except Exception as e:
			pass
	return cmd





def mipsel_shell_cmd(cmd, cmd_whole_path, envp,filename=None):
	context.arch='mips'
	context.endian='little'
	context.bits="32"
	log.success("CMD is  "+ cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.execve(cmd_whole_path,cmd,envp)
	shellcode = asm(shellcode)
	ELF_data=make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
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


def mips_shell_cmd(cmd, cmd_whole_path, envp,filename=None):
	context.arch='mips'
	context.endian='big'
	context.bits="32"
	log.success("CMD is  "+ cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.execve(cmd_whole_path,cmd,envp)
	shellcode = asm(shellcode)
	ELF_data=make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		f=open(filename,"wb")
		f.write(ELF_data)
		f.close()
		log.success("{} is ok in current path ./".format(filename))
		os.chmod(filename, 0o755)
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

def armelv5_shell_cmd(cmd,cmd_whole_path ,envp,filename=None):
	context.arch = 'arm'
	context.endian = 'little'
	context.bits = '32'
	log.success("CMD: "+cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	cmd = cmd[::-1]
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	data_shellcode = ''
	text_shellcode = ''
	#cmd_list = cmd_list.reverse()
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "ldr r2, =cmd%d\npush {r2}\n"%(i)
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
	.ARM
		add	r3, pc, #1
		bx	r3
	.THUMB
		ldr r0, =spawn
		eor     r3, r3
		push  {r3}
	'''
	shellcode_text += text_shellcode
	shellcode_text += '''
		eor r2, r2
		mov r1, sp
		mov r7, #11
		svc #1
	'''
	shellcode = shellcode_data + shellcode_text
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
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
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return

def armebv5_shell_cmd(cmd, cmd_whole_path, envp,filename):
	context.arch = 'arm'
	context.endian = 'big'
	context.bits = '32'
	log.success("CMD: "+cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	cmd = cmd[::-1]
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	data_shellcode = ''
	text_shellcode = ''
	#cmd_list = cmd_list.reverse()
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "ldr r2, =cmd%d\npush {r2}\n"%(i)
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
	.ARM
		add	r3, pc, #1
		bx	r3
	.THUMB
		ldr r0, =spawn
		eor     r3, r3
		push  {r3}
	'''
	shellcode_text += text_shellcode
	shellcode_text += '''
		eor r2, r2
		mov r1, sp
		mov r7, #11
		svc #1
	'''
	shellcode = shellcode_data + shellcode_text
	#print(shellcode)
	#ith open("2.s",'w') as f:
	#	f.write(shellcode)
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
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
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return


def armelv7_shell_cmd(cmd, cmd_whole_path, envp,filename):
	context.arch = 'arm'
	context.endian = 'little'
	context.bits = '32'
	log.success("CMD: "+cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.execve(cmd_whole_path, cmd, envp)
	shellcode = asm(shellcode)
	ELF_data=make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		f =open(filename,"wb")
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

def armebv7_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'arm'
	context.endian = 'big'
	context.bits = '32'
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.execve(cmd_whole_path, cmd, envp)
	shellcode = asm(shellcode)
	ELF_data=make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
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
'''
mips64,mips64el,cmdfile 2022.12.23 add by doudoudedi
'''



def mips64_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'mips64'
	context.endian = 'big'
	context.bits = '64'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	#cmd_list = cmd_list.reverse()
	num = 1
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "dla $t3, cmd%d\nsd $t3,+%d($sp)\n"%(i, num*8)
		num = num+1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global __start
__start:
dla $a0, spawn
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
xor $t3, $t3, $t3
sd  $t3, +%d($sp)
daddiu $a1,$sp,8
xor $a2, $a2, $a2
li $v0, 0x13c1
syscall 0x40404
	'''%(num*8)
	#print(shellcode_text)
	shellcode = shellcode_data + shellcode_text
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
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
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return


def mips64el_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'mips64'
	context.endian = 'little'
	context.bits = '64'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	#cmd_list = cmd_list.reverse()
	num = 1
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "dla $t3, cmd%d\nsd $t3,+%d($sp)\n"%(i, num*8)
		num = num+1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global __start
__start:
dla $a0, spawn
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
xor $t3, $t3, $t3
sd  $t3, +%d($sp)
daddiu $a1,$sp,8
xor $a2, $a2, $a2
li $v0, 0x13c1
syscall 0x40404
	'''%(num*8)
	#print(shellcode_text)
	shellcode = shellcode_data + shellcode_text
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
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
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return

'''
add 1.5 
aarch64_cmd_file
x86_cmd_file
x64_cmd_file
'''

def aarch64_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'aarch64'
	context.endian = 'little'
	context.bits = '64'
	log.success("CMD: "+cmd)

	shellcode = '''
	.section .data
	.data
	cmd: .ascii "%s\\x00"
	.section .shellcode,"awx"
	.global _start
	.global __start
	.p2align 2
	_start:
	__start:
	'''%(cmd)

	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		
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
	mov  x15, #25389
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


	ldr x15, =cmd

	str x15, [sp, #16]

	/* set x1 to the current top of the stack */
	mov  x2, xzr
	/* call execve() */
	mov  x8, #0xdd
	svc 0
		'''

	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		shellcode += '''
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
	movk x15, #25389, lsl #16
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

	sub sp, sp, 8

	ldr x15, =cmd

	str x15, [sp, #32]

	/* set x1 to the current top of the stack */
	mov  x2, xzr
	/* call execve() */
	mov  x8, #0xdd
	svc 0
	'''
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	#shellcode = shellcraft.execve(cmd_whole_path, cmd, envp)
	#shellcode = asm(shellcode)
	#ELF_data=make_elf(shellcode)
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_elf(shellcode, filename)
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
				my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return


def x86_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'i386'
	context.endian = 'little'
	context.bits = '32'
	log.success("CMD: "+cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.execve(cmd_whole_path, cmd, envp)
	shellcode = asm(shellcode)
	ELF_data=make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
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


def x64_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'amd64'
	context.endian = 'little'
	context.bits = '64'
	log.success("CMD: "+cmd)
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = shellcraft.execve(cmd_whole_path, cmd, envp)
	shellcode = asm(shellcode)
	ELF_data=make_elf(shellcode)
	if filename==None:
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
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

'''
aim to aarch64_cmd_file
def android_aarch64_cmd(cmd, cmd_whole_path, filename):
	context.arch = 'aarch64'
	context.endian = 'little'
	context.bits = 64
'''


def riscv64el_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch='riscv'
	context.bits="64"
	context.endian="little"
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	#cmd_list = cmd_list.reverse()
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "la a5, cmd%d\nsd a5,%d(sp)\n"%(i, num*8)
		num = num+1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
la a0, spawn
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
slt a2,zero,-1 
sd  a2,%d(sp)
mv  a1,sp
li a7, 221
ecall
	'''%(num*8)
	shellcode = shellcode_data + shellcode_text
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return

'''
add 1.6
powerpc_cmd_file
'''


def powerpc_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch='powerpc'
	context.bits="32"
	context.endian="big"
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	#cmd_list = cmd_list.reverse()
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "lis 9, cmd%d@ha\naddi 9,9,cmd%d@l\nstwu 9,4(1)\n"%(i,i)
		num = num +1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
lis  3, spawn@ha
addi 3,3,spawn@l
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
xor   5,5,5 
stwu  5,%d(1)
addi  4,1,-%d
li    0, 0xb
sc

	'''%(4,(num)*4)
	shellcode = shellcode_data + shellcode_text
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 


'''
1.13
powerpc64_cmd_file
powerpcle_cmd_file
powerpc64le_cmd_file
'''

def powerpcle_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'powerpc'
	context.endian = 'little'
	context.bits = '32'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "lis 9, cmd%d@ha\naddi 9,9,cmd%d@l\nstwu 9,4(1)\n"%(i,i)
		num = num +1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
lis  3, spawn@ha
addi 3,3,spawn@l
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
xor   5,5,5 
stwu  5,%d(1)
addi  4,1,-%d
li    0, 0xb
sc

	'''%(4,(num)*4)
	shellcode = shellcode_data + shellcode_text
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 


def powerpc64_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'powerpc64'
	context.endian = 'big'
	context.bits = '64'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "lis 9, cmd%d@ha\naddi 9,9,cmd%d@l\nstd 9,%d(31)\n"%(i,i,num*8)
		num = num +1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
mr   31, 1
lis  3, spawn@ha
addi 3,3,spawn@l
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
xor   5,5,5 
std  5,%d(31)
mr   4, 31
li    0, 0xb
sc

	'''%(num*8)
	shellcode = shellcode_data + shellcode_text
	#print(shellcode)
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 


def powerpc64le_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'powerpc64'
	context.endian = 'little'
	context.bits = '64'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "lis 9, cmd%d@ha\naddi 9,9,cmd%d@l\nstd 9,%d(31)\n"%(i,i,num*8)
		num = num +1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)
	shellcode_data += data_shellcode
	shellcode_text = '''
.text
.global _start
_start:
mr   31, 1
lis  3, spawn@ha
addi 3,3,spawn@l
'''
	shellcode_text += text_shellcode
	shellcode_text += '''
xor   5,5,5 
std  5,%d(31)
mr   4, 31
li    0, 0xb
sc

	'''%(num*8)
	shellcode = shellcode_data + shellcode_text
	#print(shellcode)
	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 


'''
2023.1.9
add sparc,sparc64 cmd file
bash or sh
'''

def sparc_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'sparc'
	context.endian = 'big'
	context.bits = '32'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "set cmd{}, %g1\nst %g1,[%sp + {}]\n".format(i, num*4)
		num = num +1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)

	shellcode_data += data_shellcode

	shellcode_text = '''
.text
.global _start
_start:
set spawn , %g1
mov %g1,%o0
mov 0, %g2
mov %g3,%o2
	'''

	shellcode_text += text_shellcode

	shellcode_text += '''
st %o2,[%sp + {}]
mov 0x3b, %g1
mov %sp, %o1
ta 0x10

	'''.format(num*4)
	shellcode = shellcode_data + shellcode_text

	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 


def sparc64_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'sparc64'
	context.endian = 'big'
	context.bits = '64'
	log.success("CMD: "+cmd)
	data_shellcode = ''
	text_shellcode = ''
	if cmd_whole_path == "/bin/sh" or cmd_whole_path == "sh":
		cmd_whole_path = "/bin/sh"
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	elif cmd_whole_path == "/bin/bash" or cmd_whole_path == "bash":
		cmd_whole_path = "/bin/bash"
		cmd_basic = ['/bin/bash','-c']
		cmd_basic.append(cmd)
		cmd = my_package.remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = my_package.remove_null(my_package.spaceReplace(cmd))
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	num = 0
	for i in range(len(cmd)):
		data_shellcode += "cmd%d: .ascii \"%s\\x00\"\n"%(i, cmd[i])
		text_shellcode += "set cmd{}, %g1\nstx %g1,[%sp + {}]\n".format(i, num*8)
		num = num +1
	shellcode_data = """
.section .data
.section .text
.data
spawn: .ascii "%s\\x00"
	"""
	shellcode_data = shellcode_data%(cmd_whole_path)

	shellcode_data += data_shellcode

	shellcode_text = '''
.text
.global _start
_start:
set spawn , %g1
mov %g1,%o0
mov 0, %g2
mov %g3,%o2
	'''

	shellcode_text += text_shellcode

	shellcode_text += '''
stx %o2,[%sp + {}]
mov 0x3b, %g1
mov %sp, %o1
ta 0x10

	'''.format(num*8)
	shellcode = shellcode_data + shellcode_text

	if(filename == None ):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-cmd-" + my_package.random_string_generator(4,chars)
		my_package.my_make_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch='i386'
		context.bits="32"
		context.endian="little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			filename = my_package.my_make_elf(shellcode, filename)
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
				filename = my_package.my_make_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
				return 
			else:
				return 
