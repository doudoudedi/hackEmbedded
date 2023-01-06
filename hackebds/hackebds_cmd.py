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

remove_null = lambda x:[i for i in x if i != '']

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



def spaceReplace(i):
    i = re.sub(' +', ' ', i).split(' ')
    return i


def mipsel_shell_cmd(cmd, cmd_whole_path, envp,filename=None):
	context.arch='mips'
	context.endian='little'
	context.bits="32"
	log.success("CMD is  "+ cmd)
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	#cmd = spaceReplace(cmd)
	#cmd = cmd_basic + cmd
	#for i in range(len(cmd)):
	#	cmd[i] = cmd[i] + "\x00"
	if (envp == None):
		envp = 0
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
	shellcode = shellcraft.execve(cmd_whole_path,cmd,0)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	cmd = cmd[::-1]
	if (envp == None):
		envp = 0
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
		filename = my_package.my_make_elf(shellcode, filename)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	cmd = cmd[::-1]
	if (envp == None):
		envp = 0
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
		filename = my_package.my_make_elf(shellcode, filename)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
	#cmd_list = cmd_list.reverse()
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null(cmd_basic)
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
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
		filename = my_package.my_make_elf(shellcode, filename)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
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
		filename = my_package.my_make_elf(shellcode, filename)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
	shellcode = shellcraft.execve(cmd_whole_path, cmd, 0)
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



def x86_cmd_file(cmd, cmd_whole_path, envp,filename):
	context.arch = 'i386'
	context.endian = 'little'
	context.bits = '32'
	log.success("CMD: "+cmd)
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
	shellcode = shellcraft.execve(cmd_whole_path, cmd, 0)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
	shellcode = shellcraft.execve(cmd_whole_path, cmd, 0)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
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
		filename = my_package.my_make_elf(shellcode, filename)
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
	if cmd_whole_path == "/bin/sh":
		cmd_basic = ['sh','-c']
		cmd_basic.append(cmd)
		cmd = remove_null((cmd_basic))
	else:
		#cmd = remove_null(handle_quotation_mark(cmd))
		cmd = remove_null(spaceReplace(cmd))
	if (envp == None):
		envp = 0
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
		filename = my_package.my_make_elf(shellcode, filename)
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