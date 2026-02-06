from pwn import *


def extract_sl_print(source_shellcode,shellcode_for_hex):
	data=enhex(source_shellcode)
	for i in range(len(data)):
		if i%2==0:
			shellcode_for_hex+="\\x"
		shellcode_for_hex+=data[i]
	return shellcode_for_hex
