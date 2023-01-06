import os
import shutil
import random
import string
from os import path
import subprocess
import tempfile
from pwn import context,log,sleep,pwnlib
from pwnlib import atexit


chars = string.ascii_letters

def random_string_generator(str_size, allowed_chars):
	return ''.join(random.choice(allowed_chars) for x in range(str_size))

	
'''
child1 = subprocess.Popen(['cat','/etc/passwd'],stdout=subprocess.PIPE)
print(child1.stdout.read())

update 2022.12.25 
'''

def my_make_elf(code , filename=None,vma= None,shared=False, strip=None,extract=None):
	assembler = pwnlib.asm._assembler()
	linker    = pwnlib.asm._linker()
	log.debug("Building ELF:\n")
	tmpdir= tempfile.mkdtemp(prefix = 'pwn-asm-')
	step1 = path.join(tmpdir, 'step1-asm')
	step2 = path.join(tmpdir, 'step2-obj')
	step3 = path.join(tmpdir, 'step3-elf')
	try:
		with open(step1, 'w') as f:
			f.write(code)

		pwnlib.asm._run(assembler + ['-o', step2, step1])
		linker_options = ['-z', 'execstack']
		if vma is not None:

			linker_options += ['--section-start=.shellcode=%#x' % vma,
                               '--entry=%#x' % vma]
		elif shared:
			linker_options += ['-shared', '-init=_start']

		linker_options += ['-o', step3, step2]

		pwnlib.asm._run(linker + linker_options)

		if strip:
			pwnlib.asm._run([pwnlib.asm.which_binutils('objcopy'), '-Sg', step3])
			pwnlib.asm._run([pwnlib.asm.which_binutils('strip'), '--strip-unneeded', step3])

		if not extract:
			os.chmod(step3, 0o755)
			if(filename == None):
				basename = context.arch + "-cmd-" + random_string_generator(4,chars)
				shutil.copyfile(step3,basename)
				os.chmod(basename, 0o755)
				retval = basename
			else:
				shutil.copyfile(step3,filename)
				os.chmod(filename, 0o755)
				retval = filename

		else:
			with open(step3, 'rb') as f:
				retval = f.read()
	except Exception:
		log.exception("An error occurred while building an ELF:\n%s" % code)
	else:
		atexit.register(lambda: shutil.rmtree(tmpdir))
	return retval
	'''
	if arch =='arm' or arch == 'mips64' or arch == 'mips64el':
		generate_o_cmd = [assembler_as, assembler[2],'-o',generate_o,source_s]
		generate_elf_cmd = [assembler_ld, assembler[2],'-o', filename, generate_o]
	else:
		generate_o_cmd = [assembler_as, assembler[2], assembler[3],'-o',generate_o,source_s]
		generate_elf_cmd = [assembler_ld, '-o', filename, generate_o]
	try:
		print(generate_o_cmd)
		print(generate_elf_cmd)
		child1 = subprocess.Popen(generate_o_cmd ,stdout=subprocess.PIPE)
		sleep(0.2)
		child2 = subprocess.Popen(generate_elf_cmd ,stdout=subprocess.PIPE)
		log.success("{} generated successfully".format(filename))
		sleep(0.2)
		os.remove(generate_o)
		sleep(0.2)
		os.remove(source_s)
	except  Exception as e:
		print(e)
		os.remove(generate_o)
		os.remove(source_s)
	'''