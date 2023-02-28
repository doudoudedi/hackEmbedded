import os
import shutil
import random
import string
from os import path
import subprocess
from subprocess import PIPE
import tempfile
from pwn import context,log,sleep,pwnlib
from pwnlib import atexit
import re
import platform

chars = string.ascii_letters

def random_string_generator(str_size, allowed_chars):
	return ''.join(random.choice(allowed_chars) for x in range(str_size))

	
'''
child1 = subprocess.Popen(['cat','/etc/passwd'],stdout=subprocess.PIPE)
print(child1.stdout.read())

update 2022.12.25 
'''

remove_null = lambda x:[i for i in x if i != '']


def spaceReplace(i):
    i = re.sub(' +', ' ', i).split(' ')
    return i


def get_envir_args(envp):
	return remove_null(spaceReplace(envp))



def my_make_elf(code , filename=None,vma= None,shared=False, strip=None,extract=None):
	assembler = pwnlib.asm._assembler()
	linker    = pwnlib.asm._linker()
	log.debug("Building ELF:\n")
	tmpdir= tempfile.mkdtemp(prefix = 'pwn-asm-')
	step1 = path.join(tmpdir, 'step1-asm')
	step2 = path.join(tmpdir, 'step2-obj')
	step3 = path.join(tmpdir, 'step3-elf')
	try:
		code = pwnlib.asm.cpp(code)
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
				basename = context.arch + '-noknow-' + random_string_generator(4,chars)
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

def my_bfdname():
    arch = context.arch
    E    = context.endianness
    #print("doudou")
    bfdnames = {
        'i386'    : 'elf32-i386',
        'aarch64' : 'elf64-%saarch64' % E,
        'amd64'   : 'elf64-x86-64',
        'arm'     : 'elf32-%sarm' % E,
        'thumb'   : 'elf32-%sarm' % E,
        'avr'     : 'elf32-avr',
        'mips'    : 'elf32-trad%smips' % E,
        'mips64'  : 'elf64-trad%smips' % E,
        'alpha'   : 'elf64-alpha',
        'cris'    : 'elf32-cris',
        'ia64'    : 'elf64-ia64-%s' % E,
        'm68k'    : 'elf32-m68k',
        'msp430'  : 'elf32-msp430',
        'powerpc' : 'elf32-powerpc',
        'powerpc64' : 'elf64-powerpc',
        'riscv'   : 'elf%d-%sriscv' % (context.bits, E),
        'vax'     : 'elf32-vax',
        's390'    : 'elf%d-s390' % context.bits,
        'sparc'   : 'elf32-sparc',
        'sparc64' : 'elf64-sparc',
        'loongarch64' : None ,
        'mipsn32' : None,
		'mipsn32el' : None
    }

    if arch in bfdnames:
        return bfdnames[arch]
    else:
        raise Exception("Cannot find bfd name for architecture %r" % arch)



def my_linker():
    ld  = [pwnlib.asm.which_binutils('ld')]
    #bfd = ['--oformat=' + my_bfdname()]

    E = {
        'big':    '-EB',
        'little': '-EL'
    }[context.endianness]

    arguments = {
        'i386': ['-m', 'elf_i386'],
    }.get(context.arch, [])

    return ld  + [E] + arguments





def my_make_add_arch_elf(code , filename=None,vma= None,shared=False, strip=None,extract=None):
	assembler = pwnlib.asm._assembler()
	linker    = my_linker()
	log.debug("Building ELF:\n")
	tmpdir= tempfile.mkdtemp(prefix = 'pwn-asm-')
	step1 = path.join(tmpdir, 'step1-asm')
	step2 = path.join(tmpdir, 'step2-obj')
	step3 = path.join(tmpdir, 'step3-elf')
	try:
		code = pwnlib.asm.cpp(code)
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
				basename = context.arch + '-noknow-' + random_string_generator(4,chars)
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


def check_root():
	if(os.getuid() == 0):
		return True
	else:
		return False

def check_mipsn32_envir():
	matter_path = os.path.expanduser('~')
	with open(matter_path+"/.bashrc", "r") as f:
		data = f.read()
	if("export PATH=$PATH:/tmp/mipsn32_binutils" in data):
		return 1
	else:
		return 2


def get_mipsn32_binutils():
	if(platform.system()== "Linux"):
		log.success("checking and installing mipsn32 cross tool")
		try:
			if(os.path.exists("/usr/bin/mipsn32-linux-gnu-as") == True):
				try:
					cmd_out = subprocess.Popen(['readelf','-h', "/usr/bin/mipsn32-linux-gnu-as"], shell=False, stdout=PIPE, stderr = PIPE).stderr.read()
					if cmd_out != b"":
						if(check_root() == True):
							subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32-linux-gnu-as", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32-linux-gnu-as"],shell=False)
						else:
							log.info("root user is required")
							return 1
						log.success("mipsn32-linux-gnu-as download success")
				except:
					log.info("please install readelf")
					return 1
			else:
				if(check_root() == True):
					subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32-linux-gnu-as", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32-linux-gnu-as"],shell=False)
				else:
					log.info("root user is required")
					return 1
				log.success("mipsn32-linux-gnu-as download success")
		except:
			log.info("check your netwrok or download https://github.com/doudoudedi/hackEmbedded/tree/main/cross-tools")
			return 1
		
		#mipsn32_ld = subprocess.check_call
		try:
			if(os.path.exists("/usr/bin/mipsn32-linux-gnu-ld") == True):
				try:
					cmd_out = subprocess.Popen(['readelf','-h', "/usr/bin/mipsn32-linux-gnu-ld"], shell=False, stdout=PIPE, stderr = PIPE).stderr.read()
					if cmd_out != b"":
						if(check_root() == True):
							subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32-linux-gnu-ld", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32-linux-gnu-ld"],shell=False)
						else:
							log.info("root user is required")
							return 1	
						log.success("mipsn32-linux-gnu-ld download success")
				except:
					log.info("please install readelf")
					return 1
			else:
				if(check_root() == True):
					subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32-linux-gnu-ld", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32-linux-gnu-ld"],shell=False)
				else:
					log.info("root user is required")
					return 1
				log.success("mipsn32-linux-gnu-as download success")
		except:
			log.info("check your netwrok or download https://github.com/doudoudedi/hackEmbedded/tree/main/cross-tools")
			return 1
		
		try:
			if(os.path.exists("/usr/bin/mipsn32el-linux-gnu-ld") == True):
				try:
					cmd_out = subprocess.Popen(['readelf','-h', "/usr/bin/mipsn32el-linux-gnu-ld"], shell=False, stdout=PIPE, stderr = PIPE).stderr.read()
					if cmd_out != b"":
						if(check_root() == True):
							subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32el-linux-gnu-ld", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32-linux-gnu-ldel"],shell=False)
						else:
							log.info("root user is required")
							return 1	
						log.success("mipsn32el-linux-gnu-ld download success")
				except:
					log.info("please install readelf")
					return 1
			else:
				if(check_root() == True):
					subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32el-linux-gnu-ld", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32el-linux-gnu-ld"],shell=False)
				else:
					log.info("root user is required")
					return 1
				log.success("mipsn32-linux-gnu-as download success")
		except:
			log.info("check your netwrok or download https://github.com/doudoudedi/hackEmbedded/tree/main/cross-tools")
			return 1
		try:
			if(os.path.exists("/usr/bin/mipsn32el-linux-gnu-as") == True):
				try:
					cmd_out = subprocess.Popen(['readelf','-h', "/usr/bin/mipsn32el-linux-gnu-as"], shell=False, stdout=PIPE, stderr = PIPE).stderr.read()
					if cmd_out != b"":
						if(check_root() == True):
							subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32el-linux-gnu-as", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32el-linux-gnu-as"],shell=False)
						else:
							log.info("root user is required")
							return 1
						log.success("mipsn32el-linux-gnu-as download success")
				except:
					log.info("please install readelf")
					return 1
			else:
				if(check_root() == True):
					subprocess.check_output(["wget", "-O", "/usr/bin/mipsn32el-linux-gnu-as", "-T", "10", "-t", "3","https://github.com/doudoudedi/hackEmbedded/raw/main/cross-tools/mipsn32el-linux-gnu-as"],shell=False)
				else:
					log.info("root user is required")
					return 1
				log.success("mipsn32el-linux-gnu-as download success")
		except:
			log.info("check your netwrok or download https://github.com/doudoudedi/hackEmbedded/tree/main/cross-tools")
			return 1

		#subprocess.Popen("mv","./mipsn32-linux-gnu-as","/usr/bin")
		if(check_root() == True):
			os.system("chmod +x /usr/bin/mipsn32-linux-gnu-as;chmod +x /usr/bin/mipsn32-linux-gnu-ld;chmod +x /usr/bin/mipsn32el-linux-gnu-ld;chmod +x /usr/bin/mipsn32el-linux-gnu-as")
			if(os.path.exists("/tmp/mipsn32_binutils")==False and check_mipsn32_envir()==2):
				try:
					print("Debug")
					os.system("mkdir -p /tmp/mipsn32_binutils;cp /usr/bin/mipsn32-linux-gnu-as /tmp/mipsn32_binutils;cp /usr/bin/mipsn32-linux-gnu-ld /tmp/mipsn32_binutils;cp /usr/bin/mipsn32el-linux-gnu-as /tmp/mipsn32_binutils;cp /usr/bin/mipsn32el-linux-gnu-ld /tmp/mipsn32_binutils")
					os.system("echo \"export PATH=\$PATH:/tmp/mipsn32_binutils\" >> ~/.bashrc")
					log.success("mipsn32_binutils write environment variable succeeded ")
				except:
					log.info("mipsn32_binutils write environment variable faild ")
				

	else:
		log.info("Insufficient permissions(need root) or not linux operating system")
		return 1

