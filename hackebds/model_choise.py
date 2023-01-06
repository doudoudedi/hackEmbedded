import os
from pwn import log,shellcraft
import platform
from colorama import Fore,Back,Style

'''
Equipment model -> backdoor model
This is a learning module. After the generation, add the device model. The tool will remember it after the next use, accelerating the generation of the backdoor and shell code next time

1 arch 0 model 1
2 arch
'''


def get_system_version():
	return platform.system()



model_tree = {
	
}

def touchfile():
	try:
	#with open("/tmp/hackebds_model_table",'w') as f:
	#f.write()
		system_version = get_system_version()
		if system_version=="Linux":
			log.success("Creating contact file")
			os.mknod("/tmp/hackebds_model_table")
		if system_version == "Darwin" or "Mac":
			log.success("Creating contact file")
			f=open("/tmp/hackebds_model_table",'w+')
			f.close()
		else:
			log.info("This function is not applicable to this system")
	except Exception as e:
		log.error("error "+e)

def dict_to_txt(dic1):
	try:
		with open('/tmp/hackebds_model_table', 'w') as dict_f:
			for k, v in dic1.items():
				dict_f.write(str(k) + ' ' + str(v) + '\n')
	except Exception as e:
		pass
		#log.success("error "+ e)

def txt_to_dict():
	global model_tree
	try:
		with open('/tmp/hackebds_model_table', 'r') as dict_f:
			for line in dict_f.readlines():
					line=line.strip()
					k,v=line.split(' ')
					model_tree[k]=str(v)
	except Exception as e:
		pass
		#log.error("error "+ e)


def append_to_tree(model, arch):
	global model_tree
	txt_to_dict()
	model_tree[model]=arch
	dict_to_txt(model_tree)

def model_to_arch(model):
	txt_to_dict()
	#print(model_tree)
	return model_tree[model]

def print_mmodel_dic():
	try:

		dict_2 = dict(sorted(model_tree.items(), key=lambda i:i[0]))

		log.success("model ----> arch:")

		for key,value in dict_2.items():
			print("-"*0x29)
			print("|"+Fore.GREEN+key.ljust(15)+Fore.RESET+"----->    "+Fore.GREEN+value.ljust(14)+Fore.RESET+"|")

		print("-"*0x29)

	except Exception as e:
		print(e)



#append_to_tree("DIR-816",'mips')
#print(model_to_arch("DIR-832"))