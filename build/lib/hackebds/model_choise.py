import os
from pwn import *
'''
Equipment model -> backdoor model
This is a learning module. After the generation, add the device model. The tool will remember it after the next use, accelerating the generation of the backdoor and shell code next time

1 arch 0 model 1
2 arch
'''

model_tree = {
	
}

def touchfile():
	#with open("/tmp/hackebds_model_table",'w') as f:
	#f.write()
	log.success("Creating contact file")
	os.mknod("/tmp/hackebds_model_table")

def dict_to_txt(dic1):
	with open('/tmp/hackebds_model_table', 'w') as dict_f:
		for k, v in dic1.items():
			dict_f.write(str(k) + ' ' + str(v) + '\n')

def txt_to_dict():
	global model_tree
	with open('/tmp/hackebds_model_table', 'r') as dict_f:
		for line in dict_f.readlines():
				line=line.strip()
				k,v=line.split(' ')
				model_tree[k]=str(v)


def append_to_tree(model, arch):
	global model_tree
	txt_to_dict()
	model_tree[model]=arch
	dict_to_txt(model_tree)

def model_to_arch(model):
	txt_to_dict()
	#print(model_tree)
	return model_tree[model]




#append_to_tree("DIR-816",'mips')
#print(model_to_arch("DIR-832"))