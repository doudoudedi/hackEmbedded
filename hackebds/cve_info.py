import requests
import re
from colorama import Fore,Back,Style
import os
import argparse
from pwn import *

local_file_flag = 0


def do_get_req(url):
	return requests.get(url, timeout=10).text


def check_dir(model):
	if(os.path.exists('/tmp/hackebds/')):
		pass
	else:
		os.mkdir("/tmp/hackebds")
	if(os.path.exists("/tmp/hackebds/"+model)):
		local_file_flag = 1
		pass
	else:
		os.mkdir("/tmp/hackebds/"+model)

def re_detail(data):
	compil=r'a target="_blank" href="(.*)">MISC:'
	compil1=r'<li><a target="_blank" href="(.*)">URL'
	res1 = re.findall(compil1,data)
	res = re.findall(compil,data)

	#print(requests.get(res[0]).text)
	return res + res1

def save_file(model,data):
	'''
	判断路径是否存在os.path.exit
	'''
	with open("/tmp/hackebds/%s/CVElist"%(model),'w') as f:
		#f.write("DIR-816: \n\n")
		for i in range(len(data)):
			f.write(data[i][1]+": "+data[i][2]+"\n\n")

def get_local_file(model):
	with open("/tmp/hackebds/%s/CVElist"%(model),'r') as f:
		data= f.read()
		if data == None:
			log.error("localfile is NuLL")
			return
	data = data.split("\n\n")
	for i in range(len(data)):
		try:
			data[i] = data[i].split(": ")
			print(Fore.RED+data[i][0]+": "+Fore.GREEN+data[i][1]+"\n"+Fore.RESET)
		except:
			pass



def get_detail(url):
	url = "https://cve.mitre.org"+url
	#print(url)
	res= re_detail(requests.get(url).text)
	return res

def parseCVE(model):

	#global information_2021
	try:
		result = do_get_req("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+model)
		compil=r'<td valign="top" nowrap="nowrap"><a href="(.*)">(.*)</a></td>\n.*>(.*)'
		compil1=r'<td valign="top">(.*)\n'
		aim=re.findall(compil,result)
		if len(aim)==0:
			print(Fore.RED+"nothing")
			exit()
		for i in range(len(aim)):
		#print(aim[i][0])
		#get_detail(aim[i][0])
			print(Fore.RED+aim[i][1]+": "+Fore.GREEN+aim[i][2]+"\n"+Fore.BLUE+"link: "+str(get_detail(aim[i][0])))
		save_file(model, aim)
	#get_detail(aim[0][0])
	except Exception as e:
		log.info("fail to connect cve.mitre.org, readinf localfile")
		get_local_file(model)


def main(model):
	#parser = argparse.ArgumentParser("This tool is convenient for CVE search of equipment")
	#parser.add_argument('-model', required=True, type=str,default=None, help='device model')
	#args = parser.parse_args()
	check_dir(model)
	parseCVE(model)
	#save_file(model, cveinfo_data)


if __name__  == "__main__":
	#parser = argparse.ArgumentParser()
	#parser.add_argument('-model', required=True, type=str,default=None, help='Learning module')
	main()




'''
res=requests.get("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=TL-WDR5620").text
#save_file(parseCVE(res))
print(parseCVE(res))
'''