import requests
import re
from colorama import Fore,Back,Style
import os
import argparse
from pwn import *
from . import database

local_file_flag = 0


def do_get_req(url):
	return requests.get(url, timeout=10).text


def check_dir(model):
	"""Check/create directory - now uses database, this is a no-op for compatibility."""
	# Database is already initialized by main(), no directory needed
	pass

def re_detail(data):
	compil=r'a target="_blank" href="(.*)">MISC:'
	compil1=r'<li><a target="_blank" href="(.*)">URL'
	res1 = re.findall(compil1,data)
	res = re.findall(compil,data)

	#print(requests.get(res[0]).text)
	return res + res1

def save_file(model, data):
	"""Save CVE search results to database cache."""
	cve_data = []
	for i in range(len(data)):
		# data[i] is a tuple: (url, cve_id, description)
		cve_id = data[i][1]
		url = data[i][2] if len(data[i]) > 2 else ''
		cve_data.append((cve_id, url))
	database.save_cve_cache(model, cve_data)


def get_local_file(model):
	"""Get CVE results from database cache."""
	cve_data = database.get_cve_cache(model)
	if not cve_data:
		log.error("No cached CVE data found")
		return
	for cve_id, url in cve_data:
		print(Fore.RED + cve_id + ": " + Fore.GREEN + url + "\n" + Fore.RESET)



def get_detail(url):
	url = "https://cve.mitre.org"+url
	#print(url)
	res= re_detail(requests.get(url).text)
	return res

def parseCVE(model):
	"""Parse CVE information from cve.mitre.org, with database caching."""
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
		log.info("fail to connect cve.mitre.org, reading from database cache")
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