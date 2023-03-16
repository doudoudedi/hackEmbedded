from ast import expr
import os
from statistics import mode
from pwn import log,shellcraft
import platform
from colorama import Fore,Back,Style
from multidict import CIMultiDict
from . import exp_database
from fuzzywuzzy import process
'''
Equipment model -> backdoor model
This is a learning module. After the generation, add the device model. The tool will remember it after the next use, accelerating the generation of the backdoor and shell code next time

1 arch 0 model 1
2 arch
'''
model_tree=CIMultiDict()
model_arch_tree = CIMultiDict()

model_tree_info_dicname = "/tmp/model_tree_info/"

'''
information for model
[arch, function ,os ,cpu_vender ,cpu , web_server, SSH_support,Eavesdropping, default_telnet_username, default_telnet_passwd ,sdk_link,support_for_openwrt, is_vulnerable]
'''


model_arch_tree["RV_340"] = "armelv7"



####TOTOLINK
#model_tree["TOTOLINK_A850R"] = ["mips", "linux" , "Realtek" ,"RTL8192ER", "https://github.com/doudoudedi","False", "Ture", poc]

'''
wifi_extender
'''

def data_base_init():

	model_tree["TOTOLINK_EX200"] = ['mips', "wifi_extender","linux" , "Realtek", "RTL8196E", "lighttpd", "False","False", 'root', 'cs2012',"https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TOTOLINK_EX200"] ]


	model_tree["Netgear_EX6100v1"] = ['mipsel', "wifi_extender", "linux", "MediaTek","MT7620A", "httpd(like:goahead)", "False", "False", "The latest version of the telnetd service is not started by default", "The latest version of the telnetd service is not started by default","https://github.com/houzhenggang/mt7620_sdk","False","True", exp_database.model_exp_dic["Netgear_EX6100v1"]]
	#model_tree["TOTOLINK_N600R"] = ["mips", "linux", "Realtek" ,"RTL8197D", "https://github.com/doudoudedi", "False", "True", poc]

	model_tree["Xiaomi_wifi_amplifier"] = ["mipsel", "wifi_extender", "ecos", "MediaTek", "MT7628KN", "ecos", "False", "False", "no", "no", "unknow", "False", "False", {}]

	model_tree["tenda_A18"] = ["mipsel", "wifi_extender", "linux", "Realtek", "RTL8197fnt", "False", "False", "root", "unknow","https://sourceforge.net/projects/rtl819x/", "False", "True", {}]#update 2023.3.1

	model_tree["KPN_Experia_Wifi(Arca_WE420223-99)"] = ['mipsel', "wifi_extender&&router", "linux","MediaTek", "MT7615DN", "unknow", "False", "False", "unknow", "unknow", "unknow", "True", "True",exp_database.model_exp_dic['Arca_WE420223-99']]

	model_tree["TP_TL-WPA8630"] = ["mips", "Powerline Access Point", "linux", "Qualcomm Atheros", "QCA9563",  "httpd(self)", "True", "False", "root", "sohoadmin", "unknow", "True", "True", exp_database.model_exp_dic["TP_WPA8630_v2"]]

	model_tree["TP_WPA8630_v2"] = ["mips", "Powerline Access Point", "linux", "Qualcomm Atheros", "QCA9563",  "httpd(self)", "True", "False", "root", "sohoadmin", "unknow", "True", "True", exp_database.model_exp_dic["TP_WPA8630_v2"]]
 
	model_tree["Netgear_WNDR3700v2"] = ['mips', "router", "linux", "Atheros", "AR7161", "uhttpd", "False", "False", "admin", "Default Password", "unknow", "True", "True", exp_database.model_exp_dic["Netgear_WNDR3700v2"]]
 
	model_tree["TL-WR802N(US)_V4"] = ['mipsel', "router", "linux", "Mediatek", "MT7628N", "httpd", "False", "False", "unknow", "unknow", "unknow", "True", "True", exp_database.model_exp_dic['TL-WR802N(US)_V4']]
	
	model_tree["Tenda_AX1806"] = ['armelv7', "router", "linux", "Broadcom", "BCM6755", "tdhttpd(like goahead)", "False", "False", "unknow", "unknow","unknow", "False", "True", exp_database.model_exp_dic["Tenda_AX1806"]]
 
	'''
	Router
	'''

	model_tree["TOTOLINK_X5000R"] = ['mipsel', "router", "linux","MediaTek", "MT7621AT", "lighttpd","False","False", 'root', 'cs2012',"unknow", "True", "True" , exp_database.model_exp_dic["TOTOLINK_X5000R"]]

	model_tree["TOTOLINK_A8000RU"] = ['aarch64(armv8)', "router","linux", "MediaTek", "MT7622","lighttpd","False","False", 'root', 'cs2012', "unknow", "True", "True", {}]

	model_tree["TOTOLINK_A7000R"] = ['mipsel', 'router' ,"linux", "MediaTek","MT7621AT",'lighttpd',"False","False", 'root', 'cs2012',"unknow" ,"True", 'True' ,exp_database.model_exp_dic["TOTOLINK_A7000R"]]

	model_tree["TOTOLINK_A850R"] = ["mips", "router" ,"linux" , "Realtek" ,"RTL8192ER", 'boa', "False","False", 'root', '',"https://sourceforge.net/projects/rtl819x/","False", "True", {}]

	model_tree["TOTOLINK_N600R"] = ["mips", "router" ,"linux", "Realtek" ,"RTL8196D", "lighttpd", "False","False", 'root', 'cs2012',"https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TOTOLINK_N600R"]]

	model_tree["TOTOLINK_A800R"] = ["mips", "router" ,"linux", "Realtek" ,"RTL8197DL", "lighttpd","False","False", 'root', 'cs2012', "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TOTOLINK_A800R"]]

	model_tree["TOTOLINK_T6"] = ['mipsel', "router", "linux", "Realtek", "RTL8197F", "lighttpd","False","False", 'root', 'cs2012',"https://sourceforge.net/projects/rtl819x/", "Not_supported_temporarily", "True", {}]

	model_tree["TOTOLINK_X18"] = ['mipsel', "router", "linux", "MediaTek", "MT7621+MT7905", "lighttpd", "False","False", 'root', 'cs2012',"unkonw", "Not_supported_temporarily", "True", {}]

	model_tree["TOTOLINK_A7100RU"] = ['mipsel', "router", "linux", "MediaTek","MT7621A+MT7615Ex2", "lighttpd","False","False", 'root', 'cs2012',"unkonw", "True", "True", {}]

	model_tree["Cisco_RV340"] = ["armelv7", "router", "linux", "Cisco", "unknow", "nginx", "True" ,"False", "unknow", "unknow", "unknodw","False", "True", exp_database.model_exp_dic["Cisco_RV340"]]

	model_tree["Cisco_RV16x"] = ["armelv7", "router", "linux", "Cisco", "unknow", "mini_httpd", "True", "False", "unkow", "unknow", "unknow", "False", "True", exp_database.model_exp_dic["Cisco_RV16x"]]

	model_tree["wavlink_WL-WN535K3"] = ["mipsel", "router", "linux", "Mediatek", "MT7620A", "lighttpd", "False", "False", "unknow", "unknow", "https://github.com/houzhenggang/mt7620_sdk", "True", "True", exp_database.model_exp_dic["wavlink_WL-WN535K3"]]

	model_tree["TOTOLINK_A810R"] = ["mipsel", "router", "linux", "Realtek", "RTL8197F", "lighttpd", "False", "False", "root", "cs2012", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TOTOLINK_A810R"]]

	model_tree["BR-6428nS_v3"] = ["mipsel", "router", "linux", "Realtek", "RTL8196E", "axhttpd", "False", "False", "NULL", "NULL","https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["BR-6428nS_v3"]]

	model_tree["DIR-816"] = ["mipsel", "router", "linux", "Realtek", "RTL8881AQ", "goahead", "False", "False", "admin", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["DIR-816"]]

	model_tree["DIR_810L"] = ["mipsel", "router", "linux", "MediaTek", "MT7620A", "mini_httpd", "False", "False", "admin", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["DIR-810L"]]

	model_tree["DIR-820L"] = ["mips", "router", "linux", "Realtek", "RTL8197D", "jjhttpd", "False", "False","root", "root", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["DIR-810L"]]

	model_tree["DIR-820LW"] =["mips", "router", "linux", "Realtek", "RTL8197D", "jjhttpd", "False", "False","root", "root", "https://sourceforge.net/projects/rtl819x/", "False", "True",exp_database.model_exp_dic["DIR-810L"]]

	model_tree["DIR-605"] = ["mipsel", "router", "linux2.4.18", "Realtek" ,"RTL8196C" ,"boa", "False", "False", "admin", "NULL", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["DIR-605"]]

	model_tree["DIR-860L"] = ["A1: Armelv7 && B1: mipsel,", "router", "linux", "A1:Broadcom && B1:Mediatek", "A1:BCM47081A0 && B1:MT7621AT", "httpd(D-link_self)","False", "False", "root", "NULL","unknow", "B1version True","True", exp_database.model_exp_dic["DIR-860L"]]

	model_tree["TEW-651BR"] = ["mips", "router", "linux", "Realtek","RTL8196B", "mini_httpd", "False", "False", "root", "NULL", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TEW-651BR"]]

	model_tree["DIR-818LW"] = ["mips", "router", "linux", "MediaTek", "MT6592", "httpd(D-link_self)", "False", "False", "root", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["DIR-818LW"]]

	model_tree["DIR-822"] = ["mips", "router", "linux", "Realtek", "RTL8197FN", "httpd(D-link_self)", "False", "False", "root", "NULL",  "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["DIR-822"]]

	model_tree["DIR-846"] = ["mipsel", "router", "linux", "Realtek", "RTL8197F", "lighttpd", "False", "False", "admin/root", "unknow", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["DIR-846"]]

	model_tree["RT-N53"] = ["mipsel", "router", "linux", "Broadcom", "BCM5358", "httpd(link goahead)", "False", "False" ,"root", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["RT-N53"]]

	model_tree["tenda_MW6"] = ["mipsel", "router", "linux", "Realtek","RTL8197F", "app(unknow)", "False", "False", "root", "unknow", "https://sourceforge.net/projects/rtl819x/", "False", "False", {}]

	model_tree["Netgear_R6200v1"] = ["mipsel", "router", "linux", "Broadcom", "BCM4718", "httpd(like goahead)", "False", "False", "NULL", "NULL", "unknow", "True", "True", {}]

	model_tree["Netgear_EX6300v2"] = ["armelv7", "router", "linux", "Broadcom", "BCM4708A0(Cortex-A9)", "httpd(like goahead)", "False", "False", "NULL", "NULL", "unknow", "True", "True", {}]

	#model_tree["Netgear_R8000P"] = []

	model_tree["H3C_magic_R100"] = ["mips", "router", "linux", "RealTek", "RTL8196E", "boa", "False", "False", "root", "root", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["H3C_magic_R100"]]

	#model_tree["H3C_TX1801_Plus"] = ["", "", "", "MediaTek", "MT7621AT"]

	model_tree["DSL-AC3100"] = ["armelv7","router", "linux", "Broadcom", "BCM63138", "httpd", "False", "False", "root", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["DSL-AC3100"]]

	model_tree["Buffalo_WSR-2533DHP2"] = ["aarch64(armv8)" ,"router", "linux", "MediaTek", "MT7622B", "unknow", "False", "False", "unknow", "unknow", "unknow", "True", "True",exp_database.model_exp_dic["DSL-AC3100"]]


	model_tree["Tenda_AC6v2"] = ["mipsel", "router", "linux", "Realtek", "RTL8197FN", "httpd(linke goahead)", "False", "False", "root", "unknow", "https://sourceforge.net/projects/rtl819x/","False", "True", exp_database.model_exp_dic["Tenda_AC6v2"]]

	model_tree["Tenda_AC6v5"] = ["mips", "router", "RTOS", "Realtek", "RTL8197FH", "no", "False", "False", "not support", "not support", "https://sourceforge.net/projects/rtl819x/","False", "unknow", {}]

	#model_tree["xiaomi_wifi_R3"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "sysapihttpd(niginx)", "True", "False", "root", "unknow", "unknow","True", "True", exp_database.model_exp_dic["mi_wifi_R3"]]

	model_tree["Netgear_R6300v1"] = ["mipsel", "router", "linux", "Broadcom", "BCM4706(MIPS 74Kc)", "httpd(like goahead)", "False", "False", "NULL", "NULL", "unknow", "True", "True", {}]

	model_tree["Netgear_R8300"] = ["armelv7", "router", "linux", "Broadcom","BCM47094(Cortex-A9)", "httpd(like goahead)", "False", "False", "NULL", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["Netgear_R8300"]]

	model_tree["Tenda_FH330"] = ["arm?", "router", "ecos", "Broadcom", "BCM5357C0", "no", "False", "False", "not support", "not support", "unknow", "False", "unknow", {}]

	model_tree["TL-WR841Nv12_us"] = ["mips", "router", "linux", "Atheros", "QCA9533 @ 560 MHz,", "httpd", "False", "False", "root", "shoadmin", "unknow", "True", "True", exp_database.model_exp_dic["TL-WR841Nv12_us"]]

	model_tree["TL-WDR5620v1"] = ["mipsel", "router", "linux", "MediaTek", "MT7628A", "uhttpd", "False", "False", "root", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["TL-WDR5620v1"]]

	model_tree["TOTOLINK_A950RG"] = ["mipsel", "router", "linux", "MediaTek", "MT7621A", "lighttpd", "False", "False", "root", "cs2012", "unknow", "False", "True", exp_database.model_exp_dic["TOTOLINK_A950RG"]]

	model_tree["TOTOLINK_T10"] = ["mipsel", "router", "linux", "Realtek", "RTL8197F", "lighttpd","False", "False", "root", "cs2012", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TOTOLINK_T10"]]

	#model_tree["TL-WA830RE"] = [""]

	model_tree["TOTOLINK_A860R"] = ["mipsel", "router", "linux", "Realtek", "RTL8195AM","lighttpd","False", "False", "root", "cs2012", "https://sourceforge.net/projects/rtl819x/", "False", "True", exp_database.model_exp_dic["TOTOLINK_A860R"]]

	model_tree["Linsys_RE6500"] = ["mipsel", "router", "linux", "MediaTek","MT7621AT" , "lighttpd", "False", "False", "root", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["Linsys_RE6500"]]

	model_tree["TP_Archer_AX50"] = ["mips", "router", "linux", "intel", "AnyWAN_GRX350", "uhttpd", "True", "False", "root", "NULL", "unknow","False", "True", exp_database.model_exp_dic["TP_Archer_AX50"]]

	model_tree["RT-AC68U"] = ["armelv7" ,"router", "linux", "Broadcom", "BCM4708A0(Cortex-A9)", "lighttpd", "True", "False", "root", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["RT-AC68U"]]

	model_tree["Netgear_R7000"] = ["armelv7", "router", "linux","Broadcom", "BCM4709A0(Cortex-A9)", "httpd", "True", "False", "root", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic["R7000"]]

	#model_tree["R6250"] = ["armelv7", "router", "linux", "Broadcom", "BCM4708A0", ""]

	model_tree["TL-MR6400"] = ["mips", "router", "linux", "Qualcomm", "Atheros QCA9531", "httpd(like goahead)","False","False", "root", "unknow", "unknow", "Ture","True", {}]

	model_tree["Netgear_R6900v2"] = ["mipsel", "router","linux","MediaTek", "MT7621AT", "new: mini_httpd, old:lighttpd", "False", "False", "root", "Default passwd", "unknow", "True", "True",{}]

	model_tree["Netgear_R6220"] = [ "mipsel", "router", "linux","MediaTek","MT7621ST", "new: mini_httpd, old:lighttpd", "True", "False", "admin", "Default passwd", "unknow", "True", "True", {}]

	model_tree["DIR-885L"] = ["armelv7", "router","linux", "Broadcom","BCM4709C0", "httpd", "False", "False", "root", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["DIR-885L"]]

	model_tree["huawei_HG532"] = ["mips", "router", "linux", "Ralink", "RT3052", "unknow", "False", "False", "root", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["huawei_HG532"]]

	model_tree["Cisco_RV110W"] = ["mipsel", "vpn firewall router", "linux", "Broadcom", "BRCM5357", "httpd", "False", "False", "admin", "Admin123", "unknow", "False",{}]

	model_tree["Cisco_RV130"] = ["armelv7", "vpn firewall router", "linux", "Broadcom", "BCM58522(Cortex A9)", "httpd", "False", "False", "admin", "Admin123", "unknow", "False", "True",exp_database.model_exp_dic["Cisco_RV130"]]

	model_tree["Cisco_RV130W"] = ["armelv7", "vpn firewall router", "linux", "Broadcom", "BCM58522(Cortex A9)", "httpd", "False", "False", "admin", "Admin123", "unknow", "False", "True",exp_database.model_exp_dic["Cisco_RV130"]]

	model_tree["ASUS_RT-AC56U"] = ["armelv7", "router", "linux", "Broadcom", "BCM4352", "lighttpd", "True", "False", "root", "NULL", "unknow", "True", "False", {}]

	model_tree["Asus_DSL-AC87VG"] = ["armelv7", "router", "linux", "Broadcom", "BCM63138(Cortex-A9)", "httpd(self)", "False", "False", "root", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["Buffalo_WSR-2533DHPL"]]

	model_tree["InRouter615-S"] = ["mipsel", "Industrial_routier", "linux", "unknow", "unknow", "httpd(self)","False", "False", "root","NULL", "unknow", "False", "True", exp_database.model_exp_dic["InRouter615-S"]]

	model_tree["Netgear_R6900"] = ["armelv7", "router", "linux", "Broadcom", "BCM4709A0(Cortex-A9)", "httpd", "False", "False", "admin","Default passwd", "unknow", "unknow", "True", {}]
	# model_tree["Netgear_R6950"] = ["mipsel", "router", "linux", ""]

	model_tree["DrayTek_Vigor2960"] = ["armelv5", "router", "linux", "intel(not sure)", "unknow", "lighttpd", "False", "False", "root", "NULL", "unknow", "False", "True", exp_database.model_exp_dic["DrayTek_Vigor2960"]]

	model_tree["DIR-878"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "lighttpd", "False", "False", "root", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["DIR-878"]]

	model_tree["TPLINK_Archer_A7_V5"] = ["mips","router", "linux-3.38", "Snapdragon","QCA9563", "uhttpd", "True", "False", "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic["TPLINK_Archer_A7_V5"]]

	model_tree["Netgear_R6330"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "mini_httpd", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_R6330"]]

	model_tree["Netgear_R6350"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "mini_httpd", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_R6330"]]
 
	model_tree["Netgear_R6700v2"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "mini_httpd", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_R6330"]]# Fix errors in 2023.3.2
 
	model_tree["Netgear_R6700"] = ["armelv7", "router", "linux", "Broadcom", "BCM4709A0", "http(self)", "False", "False", "admin", "Default passwd", "unknow", "unknow", "True", {}]

	model_tree["Netgear_R6800"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "mini_httpd", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_R6330"]]

	model_tree["Netgear_R7200"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "mini_httpd", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_R6330"]]

	model_tree["DIR-882"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT", "lighttpd", "False", "False", "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic["DIR-882"]]

	model_tree["DIR-825vB"] = ["mips", "router", "linux", "Qualcomm Atheros", "AR7161 rev 2", "httpd(self)", "False","False","unknow","unknow","unknow", "True", "True", exp_database.model_exp_dic["DIR-825vB"]]

	model_tree["DIR-619L"] =["mips", "router", "linux", "Realtek", "RTL8192CE", "boa", "False", "False", "root", "realtek", "unknow", "False", "True", exp_database.model_exp_dic["DIR-619L"]]
	
	model_tree["Netgear_WAC104"] = ["mipsel", "router" , "linux" ,"MediaTek", "MT7621ST", "mini_httpd", "False", "False", "root", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic["Netgear_WAC104"]]
 
	model_tree["ASUS_RT-AX56U"] = ["armelv7", "router", "linux", "Broadcom","BCM6755(Cortex-A9)","httpd(self)", "True", "False", "unknow", "unknow", "unknow", "False", "True", exp_database.model_exp_dic["ASUS_RT-AX56U"]]

	model_tree["GT-AC2900"] = ["aarch64(armv8)" ,"router","linux" ,"Broadcom", "BCM4906(Cortex-A53)", "httpd(self)", "True", "False", "unknow", "unknow", "unknow", "False", "True", exp_database.model_exp_dic["GT-AC2900"]]

	model_tree["Netgear_WNR1000v3"] = ["mipsel", "router", "linux", "Broadcom", "BCM5356", "httpd(self)", "False", "False",  "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic['Netgear_WNR1000v3']]
	
	model_tree["ASUS_RT_AC88U"] = ["armelv7", "router", "linux", "Broadcom","BCM4709C0KFEBG(Cortex-A9)", "httpd(self)","True", "False", "unknow", "unknow", "unknow", "True", "True", exp_database.model_exp_dic["ASUS_RT_AC88U"]]

	model_tree["Netgear_WNDR4500v2"] = ['mipsel', "router", "linux", "Broadcom", "BCM4706", "httpd(self)", "False", "False",  "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic['Netgear_WNDR4500v2']]

	model_tree["Xiaomi_AX3600"] = ["aarch64", "router", "linux","Qualcomm", "IPQ8071A", "Nginx", "True", "False", "root", "unknow", "unknow", "True", "True", exp_database.model_exp_dic["Xiaomi_AX3600"]]

	model_tree["Netgear_WNR3500L"] = ["mipsel", "router", "linux","Broadcom", "BCM4718A", "httpd(self)", "False", "False",  "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic['Netgear_WNDR4500v2']]

	model_tree["DIR-859"] = ["mips", "router", "linux", "Qualcomm", "Qualcomm_Atheros_QCA9563", "httpd(self)", "False", "False", "NULL", "NULL", "unknow", "True", "True", exp_database.model_exp_dic["DIR-859"]]
 
	model_tree["TPLINK-TL-WR840N_V5"] = ["mipsel", "router", "linux", "MediaTek","MT7628NN", "httpd(self)","False", "False" ,"admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["TPLINK-TL-WR840N_V5"]]
 
 	#model_tree[""]
	model_tree["Cisco_R0XX"]  = ["mips64", "vpnrouter", "linux", "unknow", "unknow", "unknow", "unknow", "unknow", "unknow", "unknow", "unknow", "False", "True", exp_database.model_exp_dic["Cisco_R0XX"]]
 
	model_tree["Netcomm_NF20"] = ["armelv7", "router && Modem", "linux", "Broadcom", "BCM6328 and wifi BCM43225KMLG", "unknow","False", "False", "unknow", "unknow", "unknow", "True", "True", exp_database.model_exp_dic["Netcomm_NF20"]]
  
	model_tree["Netgear_WNDR3700v4"] = ['mips', "router &&Modem", "linux", "Atheros", "AR9344", "uhtttpd", "False", "False",  "admin", "Default passwd", "unknow", "True", "True", {}] #exp_database.model_exp_dic["Netgear_WNDR3700v4"]]
  
	model_tree["Netgear_RAX30"] = ["armelv7 && aarch64", "router", "linux4.19.0", "Broadcom", "BCM4908(Cortex-A53和Cortex-A57)", "lighttpd", "False", "False","admin", "Default passwd", "unknow", "True", "True", {}]

	model_tree["Netgear_RAX120"] = ["aarch64", "router", "linux", "Qualcomm", "IPQ8074(cortex-a53)", "lighttpd", "False", "False","admin", "Default passwd", "unknow", "True", "True", {}]

	model_tree["DIR-867_A1"] = ["mipsel", "router", "linux", "MediaTek", "MT7621AT","lighttpd", "False", "False", "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic["DIR-867"]]
  
	'''
	AP wifi
 	'''
	model_tree["H3C_A210-G"] = ["unknow", "AP_wifi", "linux", "Realtek(??)","unknow", "like goahead","False", "False", "unknow", "unknow", "unknow", "False", "True", exp_database.model_exp_dic["H3C_A210-G"]]
  
  
	'''
	Modem
	'''
	model_tree["fenghuo_MR820"] = ["mips(router)&&arm(android)", "Modem", "linux&&android", "MediaTek && ??","RTL-8676S&&??", "boa", "False", "False", "unknow", "unknow", "unknow", "False", "True", {}]

	model_tree["Netgear_DGN1000v1"] = ['mips', "Modem", "linux", "Infineon/Lantiq","Lantiq PSB 50601 HL v1.2", "mini_httpd", "False", "False", "NULL", "NULL", "unknow", "False", "True", {}]

	model_tree["Buffalo_WSR-2533DHPL"] = ["mipsel", "Modem&&router", "linux", "MediaTek", "MT7621A", "httpd", "False", "False" ,"unknow", "unknow", "unknow", "True", "True",exp_database.model_exp_dic["Buffalo_WSR-2533DHPL"]]

	model_tree["Buffalo_WSR-3200AX4S"] = ["aarch64(armv8)", "Modem&&router", "linux", "MediaTek", "MT7622", "httpd", "False", "False", "root", "unknow", "unknow","True", "True",exp_database.model_exp_dic["Buffalo_WSR-2533DHPL"]]
 
	model_tree["Netgear_D7000v1"] = [ "armelv7" ,"Modem&&router" ,"linux", "Broadcom", "BCM63138(Cortex A9)", "mini_httpd", "False", "False", "root", "unknow", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_D7000v1"]]

	model_tree["Netgear_MBR1515"] = ["mipsel", "Modem&&router", "linux", "Broadcom", "BCM4717A1", "httpd(self)", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic['Netgear_MBR1515']]
 
	model_tree["Netgear_MBR1516"] = ["mipsel", "Modem&&router", "linux", "Broadcom", "BCM4717A1", "httpd(self)", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic['Netgear_MBR1516']]
 
	model_tree["Netgear_DGN2200M"] = ["mips", "Modem&&router", "linux", "Broadcom","BCM6358", "httpd(self)", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic['Netgear_DGN2200M']]
 
	model_tree["Netgear_WNDR3400"] = ["mipsel", "Modem&&router", "linux", "Broadcom", "BCM4718A1", "httpd(self)", "False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_WNDR3400"]]
 
	model_tree["Netgear_WNR3500"] = ["armelv5", "Modem&&router", "linux", "Marvell", "Marvell_88F5180NB1","httpd(self)" ,"False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_WNR3500"]]

	model_tree["Netgear_WNR834Bv2"] = ["mipsel" , "Modem&&router", "linux-2.4.20", "Broadcom", "BCM4704", "httpd(self)","False", "False", "admin", "Default passwd", "unknow","False", "True", exp_database.model_exp_dic["Netgear_WNR834Bv2"]]

	model_tree["Netgear_WNDR3300"] = ["mipsel", "Modem&&router", "linux", "Broadcom", "BCM4704", "httpd(self)","False", "False", "admin", "Default passwd", "unknow", "False", "True", exp_database.model_exp_dic["Netgear_WNDR3300"]]

	model_tree["Netgear_WNDR3400v2"] = ["mipsel",  "Modem&&router", "linux", "Broadcom", "BCM5358UB0", "http(self)", "False", "False", "admin", "Default passwd", "unknow", "True", "True", exp_database.model_exp_dic["Netgear_WNDR3400v2"]]


	'''
	Firewall
	'''
	model_tree["F5_BIG-IP"] = ["x64", "Firewall","linux", "intel", "X3220  @ 2.40GHzstepping 4core","Apache and Tomcat" ,"True", "True", "not support", "not support", "no have", "False", "True" , exp_database.model_exp_dic["F5_BIG-IP"]]

	model_tree["Zyxel_USG_FLEX_500"] = ["mips32n", "Firewall", "linux", "unknow", "unknow(Cortex A9)", "Apache", "True", "False", "no", "no", "unknow", "False", "True", exp_database.model_exp_dic["Zyxel_USG_FLEX_500"]]


	'''
	camera
	'''
	model_tree["dh_ipc-kw12_chn"] = ['armelv5', "IP camera", "linux", "HuaWei", "hi3518", "sonia", "False",'True','admin' ,'7ujMko0admin' ,"unkonw", "unkonw", "False", {}]

	model_tree["DCS-5010L"] = ['mipsel', "IP camera and wireless repeater", "linux", "unknow(Ralink)", "unknow", "alphapd", "False", "True", "root", "NULL", "unknow", "False", "True", {}]

	model_tree["DCS-5020L"] = ['mipsel', "IP camera and wireless repeater", "linux", "Mediatek" ,"RT3352F", "alphapd","False", "True", "root", "NULL",  "unknow", "False but have Beta", "True", {}]

	model_tree["Hikvision_DS-2CD2xx0F-ISeries"] = ["armelv5", "IP camera and wireless repeater", "linux", "HUAWEI", "hixxx", "unknow", "True", "unknow", "unknow", "unknow", "unknow" ,"False", "True", exp_database.model_exp_dic["DS-2CD2xx0F-ISeries"]]



	model_tree["DCS-93xL"] = ["mipsel", "IP camera", "linux","Ralink","RT3050F && RT5350F", "alphapd","False", "True","admin", "NULL", "unknow" ,"True", "True", exp_database.model_exp_dic["DCS-93xL"]]

	model_tree["DCS-2530L"] = ["unknow", "IP camera", "unknow", "unknow","unknow","unknow","False","True", "unknow", "unknow", "unknow" ,"False", "True", exp_database.model_exp_dic["DCS-2530L"]]

	model_tree["DCS-1130"] = ["armelv5", "IP camera", "linux", "unknow", "unknow", "False", "True", "lighttpd", "root", "NULL", "unknow", "False", "True", {}]
 
	'''
	DVR
 	'''
	model_tree["TBK_DVR"] = ["armelv7", "DVR", "linux", "unknow", "unknow", "False", "True", "unknow", "Not", "Not", "unknow", "False", "True", exp_database.model_exp_dic["TBK_serise_DVR"]]
 

	'''
	switch
 	'''
	#model_tree["Netgear_GS110TPv3"] = ['armelv7', "switch", ""]
 
	'''
	information for model
	[arch, function ,os ,cpu_vender ,cpu , web_server, SSH_support,Eavesdropping, default_telnet_username, default_telnet_passwd ,sdk_link,support_for_openwrt, is_vulnerable]
	'''





def get_system_version():
	return platform.system()



def touchfile():
	try:
	#with open("/tmp/hackebds_model_table",'w') as f:
	#f.write()
		system_version = get_system_version()
		if system_version=="Linux":
			log.success("Creating contact file")
			os.mknod("/tmp/hackebds_model_table")
		elif system_version == "Darwin" or  system_version =="Mac":
			log.success("Creating contact file")
			f=open("/tmp/hackebds_model_table",'w+')
			f.close()
		elif system_version == "Windows":
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

def make_dic():
	try:
	#with open("/tmp/hackebds_model_table",'w') as f:
	#f.write()
		system_version = get_system_version()
		if system_version=="Linux":
			log.success("Creating contact file")
			os.makedirs(model_tree_info_dicname)
		elif system_version == "Darwin" or  system_version =="Mac":
			log.success("Creating contact file")
			os.makedirs(model_tree_info_dicname)
		elif system_version == "Windows":
			log.info("This function is not applicable to this system")
	except Exception as e:
		log.error("error "+str(e))


def txt_to_dict():
	global model_arch_tree
	try:
		with open('/tmp/hackebds_model_table', 'r') as dict_f:
			for line in dict_f.readlines():
					line=line.strip()
					k,v=line.split(' ')
					model_arch_tree[k]=str(v)
	except Exception as e:
		pass
		#log.error("error "+ e)


def append_to_tree(model, arch):
	global model_arch_tree
	txt_to_dict()
	model_arch_tree[model]=arch
	dict_to_txt(model_arch_tree)

def model_to_arch(model):
	txt_to_dict()
	#print(model_tree)
	return model_arch_tree[model]

def print_mmodel_dic():
	try:
		dict_2 = dict(sorted(model_arch_tree.items(), key=lambda i:i[0]))
		#print(dict_2)
		log.success("model ----> arch:")

		for key,value in dict_2.items():
			print("-"*0x29)
			print("|"+Fore.GREEN+key.ljust(15)+Fore.RESET+"----->    "+Fore.GREEN+value.ljust(14)+Fore.RESET+"|")

		print("-"*0x29)

	except Exception as e:
		print(e)

def model_tree_dic():
	if(os.path.exists(model_tree_info_dicname)):
		#print(model_tree.items())
		for k,v in model_tree.items():

			#print(k)

			model_info_dic = model_tree_info_dicname + k

			model_info_file = model_info_dic + "/info"

			model_poc_dic = model_info_dic + "/POC/"
   
			model_poc_info_dic = model_info_dic + "/CVE_INFO/"

			if (os.path.exists(model_info_dic) == False):
				os.makedirs(model_info_dic)
			if (os.path.exists(model_poc_dic) == False):
				os.makedirs(model_poc_dic)
    
			if (os.path.exists(model_poc_info_dic) == False):
				os.makedirs(model_poc_info_dic)

			if (os.path.exists(model_info_file) == False):
				f=open(model_info_file,'w+')
				f.close()


			info_len = len(v)
   
			print(k)

			with open(model_info_file, "w+") as f:


				model_info = "Arch :{}\n".format(v[0])


				model_info += "{} :{}\n".format(k, v[1])

				model_info += "OS :{}\n".format(v[2])

				model_info += "CPU vender :{}\n".format(v[3])

				model_info += "CPU model :{}\n".format(v[4])

				model_info += "Web Server :{}\n".format(v[5])

				model_info += "SSH server support(Default) :{}\n".format(v[6])

				model_info += "Is it possible to eavesdrop :{}\n".format(v[7])

				model_info += "Default telnet user :{}\n".format(v[8])

				model_info += "Default telnet passwd :{}\n".format(v[9])

				model_info += "Sdk exist :{}\n".format(v[10])

				model_info += "Openwrt support :{}\n".format(v[11])

				model_info += "Vulnable :{}".format(v[12])



				#for i in range(len(v)-1):

				#	model_info += ' '+v[i]

				#model_info += "\n"

				f.write(model_info)

			if (v[info_len-2] == "True" and v[info_len-1]!= {} ):

				for k1,v1 in v[info_len-1].items():


					with open(model_poc_dic+k1 , "w") as f:

						f.write(v1[1])
      
      
					with open(model_poc_info_dic+k1 , "w") as f1:
         
						f1.write(v1[0])
         
			else:
				pass
				#log.info("{} the POC of this device has not been included yet, or the availability of this device is not large".format(k) )

	else:
		make_dic()


def check_poc_info(path, model, vul):
	if(os.path.exists(path) == True):
		return 1
	else:
		try:
			return model_tree[model][13][vul][0]
		except:
			return ''



def dic_model_tree():
	global model_tree
	if(os.path.exists(model_tree_info_dicname)):
		dir_list = os.listdir( model_tree_info_dicname )
		for i in dir_list:
			model_info = []
			poc_dic = {}
			if (os.path.exists(model_tree_info_dicname + i +"/info") == True):
				with open( model_tree_info_dicname+i+"/info" , "r") as f:
					for line in f.readlines():
						line=line.strip()
						model_info.append(line.split(':',1)[1])
			else:
				for k in range(10):
					model_info.append('')
			if(os.path.exists(model_tree_info_dicname + i + "/CVE_INFO/") == False):
				os.makedirs(model_tree_info_dicname + i + "/CVE_INFO/")
    
			if (os.path.exists(model_tree_info_dicname + i + "/POC")):
				poc_dir_file_list = os.listdir(model_tree_info_dicname + i + "/POC" )
				#cve_info_dir_file_list = os.listdir(model_tree_info_dicname + i + "/POC/CVE_INFO")

				for j in poc_dir_file_list :
        
					if(os.path.isdir(model_tree_info_dicname + i + "/POC/"+ j)==False):
					
						with open(model_tree_info_dicname + i + "/POC/"+ j , "r") as f1:

							poc_data = f1.read()

						c_p_i = check_poc_info(model_tree_info_dicname + i + "/CVE_INFO/"+ j, i, j)
						if(c_p_i == 1 ):
							
							with open(model_tree_info_dicname + i + "/CVE_INFO/"+ j , "r") as f2:
								
								info_data = f2.read()
						else:
							info_data = c_p_i

						poc_dic [j] = [info_data, poc_data]
			else:
				model_info.append({})

			model_info.append(poc_dic)
			model_tree[i] = model_info

	else:
		log.info("not database")

	return


def list_model_tree():

	for key,value in model_tree.items():
		print("-"*0x42)
		#print_data = "Arch is {}\n".format(value[0])

		#print_data += "{} is {}\n".format(key, value[1])

		#print_data += "OS is {}\n".format(value[2])

		#print_data += "CPU vender is {}".format(value[3])

		#print_data += "CPU model is {}".format(value[4])

		#print_data


		print(Fore.GREEN+(key+":").ljust(0x40) +Fore.RESET)


		log.success("Arch is {}".format(value[0]))

		log.success("{} is {}".format(key ,value[1]))

		log.success("OS is {}".format(value[2]))

		log.success("CPU vender is {}".format(value[3]))

		log.success("CPU model is {}".format(value[4]))

		log.success("Web Server is {}".format(value[5]))

		log.success("SSH server support(Default) {}".format(value[6]))

		log.success("Is it possible to eavesdrop: {}".format(value[7]))

		log.success("Default telnet user {}".format(value[8]))

		log.success("Default telnet passwd {}".format(value[9]))

		log.success("Sdk exist {}".format(value[10]))

		log.success("Openwrt support {}".format(value[11]))
  
		if (value[12] == "True"):
			
			log.success("Vulnable {}".format(value[12]))

		else:
			log.info("Vulnable {}".format(value[12]))

	print("-" * 0x42)
	log.success("The total number of storage devices in the data is {}".format(str(len(model_tree.keys()))))

	log.success("The number of POCs corresponding to the model is {}".format(str(len(exp_database.model_exp_dic.keys()))))


'''
information for model
[arch, function ,os ,cpu_vender ,cpu , web_server, SSH_support,Eavesdropping, default_telnet_username, default_telnet_passwd ,sdk_link,support_for_openwrt, is_vulnerable]
'''
def print_model_information(model):
	try:
		log.success("Model is {}".format(model))

		log.success("Arch is {}".format(model_tree[model][0]))

		log.success("{} is {}".format(model, model_tree[model][1]))

		log.success("OS is {}".format(model_tree[model][2]))

		log.success("CPU vender is {}".format(model_tree[model][3]))

		log.success("CPU model is {}".format(model_tree[model][4]))

		log.success("Web Server is {}".format(model_tree[model][5]))

		log.success("SSH server support(Default) {}".format(model_tree[model][6]))

		log.success("Is it possible to eavesdrop: {}".format(model_tree[model][7]))

		log.success("Default telnet user {}".format(model_tree[model][8]))

		log.success("Default telnet passwd {}".format(model_tree[model][9]))

		log.success("Sdk exist {}".format(model_tree[model][10]))

		log.success("Openwrt support {}".format(model_tree[model][11]))



		if(model_tree[model][12] == "True"):
			log.success("Vulnable {}".format(model_tree[model][12]))
			log.success("Vulnerability information is as follows:")
			print("-"*0x40)
			if (model_tree[model][13] != {}):
				#print(model_tree[model][13].items())
				for k,v in model_tree[model][13].items():
					print(Fore.GREEN + k + Fore.RESET+ "  :  " +  v[0])
					print("-"*0x40)
					#print(k+": "+v[0])
			else:
				print("Maybe this POC is not included in the script")

		else:
			log.info("Vulnable {}".format(model_tree[model][12]))
		'''
		if (model_tree[model][12] == "True" and model_tree[model][13]!= {} and model_tree[model][13]!= None):
			print(Fore.GREEN+"[+]"+"Do you need to generate a POC file(y/n)"+Fore.RESET,end='')

			choise = input()

			if choise == "y\n" or choise == "\n":

				for info in model_tree[model][7]:
					for key,value in info.items():
						for data in value:
							log.success("Firmw_verion {} ----> {}_poc.py".format(key, model+"_"+key))
							with open(model+"_"+key+"_poc.py", "w") as f:
								f.write(value)
		else:
			log.info("The POC of this device has not been included yet, or the availability of this device is not large")
		'''
	except Exception as e:
		log.info("Maybe this device is not included in the script")
		print(e)



def search_model(model):

	log.success("Basic information of search {}".format(model))

	model_tree_ky_list = list(model_tree.keys())

	top = process.extract(model, model_tree_ky_list, limit=5)

	log.success("This may be the equipment you are looking for")
	for k in top:
		if k[1]>20:
			print("-"*0x35)
			print("|"+Fore.GREEN+k[0].ljust(0x20)+Fore.RESET+"Similarity:".ljust(0x10, ' ')+str(k[1])+"%"+"|")

	print("-"*0x35+"\n")

	if (top[0][1]!=0):
		print_model_information(top[0][0]) # print most

	return top[0][0]


def get_poc(model):
	if(model_tree[model][13] == {}):
		log.info("POC is not included temporarily")
		return 
	for key,value in model_tree[model][13].items():
		log.success("POC generation information:")
		log.success("{} ----> {}".format(model, key))
		if(os.path.exists(key) !=True):
			with open(key, "w") as f:
				f.write(value[1])
		else:
			print(Fore.RED+"[+]"+" be careful File existence may overwrite the file (y/n) "+Fore.RESET,end='')
			choise = input()
			if choise == "y\n" or choise == "\n":
				with open(key, "w") as f:
					f.write(value[1])
			else:
				return

def add_model_info():
	log.info("The next step is to add/edit device information")
	log.info("The Model is ? ")

	model_info_list = []

	model_add = input().strip()
	if (model_tree.__contains__(model_add)):
		print(
			Fore.RED + "[+]" + "The existing information of the current device will be modified in the next operation,Do you want to continue?(y/n)" + Fore.RESET,
			end='')
		choise = input()
		if choise == "n\n":
			return

	log.info("Arch is ?")

	model_arch = input()

	model_info_list.append(model_arch)

	log.info("What kind of model is it(like router/switch/camera....)")

	model_kind = input()

	model_info_list.append(model_kind)

	log.info("OS is ?")

	model_os = input()

	model_info_list.append(model_os)

	log.info("CPU vender is ?")

	model_cpu_vender = input()

	model_info_list.append(model_cpu_vender)

	log.info("CPU model is ?")

	cpu_model = input()

	model_info_list.append(cpu_model)

	log.info("Web Server is ?")

	model_web_server = input()

	model_info_list.append(model_web_server)

	log.info("SSH server support(Default) ?")

	model_ssh_support = input()

	model_info_list.append(model_ssh_support)

	log.info("Is it possible to eavesdrop ?")

	eavesdrop_sup = input()

	model_info_list.append(eavesdrop_sup)

	log.info("Default telnet user ?")

	model_tel_user = input()

	model_info_list.append(model_tel_user)

	log.info("Default telnet passwd ?")

	model_tel_passwd = input()

	model_info_list.append(model_tel_passwd)

	log.info("Sdk exist ?(links)")

	model_sdk = input()

	model_info_list.append(model_sdk)

	log.info("Openwrt support ?")

	model_openwrt = input()

	model_info_list.append(model_openwrt)

	log.info("Vulnable ?(True/False)")

	model_vuln = input()

	model_info_list.append(model_vuln)

	for i in range(len(model_info_list)):
		model_info_list[i] = model_info_list[i].strip()

	if (model_vuln == "True\n"):
		model_add_exp = CIMultiDict()

		log.info("Input poc total num")

		poc_num = input()

		for i in range(int(poc_num)):
			log.info("Organize POC, model\'s CVEID or POC_filename")

			poc_filename = input()

			log.info("POC data")

			poc_data = input()

			model_add_exp[poc_filename] = poc_data

			model_info_list.append(model_add_exp)
	else:
		model_info_list.append({})

	model_tree[model_add] = model_info_list
	model_tree_dic()
#append_to_tree("DIR-816",'mips')
#print(model_to_arch("DIR-832"))
#print_model_information("TOTOLINK_A7000R")
#model_tree_dic()
#dic_model_tree()
#search_model("N600R")
#model_tree_dic()