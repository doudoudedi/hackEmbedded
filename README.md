# introduction

#### foreword

>In the process of penetration and vulnerability mining of embedded devices, many problems have been encountered. One is that some devices do not have telnetd or ssh services to obtain an interactive shell, and the other is that memory corruption vulnerabilities such as stack overflow are usually Null bytes are truncated, so it is more troublesome to construct reverse_shellcode, so this tool was developed to exploit the vulnerability. This tool is developed based on the PWN module and currently uses the python2 language

#### fuction

This tool is embedded in the security test of the device. There are two main functions:

1.  Generate **backdoor programs** of various architectures. The backdoor program is packaged in shellless pure shellcode and is smal in size.**Armv5, Armv7, Armv8, mipsel, mips are now supported, and they are still being updated**

2.  Generate **reverse_shell shellcode** of various architectures during the exploit process, and no null bytes, which facilitates the exploitation of memory corruption vulnerabilities on embedded devices. **Armv5, Armv7, Armv8, mipsel, mips are now supported, and they are still being updated**

#### Construct ELF
  python2 install pwn
```
pip install pwn
```

​	This tool is developed in python language, so converting python to EL can be done through **nuitka**

```shell
nuitka hackEmbedded_tool.py
```

​	If possible, put the modules that generate various backdoors and reverse_shellcode under python's site-packages

```
sudo cp ./generate_* {your_dir}/site-packages
sudo cp ./extract_shellcode.py {your_dir}/site-packages
```

You can view the path in sys.path under the python terminal

```
Python 2.7.17 (default, Mar 18 2022, 13:21:42) 
[GCC 7.5.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> sys.path
```

#### Instructions for use

​	To use the generated backdoor or reverse_shellcode, you need to specify the ip address, port number, assembly architecture, endian （Default is armv7）

​	**Here is the example that generates reverse_shellcode without null bytes**

![image-20220428161403858](./img/image-20220428161403858.png)

**Here is the example that generates reverse_shellcode without null bytes**

![image-20220428161757170](./img/image-20220428161757170.png)

**You can view tool information with -h**

![image-20220428161847829](./img/image-20220428161847829.png)


#### chips and architectures
Tests can leverage chips and architectures

Mips:
MIPS 74kc V4.12 big endian
MIPS 24kc V5.0  little endian

Armv7:
Allwinner(全志)V3s

Armv8:
Qualcomm Snapdragon 660

#### One-click build environment

To be added
