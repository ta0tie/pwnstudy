# PWN

## 栈溢出

### 简单栈溢出

ret2text 即控制程序执行程序本身已有的的代码 (.text)。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码 (也就是 gadgets)，这就是我们所要说的 ROP。

这时，我们需要知道对应返回的代码的位置。当然程序也可能会开启某些保护，我们需要想办法去绕过这些保护。

**ret2text**

IDA查看,使用了get()函数,可能存在栈溢出,同时在子函数secure中存在 `system(/bin/sh)`,对应地址 `0x8048763`.我们只要让栈溢出填充返回地址为目标地址即可.

gdb动调:

先在get处打断点

```c
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

`<pre>00:0000│ <b>esp</b> <span style="color:#FEA44C">0xffffcac0</span> —▸ <span style="color:#FEA44C">0xffffcadc</span> ◂— &apos;aaaaaaaaaaaaaaaaaaaaaa&apos; 01:0004│ <b>   </b> <span style="color:#FEA44C">0xffffcac4</span> ◂— 0x0 02:0008│ <b>   </b> <span style="color:#FEA44C">0xffffcac8</span> ◂— 0x1 03:000c│ <b>   </b> <span style="color:#FEA44C">0xffffcacc</span> ◂— 0x0 04:0010│ <b>   </b> <span style="color:#FEA44C">0xffffcad0</span> —▸ <span style="color:#9755B3">0xf7ffdb8c</span> —▸ <span style="color:#9755B3">0xf7fc26f0</span> —▸ <span style="color:#9755B3">0xf7ffda20</span> ◂— 0x0 05:0014│ <b>   </b> <span style="color:#FEA44C">0xffffcad4</span> ◂— 0x1 06:0018│ <b>   </b> <span style="color:#FEA44C">0xffffcad8</span> —▸ <span style="color:#9755B3">0xf7fc2720</span> —▸ <span style="color:#D41919">0x8048354</span> ◂— <span style="color:#AFD700">inc</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">edi</span> /* &apos;GLIBC_2.0&apos; */ 07:001c│ <b>eax</b> <span style="color:#FEA44C">0xffffcadc</span> ◂— &apos;aaaaaaaaaaaaaaaaaaaaaa&apos; ... ↓        4 skipped 0c:0030│ <b>   </b> <span style="color:#FEA44C">0xffffcaf0</span> ◂— 0xff006161 /* &apos;aa&apos; */ 0d:0034│ <b>   </b> <span style="color:#FEA44C">0xffffcaf4</span> —▸ 0xf7fca67c ◂— 0xe 0e:0038│ <b>   </b> <span style="color:#FEA44C">0xffffcaf8</span> —▸ <span style="color:#9755B3">0xf7ffd5e8 (_rtld_global+1512)</span> —▸ 0xf7fca000 ◂— 0x464c457f 0f:003c│ <b>   </b> <span style="color:#FEA44C">0xffffcafc</span> —▸ <span style="color:#FEA44C">0xffffdfba</span> ◂— &apos;/home/taotie/Desktop/pwnstudy/StackOverflow/ret2text/ret2text&apos; 10:0040│ <b>   </b> <span style="color:#FEA44C">0xffffcb00</span> —▸ 0xf7ffcff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x32f34 11:0044│ <b>   </b> <span style="color:#FEA44C">0xffffcb04</span> ◂— 0xc /* &apos;\x0c&apos; */ 12:0048│ <b>   </b> <span style="color:#FEA44C">0xffffcb08</span> ◂— 0x0 ... ↓        3 skipped 16:0058│ <b>   </b> <span style="color:#FEA44C">0xffffcb18</span> ◂— 0x13 17:005c│ <b>   </b> <span style="color:#FEA44C">0xffffcb1c</span> —▸ <span style="color:#9755B3">0xf7fc2400</span> —▸ 0xf7c00000 ◂— 0x464c457f 18:0060│ <b>   </b> <span style="color:#FEA44C">0xffffcb20</span> —▸ 0xf7c216ac ◂— 0x21e04c 19:0064│ <b>   </b> <span style="color:#FEA44C">0xffffcb24</span> —▸ <span style="color:#D41919">0xf7fd9e51 (_dl_fixup+225)</span> ◂— <span style="color:#AFD700">mov</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">dword</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">ptr</span><span style="color:#FFFFFF"> [</span><span style="color:#5FD7FF">esp</span><span style="color:#FFFFFF"> + </span><span style="color:#AF87FF">0x28</span><span style="color:#FFFFFF">], </span><span style="color:#5FD7FF">eax</span> 1a:0068│ <b>   </b> <span style="color:#FEA44C">0xffffcb28</span> —▸ 0xf7c1c9a2 ◂— &apos;_dl_audit_preinit&apos; 1b:006c│ <b>   </b> <span style="color:#FEA44C">0xffffcb2c</span> —▸ <span style="color:#9755B3">0xf7fc2400</span> —▸ 0xf7c00000 ◂— 0x464c457f 1c:0070│ <b>   </b> <span style="color:#FEA44C">0xffffcb30</span> —▸ <span style="color:#FEA44C">0xffffcb60</span> —▸ 0xf7e1dff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21dd8c 1d:0074│ <b>   </b> <span style="color:#FEA44C">0xffffcb34</span> —▸ <span style="color:#9755B3">0xf7fc25d8</span> —▸ <span style="color:#9755B3">0xf7ffdb8c</span> —▸ <span style="color:#9755B3">0xf7fc26f0</span> —▸ <span style="color:#9755B3">0xf7ffda20</span> ◂— ... 1e:0078│ <b>   </b> <span style="color:#FEA44C">0xffffcb38</span> —▸ <span style="color:#9755B3">0xf7fc2ab0</span> —▸ 0xf7c1f22d ◂— &apos;GLIBC_PRIVATE&apos; 1f:007c│ <b>   </b> <span style="color:#FEA44C">0xffffcb3c</span> ◂— 0x1 20:0080│ <b>   </b> <span style="color:#FEA44C">0xffffcb40</span> ◂— 0x1 21:0084│ <b>   </b> <span style="color:#FEA44C">0xffffcb44</span> ◂— 0x0 22:0088│ <b>ebp</b> <span style="color:#FEA44C">0xffffcb48</span> ◂— 0x0 23:008c│ <b>   </b> <span style="color:#FEA44C">0xffffcb4c</span> —▸ <span style="color:#D41919">0xf7c237c5 (__libc_start_call_main+117)</span> ◂— <span style="color:#AFD700">add</span><span style="color:#FFFFFF"> </span><span style="color:#5FD7FF">esp</span><span style="color:#FFFFFF">, </span><span style="color:#AF87FF">0x10</span> 24:0090│ <b>   </b> <span style="color:#FEA44C">0xffffcb50</span> ◂— 0x1 25:0094│ <b>   </b> <span style="color:#FEA44C">0xffffcb54</span> —▸ <span style="color:#FEA44C">0xffffcc04</span> —▸ <span style="color:#FEA44C">0xffffce20</span> ◂— &apos;/home/taotie/Desktop/pwnstudy/StackOverflow/ret2text/ret2text&apos; 26:0098│ <b>   </b> <span style="color:#FEA44C">0xffffcb58</span> —▸ <span style="color:#FEA44C">0xffffcc0c</span> —▸ <span style="color:#FEA44C">0xffffce5e</span> ◂— &apos;GDMSESSION=gnome&apos; 27:009c│ <b>   </b> <span style="color:#FEA44C">0xffffcb5c</span> —▸ <span style="color:#FEA44C">0xffffcb70</span> —▸ 0xf7e1dff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21dd8c </pre>`
