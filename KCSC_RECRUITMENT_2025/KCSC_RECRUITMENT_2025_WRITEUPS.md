---
title: KCSC_RECRUITMENT_2025_WRITEUPS

---

# Thông tin bài làm:
Bài làm của : Nguyễn Đăng Huy 
MSSV: AT21N0130(MN)

# KCSC RECRUITMENT 2025: PWNABLE_WARMUP_AAA

![{F3E6F828-82AB-4493-B3EA-4D1B4447EF6C}](https://hackmd.io/_uploads/Sk__aEqDyx.png)

Link: https://kcsc.tf/challenges#AAA-25


## IDA
* Sử dụng công cụ IDA để dịch ngược và phân tích đề bài:
 ![{90BD28B9-73A9-4A89-BEDA-E58F4EBDDD6F}](https://hackmd.io/_uploads/r1huvIcwye.png)

* Nhận xét tổng quan: ta thấy rằng xung quanh hàm **main** còn có hàm **setup** ta cần lưu ý. Vậy nên ta sẽ tiến hành khảo sát 2 hàm này.

* Đầu tiên ta phân tích hàm **main** của chương trình:
 ![{F808D932-A31E-47D7-8525-79FB6CE80B50}](https://hackmd.io/_uploads/SyaZWH5P1l.png)
    * Ta nhận thấy rằng đầu tiên hàm **setup** được gọi.
    * Sau đó tiến hành in ra chuỗi "Input: ".
    * Tiến hành lấy dữ liệu đầu vào qua hàm **gets** vào biến **buf**.
    * Tiến hành in ra chuỗi "Your input: " với định dạng **%s** và kí tự xuống dòng **\n** và dữ liệu từ biến **buf**.
    * Cuối cùng hàm thực hiện kiểm tra biến toàn cục **is_admin** và nếu biến này có giá trị là 1 thì tiến hành thực thi việc đọc dữ liệu từ file **'/flag'**.
    * Chuyển sang chế độ xem *IDA-view-A* tại hàm main ta có thể thấy một loạt mã máy mô tả hoạt động của hàm **main** và ta tiến hành trỏ đến biến buf để xem kích thước:
    ![{15244CF8-98BA-4D8E-A730-FA7290022B0E}](https://hackmd.io/_uploads/rJAvvH9wJg.png)
    * Và ta dễ dàng nhận thấy rằng tại đây biến **buf** được khai báo với kích thước 256 byte.

* Cùng nhìn sơ qua hàm **setup** :
 ![{499B5ECA-BD1B-418E-89A1-0FA0279ADB07}](https://hackmd.io/_uploads/rJ84rScD1x.png)
    * Hàm **setup** thực chất đang đóng vai trò để tắt đi bộ đệm cho *stdin*, *stdout* và *stderr*.
    
## Ý tưởng
* Sau khi khảo sát chương trình bằng công cụ IDA ta nhận thấy rằng chương trình tồn tại lỗi **TRÀN BIẾN (BUFFER OVERFLOW)** bởi ta nhận thấy rằng tại hàm **main** dữ liệu đang được nhập vào biến **buf** thông qua **gets** và đặc trưng của hàm **gets** là lấy không giới hạn kích thước của dữ liệu. Tuy nhiên ta đã xem xét kích thước của biến **buf** là **256 byte**.
* Vậy ý đồ của ta là nhập tràn biến **buf** và thay đổi giá trị biến toàn cục **is_admin** để đọc được cờ từ file **'/flag'**.

## Khai thác
* Với ý tưởng đã nêu trên vậy điều ta còn thiếu hiện tại là làm sao để thay đổi giá trị của biến quyền người dùng **is_admin**.
* Ta tiến hành khảo sát toàn bộ chương trình bằng cách phân tích chương trình:
 ![{7780F245-C787-436D-A52E-7E044CD46697}](https://hackmd.io/_uploads/Sy5ksr5wJl.png)
* Ta nhìn sơ qua thì có thể thấy hoạt động của chương trình tương tự như ta đã phân tích bằng công cụ IDA.
* Ta nhận thấy chương trình thực hiện lấy dữ liệu đầu vào vào biến **buf** và ta có thễ dễ dàng thấy được điều đó tại **main<+38>**: 
![{BC50F688-B74C-4419-8572-45ED259406AA}](https://hackmd.io/_uploads/HkKLx89wkl.png)

* Chương trình thực hiện việc tính toán nhanh và gán địa chỉ đang có tại địa chỉ [rip+0x2e25] được kí hiệu với địa chỉ **0x555555558060** vào thanh ghi **rax** và sau đó chương trình thiết lập các đối số phù hợp với các thanh ghi và thực thi hàm **gets**.

* Và ta cũng thấy được **is_admin** tại dòng **main<+88>**:
![{1EE6608A-BBC5-4187-A006-3B65B510E5F0}](https://hackmd.io/_uploads/BkWqx8qPyl.png)
 
* Tại đây chương trình tiến hành thiết lập thanh ghi 32 bit **eax** bằng giá trị tại địa chỉ  [rip+-0x2ef4] được kí hiệu bằng địa chỉ **0x555555558160** với tên gọi là **is_admin**. Sau đó chương trình thực hiện kiểm tra xem trong thanh ghi **eax** có giá trị bằng 0 hay không nếu không thì hệ thống tiến hành thực thi đọc dữ liệu từ file **'/flag'**.

* Ta tiến hành kiểm tra các phân vùng dữ liệu của chương trình thì nhận thấy rằng địa chỉ của biến **buf** và **is_admin** đều nằm trên cùng một phân vùng dữ liệu có thể đọc và ghi (rw):
 ![{56A9B001-B657-4477-948F-56C06601B1A1}](https://hackmd.io/_uploads/HyhharcP1e.png)
* Phân vùng trên nằm trong khoảng địa chỉ từ **0x555555558000** đến **0x555555559000** với quyền **rw-p** (đọc và ghi).

**=> Vậy ta đã nhận thấy buf và is_admin đều nằm trên một phân vùng và ta có thể dễ dàng tính khoảng cách giữa 2 biến trên bằng 0x100 byte (256) và để thay đổi được giá trị của is_admin thì ta chỉ cần ghi đè làm thay đổi giá trị ban đầu của is_admin như vậy is_admin sẽ khác 0 và ta có flag.**

* Ta sẽ tiến hành đặt breakpoint tại nơi dữ liệu được nhập vào là hàm **gets**:
![{83EE709B-3A16-4779-A8FA-3AEAAA3FC632}](https://hackmd.io/_uploads/BJVhzUqwkx.png)

* Sau đó GDB sẽ cho ta đến trước lúc hàm **gets** được gọi:
![{D5375DF3-5EE6-45E0-92FD-3713EAF22A7E}](https://hackmd.io/_uploads/HkagQ8qDyx.png)

* Với mục tiêu là làm tràn biến **buf** và thay đổi giá trị **is_admin** ta sẽ sử dụng công cụ cyclic để tạo ra một chuỗi có độ dài phù hợp để nhập vào.
* Ta thấy rằng 256 rõ ràng vừa là khoảng cách vừa là kích thước của biến **buf** tuy nhiên nếu ta cho nhập vào 256 byte thì ta chỉ mới lấp đầy được biến **buf** và dữ liệu của **is_admin** chưa bị thay đổi:
    * Để khảo sát điều này ta cho nhập vào 256 byte và khảo sát dữ liệu trên biến **buf** bằng địa chỉ ta đã có:
    ![{94D60E59-B047-429C-B5FF-C33B13AF9B11}](https://hackmd.io/_uploads/S1mkVLcDJe.png)
    * Ta nhận thấy tại **is_admin** giá trị vẫn đang tồn tại là 0 và đồng nghĩa nếu ta tiếp tục cho thực thi chương trình thì chương trình sẽ thực hiện toàn bộ lệnh và kết thúc:
    ![{63356279-C82B-4138-ACD1-54CF4055E878}](https://hackmd.io/_uploads/rJ-EVIcv1l.png)

* Với điều đã khảo sát, ta nhận thấy cần nhập hơn 256 byte vì khi đó byte thứ 257 trở đi cho đến byte thứ 260 sẽ làm thay đổi giá trị thanh ghi eax (vốn là một thanh ghi 32 bit) và khi kiểm tra thì ta sẽ thành công lấy được flag:
![{0E95A886-3EF8-40AD-8416-7E0F9D629D7D}](https://hackmd.io/_uploads/S1NTNI9P1g.png)
* Lúc này tại **is_admin** đang chứa 4 byte từ dữ liệu nhập vào của ta và khi ta tiếp tục thực thi chương trình: 
![{73AE7090-3130-4E27-A9C7-807CEE0F95BD}](https://hackmd.io/_uploads/rJGXBL5vJx.png)
* Hàm **system** đã được thực thi đồng nghĩa với việc file **'flag'** đã được đọc. Và một tiến trình con đã được thực hiện.

* Sau khi khai thác trên local thành công, ta tiến hành khai thác với máy chủ đề thi bằng lệnh : *nc 36.50.177.41 50011*.
* Ta tiến hành các bước khai thác như đã làm ở local và ta được kết quả:
![{51A2D540-6767-4E3A-AEEA-F2B29C8D01FB}](https://hackmd.io/_uploads/rJZ4L8cvye.png)

* Như vậy ta đã có được flag : 
`KCSC{AAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaa____!!!!!}`

**=> Challenge hoàn thành**

# KCSC RECRUITMENT 2025: PWNABLE_EASY_WELCOME
![{66544AD5-02CE-409A-8EAB-8FDB6E294A37}](https://hackmd.io/_uploads/rydodUqv1e.png)
Link: https://kcsc.tf/challenges#welcome-19

## IDA
* Sử dụng công cụ IDA để dịch ngược và phân tích đề bài:
![{733EE4B1-5A0C-44A6-94EC-9E1B6F442011}](https://hackmd.io/_uploads/H1xNKLqDkx.png)

* Nhận xét tổng quan: ta thấy rằng xung quanh hàm **main** còn có hàm **setup** và **win** ta cần lưu ý. Vậy nên ta sẽ tiến hành khảo sát 3 hàm này.
* Đầu tiên ta phân tích hàm **main** của chương trình:
![{51C23450-01E7-4C0C-8F10-01E45AD245D1}](https://hackmd.io/_uploads/Hyhl5L5PJg.png)
    * Ta nhận thấy trong hàm **main** biến cục bộ **s** được khai báo dưới dạng một chuỗi kí tự có 64 phần tử.
    * Hàm **setup** được gọi.
    * Tiến hành in ra màn hình chuỗi "Welcome to KCSC Recruiment !" và chuỗi "What's your name? " kèm kí tự xuống dòng "\n" và dấu "> ".
    * Sau đó tiến hành nhập dữ liệu vào biến **s** bằng hàm **fgets** với kích thước là 64 byte.
    * Thực hiện in ra chuỗi "Hi " kèm dữ liệu ta nhập vào từ biến **s**.
    * Cuối cùng thực hiện kiểm tra nếu biến **key** có giá trị bằng 4919 thì hàm **win** được gọi nếu không thì kết thúc chương trình.

* Ta tiến hành khảo sát hàm **setup**:
![{2DA03FEF-5AEB-4010-A71E-09D5650767F0}](https://hackmd.io/_uploads/Hy3jiLqDJl.png)
    * Hàm **setup** thực chất đang đóng vai trò để tắt đi bộ đệm cho *stdin*, *stdout* và *stderr*.
    
* Sau cùng ta khảo sát hàm **win**:
![{7E67C029-E662-44CB-9879-654D7B5C02FE}](https://hackmd.io/_uploads/H111nIcDyl.png)
    * Hàm **win** trả về là hành động thực thi hệ thống đối với đường dẫn **'/bin/sh'**, tạo lập một tiến trình con, cung cấp khả năng toàn quyền kiểm soát cho người tấn công hệ thống.
## Ý tưởng
* Sau khi khảo sát ta thấy rằng chương trình không tồn tại lỗi tràn biến (buffer overflow) vì dữ liệu nhập vào qua hàm fgets với đặc tính chỉ lấy thông tin với đủ kích thước của biến (như ở đây là lấy 64 byte vào biến **s** có kích thước 64 byte).
* Tuy nhiên ta cũng để ý thấy rằng tại lệnh in ra dữ liệu của biến **s** không có định dạng dữ liệu in ra cho dữ liệu của biến **s** và ta có thể dễ dàng nhận ra đây là lỗi **CHUỖI ĐỊNH DẠNG (FORMAT STRING)**.
* Mục đích của chúng ta là thay đổi giá trị của biến **key** vậy ta sẽ nghĩ ngay đến hướng giải sử dụng định dạng **%n** để có thể thay đổi dữ liệu của một biến bởi tính chất của định dạng **%n** là nó sẽ ghi vào một địa chỉ dạng con trỏ trong bộ nhớ số lượng byte mà printf đã in ra trước **%n** vì vậy ta sẽ cho nhập vào trước định dạng **%n** một lượng byte bằng 4919 và sau đó là con trỏ đến biến **key** để có thể thay đổi giá trị biến **key** thành 4919. Từ đó thỏa điều kiện và ta có thể tạo lập tiến trình con.

## Khai thác
* Ta tiến hành phân tích và kiểm tra các phương pháp bảo mật của chương trình:
![{3D6BB95A-2A45-42FA-BEF8-35C80191E262}](https://hackmd.io/_uploads/Hy82iOqD1x.png)
    * RELRO: Partial RELRO: Một phần của bảng GOT là READONLY, hạn chế việc ghi đè lên các địa chỉ thuộc bảng GOT.
    * Stack: No canary found: Không tồn tại canary kiểm tra buffer overflow.
    * NX(Non-executable stack): enable: Stack không thể thực thi được.
    * NO PIE: địa chỉ của chương trình đang tĩnh.
    * SHSTK(Shadow stack): enable: giúp giảm thiểu các cuộc tấn công bằng kĩ thuật ROP.
    *  IBT (Indirect Branch Tracking): enable: giúp tránh các cuộc tấn công chuyển hướng gián tiếp.
    * Stripped: No: tệp thực thi vẫn còn giữ các kí hiệu, tên hàm đầy đủ, thuận tiện cho khai thác.
* Ta tiến hành phân tích hàm **main** dựa vào GDB:
 ![{399A0AC8-F0EB-4995-9745-8A265310DDF0}](https://hackmd.io/_uploads/ByByo_5Pyl.png)
* Ta thấy rằng tại địa chỉ **main+118**:
![{DC9C7C8A-7680-4201-AC0F-9E81635570AF}](https://hackmd.io/_uploads/Hyofiu5wkx.png)
    * Ta có được địa chỉ *0x40408c* và ta nhận thấy địa chỉ này được kí hiệu bởi tên là **key** vậy ta đã có được địa chỉ của **key**.

* Ta đặt breakpoint ngay tại vị trí hàm **gets** và tiến hành di chuyển đến đó:
![{8D49D7DB-59A3-414E-A79F-92479EDA880A}](https://hackmd.io/_uploads/rJ3r0K9vyx.png)
    * Ta nhận thấy tại đây ta có được địa chỉ của biến **s**. Ta tiến hành tel stack từ địa chỉ của **s** và nhận thấy rằng trên stack chưa hề có địa chỉ của **key**:
    ![{2A5035AD-509E-4A6A-B155-F93FDF57641A}](https://hackmd.io/_uploads/r1sLJq9Dye.png)
    * Vậy ta cần phải nhập địa chỉ của **key** vào để có thể thay đổi giá trị của **key**.

* Như vậy ta có thể viết script để khai thác và ta có biến lưu địa chỉ của **key** như sau:
    * ![{8148DB7A-3ED0-4B78-B4C1-A6F6BC6FECD8}](https://hackmd.io/_uploads/HJeZzFcwyl.png)
    * Ở đây vì ta đã load chương trình lên script nên ta có thể gọi địa chỉ của **key** như một kí hiệu thay vì phải làm thủ công là lấy địa chỉ từ GDB.
    * Vì ta muốn thay đổi giá trị **key** thành 4919 nên trước khi định dạng **%n** ta cần truyền vào 4919 kí tự nên ta sẽ có một payload gồm 4919 byte kí tự và định dạng **%n** có tham số được tham chiếu là 6 để truyền vào chương trình nối tiếp là địa chỉ 64 bit của **key**:
    * ![{FA2EEFCB-48EC-4154-BB4D-4F03C284BD6E}](https://hackmd.io/_uploads/HkhfHc5Dyl.png)
    * Tuy nhiên không khả thi vì nếu truyền vào số lượng byte như trên thì chương trình sẽ lỗi vì lượng byte nhập vào chỉ tối đa 64 byte.
    * Nên ta sẽ sử dụng định dạng **%c** (**%c** cho phép ta in số lượng kí tự nhất định là tham số của **%c** và khi kết hợp với định dạng **%n** thì số lượng kí tự trên được ghi vào địa chỉ được tham chiếu bởi tham số của **%n**)
    * Vậy ta sẽ chuyển đổi payload ban đầu thành định dạng chuỗi Python được encode thành dạng byte và sử dụng **%c** với tham số là 4919 kết hợp với **%n** để thay đổi giá trị của **key**. 
    * Đồng thời ta cũng cần thay đổi breakpoint thành hàm printf tại **main+96** để khảo sát các kí tự ta nhập vào, đồng thời để khảo sát tham số chính xác của **%n**.
    * Vì lượng byte của chuỗi định dạng ta chưa biết trước vì vậy nếu ta nối liên tiếp với 8 byte địa chỉ của **key**:
    * ![{8FD7ABE6-59E8-40D9-B237-BF084A046538}](https://hackmd.io/_uploads/Bk5OwjcDke.png)
    * Thì địa chỉ sẽ bị dính liền với một phần của chuỗi tạo thành một địa chỉ không hợp lệ:
    * ![{BC826F77-2618-4A5F-BC49-1D7BBF0AA65F}](https://hackmd.io/_uploads/rJE37i9wyx.png)
    * Nên ta sử dụng *ljust* để bù vào một số lượng kí tự để có thể đạt đến 0x20 byte rồi nối tiếp với địa chỉ của **key**:
    * ![{92FBE618-9208-4177-8F5F-FF32A21B609E}](https://hackmd.io/_uploads/BJCrwjcv1x.png)

* Ta chạy script:
![{4A0AA30E-DCDD-441E-BB9A-3FBF3ADA82EF}](https://hackmd.io/_uploads/Hy8NNs9v1e.png)
    * Khảo sát stack ta thấy rằng các dữ liệu ta nhập vào đã đúng và địa chỉ của **key** cũng không bị lỗi, tuy nhiên **key** đang nằm ở tham số thứ 10 của **%n** và điều này dẫn đến tham số của **%c** truyền vào không đúng địa chỉ. Để giải quyết ta cần giảm đi lượng byte bù vào của ljust và tăng tham số của **%n** lên:
    * ![{317AD141-1968-4EFD-A161-27891F8F4974}](https://hackmd.io/_uploads/HkLsUi5wkg.png)

* Ta cho chạy script:
![{AA94E6E0-E222-41A9-80BB-8C2C8A8B1009}](https://hackmd.io/_uploads/r1JyZocPJe.png)
* Ta thấy rằng lúc này dữ liệu ta truyền vào đã đúng và ta tiến hành di chuyển đến bước kiểm tra gia trị của **key**:
![{D0E8817F-85A6-47BB-A001-B834B39FEAEF}](https://hackmd.io/_uploads/SkSuVs9DJx.png)
* Giá trị của **key** lúc này đã là 0x1337 (4919) đúng với điều kiện và ta cho chương trình thực thi tiếp:
![{7AFFEE55-936C-4D42-9727-93D3C4BBFA77}](https://hackmd.io/_uploads/S1sLWs9P1x.png)
* Vậy hàm system đã được thực thi tạo lập một tiến trình con, ta đã khai thác chương trình thành công trên local.

* Ta tiến hành kết nối và khai thác thử trên máy chủ:
* ![{DF807682-B7D1-4BE4-9BB7-A6ABB2B0316B}](https://hackmd.io/_uploads/ByldkHj5Dkg.png)
* Vậy ta đã có được flag của challenge:
`KCSC{A_little_gift_for_pwner_hehehehehehehehe}`

**=>Challege hoàn thành**


# KCSC RECRUITMENT 2025: PWNABLE_EASY_CCRASH
![{21C90B69-4F72-4657-B170-E6AB94109CC2}](https://hackmd.io/_uploads/HJCEtOiP1l.png)
Link: https://kcsc.tf/challenges#ccrash-4

## IDA
* Sử dụng công cụ IDA để dịch ngược và phân tích đề bài:
![{9FB1A8DB-3FE2-416F-AC7C-869A4B1C274E}](https://hackmd.io/_uploads/S1925tiDkg.png)
    * Nhận xét tổng quan: Ta thấy rằng để khai thác ta cần chú ý 2 hàm là **main** và **setup**.

* Đầu tiên phân tích **main**:
![{4232C2AD-ECD1-4FC5-81E3-DF6611D7A4D9}](https://hackmd.io/_uploads/HkmWjYoPJl.png)
    * Đầu tiên biến **result** được khai báo dưới dạng một mảng kí tự với kích thước 1024 byte.
    * Thực hiện tắt bộ nhớ đệm đối với *stdin* và *_bss_start*.
    * Sau đó hàm **setup** được gọi.
    * Tiến hành in ra các chuỗi *"Test::Test: Assertion 'false' failed!"*.
    * In ra chuỗi *"Callstack:"* 
    * In ra chuỗi *"dbg::handle_assert(214) in mylib.dll %p: Test::Test(9) in mylib.dll\n "* kèm với biến **result**.
        * Tại đây ta thấy biến **result** còn được in ra với định dạng **%p** (để in ra địa chỉ bộ nhớ) nên dữ liệu được in ra là địa chỉ của biến **result**.
    * Tiếp tục in ra chuỗi *"myfunc(10) in TestStackTrace %p: main(23) in TestStackTrace\n"* kèm với biến **strace**.
        * Một lần nữa tồn tại định dạng **%p** vì vậy ta có thể xác định rằng địa chỉ biến **trace** được in ra.
    * In ra chuỗi *"invoke_main(65) in TestStackTrace"* và  *"_scrt_common_main_seh(253) in TestStackTrace "* và chuỗi *"OK"*.
    * Cuối cùng hàm **main** thực hiện đọc dữ liệu vào biến **result** với kích thước 1040 byte và kết thúc hàm.

* Tiếp theo ta tiến hành phân tích hàm **setup**:
![{A428E672-EB15-4911-A949-4CE5E423E2AD}](https://hackmd.io/_uploads/B199h9iP1l.png)
     * Khai báo các biến cục bộ như biến bộ lọc seccomp **ctx**; biến kích thước của trang nhớ **page_size** và biến chứa thông tin bộ nhớ **savedregs**:
     ![{D095EDC4-9ED9-4503-BC15-E3054108C830}](https://hackmd.io/_uploads/ByMthsswye.png)
     * Lấy kích thước cho trang nhớ bằng hàm **sysconf** với tham số 30, kết quả trả về là kích thước của trang nhớ hệ thống và được lưu vào biến **page_size**.
     ![{8D6CCBFE-FE7C-4548-BEED-9DE6224CABFB}](https://hackmd.io/_uploads/BJkjnjoPkg.png)
     * Thực hiện bảo vệ vùng nhớ bằng hàm **mprotect** thay đổi quyền truy cập vào một vùng của bộ nhớ được xác định bởi biến **savedregs** và vùng nhớ này được cập nhật quyền hạn thành đọc, ghi và thực thi theo quy tắc số 7.
     ![{AEB84278-A3BD-4D8A-B279-AF14FD971700}](https://hackmd.io/_uploads/rJK2niovJx.png)
     * Khởi tạo biến bộ lọc seccomp **ctx**.
     ![{FDDE3B57-976D-4A5B-AE1D-09069BD22CFD}](https://hackmd.io/_uploads/BJB03ioDJg.png)
     * Tiến hành kiểm tra biến bộ lọc **ctx** có hợp lệ nếu không hợp lệ thì in thông báo khởi tạo không thành công và kết thúc hàm:
     ![{BBE74929-B94C-4D97-8C0F-71BD88D944A3}](https://hackmd.io/_uploads/SJ4V0sowke.png)
     * Tiến hành thêm các quy tắc của seccomp vào bộ lọc:
     ![{222425AA-6472-41EA-B137-C336BA006E2C}](https://hackmd.io/_uploads/rkFNassvJg.png)
         * Lệnh **seccomp_rule_add** đang thêm vào các quy tắc 59 và 322 cho bộ lọc tương ứng với lần lượt là các hàm **execve** và **open**. Đồng nghĩa với việc các hàm **execve** và **open** bị chặn, không thể sử dụng trong chương trình.
    * Sau đó tiến hành cho phép quy tắc 2 tương ứng với hàm **fork** được thực thi và sử dụng **seccomp_load** với tham số là biến **ctx** để áp dụng bộ lọc.
    ![{4533EA16-BF6D-45AD-924B-69B32F4FB7DB}](https://hackmd.io/_uploads/B18u6osv1l.png)
    * Cuối cùng tiến hành giải phỏng bộ lọc bằng hàm **seccomp_release** với tham số **ctx**.
    ![{75E5F17E-02E8-4A43-AB27-CE1AD657B3A5}](https://hackmd.io/_uploads/ByX56sjvkl.png)

## Ý tưởng
* Ta có thể dễ dàng chương trình đang tồn tại lỗi **TRÀN BIẾN (BUFFER OVERFLOW)** do hàm **read** đang lấy vào biến **result** 1040 byte trong khi kích thước được khai báo cho **result** là 1024 byte.
* Mục tiêu của chúng ta là đọc được nội dung của file `flag.txt` (hiện đang chứa flag của challenge) thông qua việc có được quyền điều khiển chương trình bằng cách thực thi **system(''/bin/sh')**. Tuy nhiên, chương trình được tích hợp kĩ thuật bảo mật seccomp gồm bộ lọc các quy tắc đã chặn mất quyền thực thi của hàm **system(execve)** và ngoài **main** và **setup** ta đã phân tích hoạt động ở trên ra thì hầu như không tồn tại một hàm hay điều kiện thực thi nào có thể thực thi hành động đọc file `flag.txt`. 
* Vì vậy ta cần có một phương pháp khai thác mới đó là mở, đọc và in ra màn hình nội dung của file `flag.txt`. Từ đó ta nghĩ đến việc truyền vào chương trình shellcode có chức năng đọc, mở và in ra màn hình thông tin cần thiết. 
    * Việc đọc và viết ta có thể hướng đến việc sử dụng hàm **read** và **write** tuy nhiên việc mở file cần dùng đến hàm **open** và **open** đã bị chặn bởi seccomp.
    * Ta tìm đến sự thay thế cho hàm **open** đó là **openat**. (So sánh: **openat** có thể linh động việc thao tác trên các thư mục, là một sự giải quyết hạn chế của **open** chỉ thao tác được cái tệp, đường dẫn trên thư mục hiện tại)
* Ngoài ra để thực thi ý tưởng khai thác này ta còn cần phải khảo sát các phương pháp bảo mật và hoạt động của chương trình bằng GDB:
    * Các phương pháp bảo mật:
    * ![{F79BCEB6-3E0A-4734-AF7E-2578214D08D1}](https://hackmd.io/_uploads/rJGhzasw1e.png)
        * Ta chú ý đến các trạng thái bảo mật chính như:
        * `Stack` đang không tồn tại canary cho phép ta gây ra việc tràn biến.
        * `Non-executable stack` đang được bật vậy nghĩa là stack không thể thực thi được.
        * `NO PIE` địa chỉ của chương trình đang tĩnh, thuận tiện cho ta thao tác với các hàm và kí hiệu.
    * Khảo sát hoạt động:
        * Ta tiến hành phân tích chương trình:
        * ![{BD2861B2-1CAF-483B-BB9E-9E04580C75C7}](https://hackmd.io/_uploads/r1Px4TsPkl.png)
            * Ta để ý trước nhất chương trình thực hiện thiết lập các bộ đệm và thực thi **setup** và **setup** có tiến hành thay đổi quyền thực thi của một phân vùng bộ nhớ nào đó của chương trình và ta sẽ tiến hành quan sát điều này trước và sau khi **setup** được thực thi:
                * Trước:
                * ![{34A86C8B-CE92-4E52-9B24-D8FC8D248B65}](https://hackmd.io/_uploads/rJq2VTjDJx.png)
                * Sau:
                * ![{25EC2EA1-F33A-4ECF-8886-F309EE74DE8C}](https://hackmd.io/_uploads/ByQ0NTivJx.png)
            * Như vậy thông qua khảo sát, sau khi **setup** được gọi thì phân vùng **stack** được bổ sung quyền thực thi. Vậy ta hoàn toàn có thể viết shellcode với chức năng mở, đọc, viết flag ra màn hình rồi truyền vào stack, sau đó ta tiến hành ghi đè địa chỉ trả về của hàm main để chương trình thực hiện return vào shellcode và thực thi.
            * Đồng thời ta còn nhận thấy **trace** được xem là kí hiệu và đang có địa chỉ là *0x404029* và nhận thấy địa chỉ này đang thuộc phân vùng bộ nhớ có quyền đọc và ghi của chương trình:
            * ![{E55F0C9A-6F19-4387-B8B3-8C4EA0BC6C23}](https://hackmd.io/_uploads/BkTRrTjwyl.png)

## Khai thác
* Chuẩn bị shellcode:
    * Hàm **openat(int dirfd, const char *pathname, int flags, mode_t mode)**:
    * Hàm yêu cầu ta thiết lập các tham số gồm: 
        * Mô tả thư mục cơ sở `dirfd` , ở đây ta cần thao tác với nội bộ thư mục hiện tại nên ta xét tham số này là `AT_FDCWD` (-100).
        * Đường dẫn đến file cần mở `pathname`, ta sẽ thiết lập thành tên file `flag.txt`.
        * Các tham số như `flag` và `mode` ta sẽ set thành 0 đồng nghĩa với chế độ mở chỉ để đọc READONLY cho `flag`.
        * ![{FE462D97-D3A7-42CE-A251-82920528AD3A}](https://hackmd.io/_uploads/rkUYh0iDJl.png)
    * Hàm **read(fd, buf, count)**
    * Các tham số:
        * Mô tả tệp, ở đây ta sẽ thiết lập tham số này là mô tả tệp của file `flag.txt`. Mô tả tệp là kết quả trả về của thao tác **openat** được lưu vào thanh ghi rax nên ta sẽ thực hiện việc chuyển mô tả tệp từ thanh ghi rax vào thanh ghi rdi.
        * Biến để dữ liệu được đọc lưu vào, ta nhận thấy rằng dữ liệu được đọc từ file `flag.txt` cần được lưu ở một phân vùng bộ nhớ trống và có đầy đủ quyền đọc và ghi và ta thấy **trace** là nơi lý tưởng để làm việc này nên ta sẽ thiết lập tham số này là địa chỉ của **trace**.
        * Kích thước đọc, ta chưa được biết trước độ dài, kích thước dữ liệu có trong file nên ta sẽ đặt là một kích thước lớn vừa đủ: 0x50 byte.
        * ![{CCB8BF37-072E-4362-A20C-6E278D5DC506}](https://hackmd.io/_uploads/SyUD3RoPkg.png)
    * Hàm **write(fd, buf, count)**
    * Các tham số:
        * Mô tả nơi muốn ghi dữ liệu, ở đây ta cần ghi dữ liệu từ `flag.txt` ra màn hình nên ta sẽ thiết lập là tham số của stdout (1)
        * Nơi dữ liệu được lưu để ghi, ta thiết lập thành địa chỉ của **trace**.
        * Kích thước, ta thiết lập như hàm **read**.
        * ![{AEDB7450-6C39-4734-967D-CF914C88F239}](https://hackmd.io/_uploads/rk_S2AiP1g.png)
* Và ta đã có được một shellcode hoàn chỉnh với đủ chức năng mở, đọc, ghi file.

* Ta cho chạy thử chương trình thì nhận thấy địa chỉ **stack** và **trace** được in ra, ta tiến hành viết script nhận vào 2 địa chỉ này:
    * ![{05A45F3B-C023-4A86-83D6-B3DB8CCF966F}](https://hackmd.io/_uploads/H1Wdo6owJx.png)
    * ![{8835DBA5-4A5E-4654-92CC-BE7E1262299A}](https://hackmd.io/_uploads/Hkann6ovkg.png)
    * Với biến `result_addr` là địa chỉ của biến **result** và `trace` là địa chỉ của **trace**, ta cho in ra màn hình giá trị của 2 biến này:
    * ![{791A93A8-4A70-4B0F-AB93-22AAE88668E0}](https://hackmd.io/_uploads/BJNonaswyx.png)
    * Ta cũng cần khảo sát sự tràn của các biến trong chương trình nên ta thiết lập một payload có 1040 byte kí tự 'a' và cho truyền vào chương trình:
    * ![{A71EE518-2BDD-4228-855F-44A01F3EE710}](https://hackmd.io/_uploads/rJT8RTiPkx.png)
* Ta cho chạy script:
    * ![{715A6BD1-E4BE-4CD9-A583-3A5736957BC7}](https://hackmd.io/_uploads/rJV_lAswJg.png)
    * Địa chỉ **result** và **trace** được in ra và ta cần kiểm tra 2 địa chỉ này có đúng hay không:
        * Đối với địa chỉ của **trace** vì địa chỉ này nằm ở phân vùng bộ nhớ của chương trình mang địa chỉ tĩnh nên so với địa chỉ ta đã khảo sát ở trên thì địa chỉ của **trace** chính xác.
        * ![{4EF578D2-AE70-4196-BC0A-AEDF8C9D0C8D}](https://hackmd.io/_uploads/Hkdx1CjPkg.png)
        * Đối với địa chỉ của **result**, ta nhận thấy so với lần chạy đầu thì mỗi lần địa chỉ in ra của **result** khác nhau cà kiểm tra, ta đã nhận các địa chỉ đúng:
        * ![{57A6AFC5-0410-41FC-A4AE-533518A4DC59}](https://hackmd.io/_uploads/rJFJb0jDkl.png)
        * Được biết dữ liệu được nhập vào **result** nên ta có thể đặt breakpoint tại hàm **read** của chương trình rồi sau đó di chuyển và khảo sát:
        * ![{C304E322-E329-4B18-BB12-4180D88D3413}](https://hackmd.io/_uploads/HkcMW0jPJl.png)
        * Ta nhận thấy chương trình đã thực thi hết các lệnh và thực hiện return vào địa chỉ 0x6161616161616161 và rõ ràng đây là một địa chỉ không hợp lệ. Và ta nhận thấy đây là chuỗi kĩ tự mà ta nhập vào.
        * Tiến hành phân tích chuỗi nhập vào bằng địa chỉ được leak ra của **result**:
        * ![{2FEA51E4-323C-43B2-ADC6-BB429660F972}](https://hackmd.io/_uploads/SyAoW0owke.png)
        * Ta thấy rằng thanh ghi rsp là thanh ghi đang trỏ đến địa chỉ mà hàm **main** return vào hiện đang trỏ đến 8 kí tự 'a' cuối cùng của chuỗi dữ liệu ta nhập vào. Vậy ta có thể tính được khoảng cách từ lúc bắt đầu nhập dữ liệu đến địa chỉ trả về của hàm là bằng 1040 - 8 = 1032.
* Với mục đích là cho chương trình return vào và thực thi shellcode ta nhập lên stack, ta tiến hành cho một payload gồm lượng kí tự bằng khoảng cách và cuối cùng là địa chỉ của stack.
* Ta nhận thấy ban đầu ta đã được biết trước địa chỉ của **result** và dữ liệu nhập vào cũng bắt đầu từ địa chỉ trên nên ta sẽ tiến hành nhập shellcode lên stack thông qua việc nhập shellcode vào rồi bù cho kích thước của payload bằng với khoảng cách và cuối cùng là địa chỉ của **return**.
* Ta tiến hành bổ sung shellcode vào script và thiết lập payload bắt đầu bằng shellcode. Ta chưa biết trước shellcode có kích thước bao nhiêu byte nên ta sẽ dùng *ljust* để bù vào một số lượng byte và ta cho ljust bù vào kí tự null byte với kích thước là bằng khoảng cách là 1032 byte.
![{38D1D55F-6025-4132-85F3-C6C569738F22}](https://hackmd.io/_uploads/r1_f30ovkg.png)
* Cuối cùng ta bổ sung vào là địa chỉ của **result**.
![{80AF9521-6031-4967-BE1B-605AE6D402C5}](https://hackmd.io/_uploads/BJsk2CsDke.png)
* Ta tiến hành chạy script:
![{132C587D-D4DE-43F3-8F0F-A86D2229AB11}](https://hackmd.io/_uploads/SJ8b0RjvJg.png)
* Vậy ta đã đọc được dữ liệu từ file `flag.txt` có nội dung "KCSC{test_flag}"
* Ta tiến hành kết nối với máy chủ để khai thác:
![{2716CDAC-2BC3-490B-90E7-680DA9552A2C}](https://hackmd.io/_uploads/rk1DARjP1x.png)
* Ta đã đọc thành công dữ liệu từ file `flag.txt` trên máy chủ và có có flag của challenge: 
`KCSC{_f3_deba3756312c79f925913b50cdd9b9}`
**=> Challenge hoàn thành**

**Cảm ơn vì đã đọc ạ ! Chúc các anh/chị một ngày tốt lành :D**