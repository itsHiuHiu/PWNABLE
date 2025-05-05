---
title: 'KCSC Trainee Task 1: TEST SKILL BABYGOODS'

---

# KCSC Trainee Task 1: TEST SKILL BABYGOODS
![{E17CDCF0-A9B2-4D6F-8439-D432408AFC0F}](https://hackmd.io/_uploads/HkxRl7E9kl.png)

## IDA
Sử dụng công cụ IDA để dịch ngược đề bài ta thấy rằng:
* Bảng các hàm:
* ![{72F52A4D-D001-41BB-91DE-BA0DDBF26451}](https://hackmd.io/_uploads/ByedhQNqJx.png)
* Ta nhận thấy ngoài hàm main ta còn các hàm cần lưu ý như menu, exitshop, buildpram và sub_15210123.

* Ta phân tích hàm main:
> ![{DF4B5B93-7CEB-4639-A72F-0DF97EB7F216}](https://hackmd.io/_uploads/ryob6XV51x.png)
> Đầu tiên hàm thiết lập xóa các bộ nhớ đệm, sau đó in ra chuỗi "Enter your name: " và lấy 32 byte dữ liệu nhập vào biến toàn cục username. 
> Sau đó chương trình thực thi loại bỏ kí tự xuống dòng và kí tự quay về đầu dòng của chuỗi username và tiến hành gọi hàm menu với tham số là chuỗi username.
* Phân tích hàm menu:
> ![{654C6653-01F6-44D7-8478-922DB70C1CEA}](https://hackmd.io/_uploads/HJ73dH4c1g.png)
> Khai báo mảng kí tự s với 4 phần tử.
> Sau đó thực thi vòng lặp vô tận in ra các chuỗi có ý nghĩa xin chào và mời chọn 1.Build new pram hoặc 2 là exit.=))) 
> Hàm tiến hành nhận dữ liệu nhập vào là tùy chọn của ta (1 or 2) và xử lý xóa kí tự xuống dòng và quay về đầu dòng trong lựa chọn đó.
> Hàm tiến hành kiểm tra nếu lựa chọn là 1 thì gọi hàm buildpram, nếu là 2 thì gọi hàm exit shop, và nếu không thuộc trong 2 trường hợp đó thì in ra chuỗi " lựa chọn không hợp lệ " và gọi hàm menu với biến a1.
* Phân tích hàm buildpram:
> ![{6A33B4A5-FFC1-406C-80AD-CF0552EECBD4}](https://hackmd.io/_uploads/BJpWir4q1g.png)
> Khai báo các mảng kí tự s có 4 phần tử và v2 có 28 phần tử cùng với biến số nguyên v3.
> Sau đó hàm tiến hành cho ta nhập vào kích thước pram muốn khởi tạo và kích thước được lưu trong mảng s và sau đó được xóa kí tự xuống dòng và quay về đầu dòng.
> Gán biến v3 bằng giá trị số nguyên của mảng kí tự s.
> Thực thi điều kiện nếu 0 < v3 <= 5 thì thực thi việc nhập vào tên cho pram mới tạo và in ra màn hình thông tin về pram mới tạo và return.
> Nếu điều kiện không thỏa thì in chuỗi " kích thước không hợp lệ " và return.
* Phân tích hàm exitshop:
> ![{D7D14DC9-EA70-406B-89D5-FB72037D9DA8}](https://hackmd.io/_uploads/BJxi3HN9kl.png)
> Hàm chỉ thực hiện in ra lời chào cuối và exit.
* Phân tích hàm sub_15210123:
> ![{679A59AB-3D4A-4B97-8F8E-D2E6D917A7F7}](https://hackmd.io/_uploads/H1ga3S4qJl.png)
> Hàm thực thi lệnh hệ thống chạy /bin/sh tạo tiến trình con.

## Ý tưởng
* Ta nhận thấy rằng mục tiêu khai thác của ta là hàm sub_15210123 và ta cần điều khiển chương trình return vào hàm thông qua lỗ hỏng buffer overflow ta thấy ở bước đặt tên cho pram vì sử dụng gets để nhập liệu cho mảng v2 trong khi gets lấy vô hạn giá trị.

## Khai thác
* Ta sử dụng GDB để khảo sát dữ liệu đầu vào tại nơi có bug và kiểm tra các phương pháp bảo mật:
* Các phương pháp bảo mật:
> ![{415AD54F-E550-4E02-84C8-2024E70CBDA2}](https://hackmd.io/_uploads/ByLS0S4qJx.png)
> Ta cần lưu ý rằng Stack không có Canary điều này đồng nghĩa ta có thể khai thác lỗi tràn biến.
> No PIE có nghĩa rằng địa chỉ chương trình đang tĩnh.
* Bug tồn tại ở hàm buildpram tại gets nên ta tiến hành đặt breakpoint tại đó. Ta khảo sát stack đối với dữ liệu trước khi được nhập:
> ![{5C0B5280-499C-4D46-B2A1-4A193A2E9ABB}](https://hackmd.io/_uploads/Hkh1yUN9ye.png)
> Ta thấy rằng rbp đã bị trừ đi một khoảng để chứa dữ liệu nhập vào và ta sẽ tiến hành tạo một chuỗi 48 byte kí tự để khảo sát dữ liệu trên stack.
> ![{922FA95D-420D-4A6E-B5FD-5A2611966845}](https://hackmd.io/_uploads/BkNQlLNc1x.png)
> Sau khi nhập vào ta thấy rằng lúc này địa chỉ trả về đã bị ghi đè bằng chuỗi kí tự ta nhập vào và ta tìm được offset đến địa chỉ là 40 byte:
> ![{5FD1BF6E-E720-4D63-9407-084515340D49}](https://hackmd.io/_uploads/SJRvlL4c1e.png)
* Vậy lúc này ta viết script với dữ liệu nhập vào gồm 40 byte kí tự bất kì và 8 byte địa chỉ hàm sub_15210123:
>![{15A858B8-4AEA-49FF-9171-7303A52039D4}](https://hackmd.io/_uploads/BklinxLE5Jx.png)
* Ta tiến hành cho chạy thử chương trình và ta có shell, ta tiến hành lấy flag (em tự tạo cho zui ạ =)))):
![{E0A85385-0990-4192-AFFE-ECECB055BAD7}](https://hackmd.io/_uploads/HkobbU49kx.png)

KCSC_TRAINEE{_Nice_ret_2_win_bro!_}

=> Challenge hoàn thành ạ!


