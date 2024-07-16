## Packer
***Description*** : Reverse this linux executable?

***Hint*** : What can we do to reduce the size of a binary after compiling it.

***Solve*** 

* Dùng string để check các chuỗi có trong binary này.
```shell
└─$ strings out | tail
Z4u.
Z/-id%ABI-
a8s,
n`I C
ot      +da$
.bssh
?p! _
H_db
UPX!
UPX!
```
* Ở dòng cuối có thể thấy được file này được đóng gói bởi UPX. Unpack file này và thu được file ***out*** mới đã được unpack
```shell
└─$ upx -d out
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
[WARNING] bad b_info at 0x4b718

[WARNING] ... recovery at 0x4b714

    877724 <-    336520   38.34%   linux/amd64   out

Unpacked 1 file.
```
* Dùng strings để tìm chuỗi có flag, ta thu được 
```shell
└─$ strings out | grep "flag"
Password correct, please see flag: 7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f33373161613966667d
```
* Dùng base64 để decode và thu được flag
`picoCTF{U9X_UnP4ck1N6_B1n4Ri3S_371aa9ff}`
