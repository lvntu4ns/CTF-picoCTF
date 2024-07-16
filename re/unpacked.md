## Unpacked
***Description*** : Can you get the flag?
Reverse engineer this binary.

***Hints*** : What is UPX?

***Solve*** 
* Download binary về và mở bằng IDA, ta thu được mã giả của file
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+14h] [rbp-3Ch] BYREF
  __int64 v5; // [rsp+18h] [rbp-38h]
  char v6[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  strcpy(v6, "A:4@r%uLFAmk0>b07fH0ff25`_f6N");
  printf("What's my favorite number? ");
  _isoc99_scanf("%d", &v4);
  if ( v4 == 754635 )
  {
    v5 = rotate_encrypt(0LL, v6);
    fputs(v5, stdout);
    putchar(10LL);
    free(v5);
  }
  else
  {
    puts("Sorry, that's not it!");
  }
  return 0;
}
```

* Dùng ROT47 để decode ta thu được flag `picoCTF{up><_m3_f7w_77ad107e}`
