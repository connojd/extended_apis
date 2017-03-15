#include <stdio.h>
#include <stdint.h>

int main()
{
    uint64_t data = 0;

    printf("data: 0x%lx\n", (uint64_t)data);
    printf("executing rdrand...\n");

    asm volatile("rdrand %0" : "=rax"(data));

    printf("data: 0x%lx\n", (uint64_t)data);
}
