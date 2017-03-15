#include <stdio.h>
#include <stdint.h>

int main()
{
    uint32_t data = 0;

    printf("data: 0x%lx\n", (uint64_t)data);
    printf("executing rdseed...\n");

    asm volatile("rdseed %0" : "=eax"(data));

    printf("data: 0x%lx\n", (uint64_t)data);
}
