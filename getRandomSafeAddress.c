#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() 
{
    void *ptr = NULL;
   
    if (posix_memalign(&ptr, 8, sizeof(int)) != 0) 
    {
        perror("posix_memalign failed");
        return 1;
    }

    int *target = (int *)ptr;
    *target = 123;

    printf("PID: %d\n", getpid());
    printf("Heap-allocated address: %p\n", (void*)target);

    printf("Press ENTER after setting the watchpoint (echo address to sysfs or use insmod)...\n");
    getchar();  

    *target = 456;
    printf("New value: %d\n", *target);
    free(target);
    return 0;
}
