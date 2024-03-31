#include <stdint.h>
#include <stdio.h>
#include <time.h>

int main()
{
    time_t t1=0,t2=0;
    uint64_t j = 1;
    for(;t2-t1<2;t1=time(NULL),t2=time(NULL)){
        for (int i=0;i<1000000;i++)
        {
            j=j*i;
        }
    }
    printf("%ld,%ld\n",t1,t2);
    return 0;
}