#include <sys/sdt.h>
#include <stdio.h>

int main() {
    DTRACE_PROBE("hello-usdt",probe-main);
    printf("hello,bpf\n");
    DTRACE_PROBE("hello-usdt", retprobe-main);
    return 0;
}