#!/usr/bin/env python
from bcc import BPF,USDT
bpf_source = """
#include <uapi/linux/ptrace.h>
BPF_HASH(cache,u64,u64);
int trace_main_exec(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 start_time_ns = bpf_ktime_get_ns();
    cache.update(&pid,&start_time_ns);
    return 0;
}
int print_duration(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 * start_time_ns = cache.lookup(&pid);
    if ( start_time_ns == NULL)
        return 0;
        
    u64 duration_ns = bpf_ktime_get_ns() - * start_time_ns;
    bpf_trace_printk("Function call duration:%d",duration_ns);
    return 0;
}
"""

usdt = USDT(path = "./hello_usdt")
usdt.enable_probe(probe="probe-main",fn_name = "trace_main_exec")
usdt.enable_probe(probe="retprobe-main",fn_name = "print_duration")
bpf = BPF(text = bpf_source,usdt_contexts=[usdt])
bpf.trace_print()