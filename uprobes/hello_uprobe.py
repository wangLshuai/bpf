#!/usr/bin/env python
from bcc import BPF
bpf_source = """

BPF_HASH(cache, u64, u64);
int trace_start_main(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 start_time_ns = bpf_ktime_get_ns();
    cache.update(&pid,&start_time_ns);
   // bpf_trace_printk("New hello-bpf process running with PID:%d",pid);
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

bpf = BPF(text = bpf_source)
bpf.attach_uprobe(name = "./hello_uprobe",sym="main",fn_name="trace_start_main")
bpf.attach_uretprobe(name = "./hello_uprobe",sym = "main",fn_name="print_duration")
bpf.trace_print()