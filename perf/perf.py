#!/usr/bin/env python
from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>
struct data_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);
int do_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    data.pid = bpf_get_current_pid_tgid()>>32;
    events.perf_submit(ctx,&data,sizeof(data));
    return 0;
}
"""

bpf = BPF(text = bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event = execve_function,fn_name = "do_sys_execve")
aggregates = Counter()

def aggregate_programs(cpu,data,size):
    event = bpf.get_table("events").event(data)
    print("%d %d %d"%(cpu,data,size),"  ",event.pid," ",event.comm)
bpf["events"].open_perf_buffer(aggregate_programs)
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

