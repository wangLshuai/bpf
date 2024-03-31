#!/usr/bin/env python
from bcc import BPF
bpf_source = """
#include <linux/bpf.h>
int do_sys_execve(struct pt_regs *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    bpf_trace_printk("executing program: %s",comm);
    return 0;
    
}
int ret_sys_execve(struct pt_regs *ctx)
{
    int return_value;
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    return_value = PT_REGS_RC(ctx);
    bpf_trace_printk("program:%s,return: %d",comm,return_value);
    return 0;
}
"""

bpf = BPF(text = bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event = execve_function,fn_name = "do_sys_execve")
bpf.attach_kretprobe(event=execve_function,fn_name="ret_sys_execve")
bpf.trace_print()
