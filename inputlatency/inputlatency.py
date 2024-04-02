#!/usr/bin/env python

from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
struct status{
    char flag;
    int fd;
};
BPF_HASH(status_hash,u64,struct status);
int hid_input_report_exec(struct pt_regs *ctx){
    u64 input_time_ns = bpf_ktime_get_ns();
    u32 type = PT_REGS_PARM2(ctx);
    u32 code = PT_REGS_PARM3(ctx);
    u32 value = PT_REGS_PARM4(ctx);
    bpf_trace_printk("report be calld time ns:%u type:%u code:%u ",input_time_ns,type,code);
    bpf_trace_printk("value:%d",value);
    return 0;
}
int read_event(struct pt_regs *ctx,int fd) {
    char comm[64];
    bpf_get_current_comm(&comm,sizeof(comm));
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid>>32;
    struct status s = {};
   
    s.fd = fd;
    s.flag=0;
 
   
    u32 fd2 = PT_REGS_PARM1(ctx);
    if (fd == 35)
    {
        s.flag=1;
        bpf_trace_printk("command :%s pid %d ",comm,pid);
        bpf_trace_printk("read fd:%d",fd);
    }
     status_hash.update(&pid,&s);
    
   return 0;
}
int read_ret_event(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid >> 32;
    ssize_t ret = PT_REGS_RC(ctx);
     struct status * s = status_hash.lookup(&pid);
     if ( s && s->flag)
     {
        bpf_trace_printk("read %d byte",ret);
    }
    return 0;
}

int vfs_read_event(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid >> 32;
    if (pid == 2243618)
    {
        u64 read_time = bpf_ktime_get_ns();
        bpf_trace_printk("in time %lu pid:%d",read_time, pid);
    }
    return 0;
}
"""

bpf = BPF(text=bpf_source)
# bpf.attach_kprobe(event="input_handle_event",fn_name="hid_input_report_exec")
read_function = bpf.get_syscall_fnname("read")
print(read_function)

# bpf.attach_kprobe(event="ksys_read",fn_name="read_event")
# bpf.attach_kretprobe(event="ksys_read",fn_name="read_ret_event")
bpf.attach_kprobe(event="vfs_read",fn_name="vfs_read_event")




bpf.trace_print()