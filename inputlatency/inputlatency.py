#!/usr/bin/env python

from bcc import BPF
import argparse
import subprocess

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/input.h>
struct status{
    char flag;
    char comm[64];
    u64 pid;
    u32 fd;
    u64 start_read_time_ns;
    char *buf;
};
BPF_HASH(status_hash,u64,struct status);
int input_handle_event_probe(struct pt_regs *ctx){
    u64 input_time_ns = bpf_ktime_get_ns();
    u32 type = PT_REGS_PARM2(ctx);
    u32 code = PT_REGS_PARM3(ctx);
    u32 value = PT_REGS_PARM4(ctx);
    char *active;
    if (type == EV_KEY)
    {
        if ( value == 1)
        {
            bpf_trace_printk("\\n\\n************************");
            bpf_trace_printk("key code:%lu pushed",code);
        }else {
            bpf_trace_printk("key code:%lu release",code);
        }
        
    }
    return 0;
}
int ksys_read_probe(struct pt_regs *ctx,u32 fd) {
    struct status s = {};
    bpf_get_current_comm(&s.comm,sizeof(s.comm));
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid>>32;
    

    s.fd = fd;
    s.flag=0;

    u32 fd2 = PT_REGS_PARM1(ctx);
    if (pid == PID )
    {
        s.flag=1;
        s.start_read_time_ns = bpf_ktime_get_ns();
        s.fd = fd;
        s.pid = pid;
        status_hash.update(&pid,&s);
    }
    
    
    return 0;
}
int ksys_read_ret_probe(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid >> 32;
    ssize_t ret = PT_REGS_RC(ctx);
    struct status * s = status_hash.lookup(&pid);
    if ( s && s->flag)
    {
        u64 readed_time_ns = bpf_ktime_get_ns();
        bpf_trace_printk("read fd:%d %lu byte",s->fd,ret);
        status_hash.delete(&pid);
    }
    
    return 0;
}



int ksys_write_probe(struct pt_regs *ctx,u32 fd,void *buf,size_t count)
{
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid >>32;
    if (pid == PID)
    {
        u64 write_time = bpf_ktime_get_ns();
        bpf_trace_printk("write fd:%u size_t:%u",fd,count);
    }
    return 0;
}


"""
parser = argparse.ArgumentParser(description="trace terminal simulator key input event",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="./inputlatency -p 340")
parser.add_argument("-p","--pid",help="trace this PID only")
args = parser.parse_args()

if args.pid:
    print(args.pid)
else:
    print("usage: ps -ef |grep gnome-terminal-server\n\
./inputlatency -p [terminal-simulator-pid]")
    exit(1)

bpf_source=bpf_source.replace("PID",args.pid)
bpf = BPF(text=bpf_source)
bpf.attach_kprobe(event="input_handle_event",fn_name="input_handle_event_probe")

bpf.attach_kprobe(event="ksys_read",fn_name="ksys_read_probe")
bpf.attach_kretprobe(event="ksys_read",fn_name="ksys_read_ret_probe")
bpf.attach_kprobe(event="ksys_write",fn_name="ksys_write_probe")


bpf.trace_print()