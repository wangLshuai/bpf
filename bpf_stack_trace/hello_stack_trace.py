#!/usr/bin/env python
from bcc import BPF,PerfType, PerfSWConfig
import sys
import signal
from time import sleep
import errno

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
struct trace_t {
    int stack_id;
};

BPF_HASH(cache, struct trace_t,u64);
BPF_STACK_TRACE(traces, 10000);
int collect_stack_traces(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != PROGRAM_PID)
        return 0;
        
    struct trace_t trace = {
        .stack_id = traces.get_stackid(&ctx->regs,BPF_F_USER_STACK),
    };
    cache.increment(trace);
    return 0;
}
    
    
    """

def signal_ignore(signal, frame):
    print()
    
       
program_pid = sys.argv[1]
bpf_source = bpf_source.replace('PROGRAM_PID',program_pid)
bpf = BPF(text=bpf_source)
bpf.attach_perf_event(ev_type = PerfType.SOFTWARE,ev_config = PerfSWConfig.CPU_CLOCK,
                      fn_name = 'collect_stack_traces',sample_freq=999)
cache = bpf.get_table('cache')
traces = bpf.get_table('traces')
try:
    sleep(999999999)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT,signal_ignore)

for trace,acc in sorted(cache.items(),key=lambda cache: cache[1].value):
    line = []
    if trace.stack_id < 0:
        line = ['Unknown stack']
    else:
        stack_trace = list(traces.walk(trace.stack_id))
        for stack_address in reversed(stack_trace):
            line.append(bpf.sym(stack_address,int(program_pid)).decode('utf-8'))
            
        frame = ";".join(line)
        print('%s %d' %(frame,acc.value))
