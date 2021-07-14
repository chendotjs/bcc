from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
from bcc import tcp

# arguments
examples = """examples:
    ./tcpdrop           # trace kernel TCP drops
"""
parser = argparse.ArgumentParser(
    description="Trace TCP drops by the kernel",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_STACK_TRACE(stack_traces, 1024);

struct ipv4_data_t {
    u32 pid;
    int oif;
    int iif;
    u32 saddr;
    u32 daddr;
    u64 fl4addr;
    u32 stack_id;
};
BPF_PERF_OUTPUT(ipv4_events);

int trace_fib_table_lookup(struct pt_regs *ctx, struct fib_table *tb, struct flowi4 *flp)
{
    if (flp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid();

    if (true) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.oif = flp->flowi4_oif;
        data4.iif = flp->flowi4_iif;
        data4.saddr = flp->saddr;
        data4.daddr = flp->daddr;
        data4.fl4addr = (unsigned long long)flp;
        data4.stack_id = stack_traces.get_stackid(ctx, 0);
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } 

    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    saddr = inet_ntop(AF_INET, pack('I', event.saddr))
    daddr = inet_ntop(AF_INET, pack('I', event.daddr))
    if (daddr != "8.8.8.8"):
        return
    print("%-8s %-6d %-2d %-2d %-20s > %-20s %ld" % (
        strftime("%H:%M:%S"), event.pid, 
         event.oif, event.iif,
         saddr, daddr,
         event.fl4addr,
         ))
    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)
    print("")

# initialize BPF
b = BPF(text=bpf_text)
if b.get_kprobe_functions(b"fib_table_lookup"):
    b.attach_kprobe(event="fib_table_lookup", fn_name="trace_fib_table_lookup")
else:
    print("ERROR: fib_table_lookup() kernel function not found or traceable. "
        "Older kernel versions not supported.")
    exit()
stack_traces = b.get_table("stack_traces")

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
