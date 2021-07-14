# Author: chenyaqi
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
    ./inet_select_addr
"""
parser = argparse.ArgumentParser(
    description="trace inet_select_addr",
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
//#include <include/netdevice.h>
#include <bcc/proto.h>

BPF_STACK_TRACE(stack_traces, 1024);

struct ipv4_data_t {
    u32 pid;
    char ifname[IFNAMSIZ];
    u32 dst;
    u32 scope;
    u32 src;
    u32 stack_id;
};

BPF_PERF_OUTPUT(ipv4_events);
BPF_HASH(ipv4_events_hash, u32, struct ipv4_data_t);


int kprobe__inet_select_addr(struct pt_regs *ctx, struct net_device *dev, __be32 dst, int scope) {
    u32 pid = bpf_get_current_pid_tgid();

    struct ipv4_data_t data = {
        .pid = pid,
        .dst = dst,
        .scope = scope,
    };

    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), dev->name);
    data.stack_id = stack_traces.get_stackid(ctx, 0);

    ipv4_events_hash.update(&pid, &data);
    return 0;
}

int kretprobe__inet_select_addr(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    struct ipv4_data_t *data = ipv4_events_hash.lookup(&pid);
    if (data == NULL) {
        return 0; // missed entry
    }
    ipv4_events_hash.delete(&pid);

    data->src = PT_REGS_RC(ctx);
    ipv4_events.perf_submit(ctx, data, sizeof(struct ipv4_data_t));

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
    print("%-8s %-6d %-30s %-20s %s ==> %-20s" % (
        strftime("%H:%M:%S"),
        event.pid,
        event.ifname,
        inet_ntop(AF_INET, pack('I', event.dst)),
        scope_map(event.scope),
        inet_ntop(AF_INET, pack('I', event.src)),
    ))
    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)
    print("")


# from rtnetlink.h
def scope_map(scope):
    return {
        0: 'RT_SCOPE_UNIVERSE',
        200: 'RT_SCOPE_SITE',
        253: 'RT_SCOPE_LINK',
        254: 'RT_SCOPE_HOST',
        255: 'RT_SCOPE_NOWHERE',
    }[scope]


# initialize BPF
b = BPF(text=bpf_text)

stack_traces = b.get_table("stack_traces")

# print header
print("%-8s %-6s %-30s %-20s %s ==> %-20s" % (
    'TIME',
    'PID',
    'IFNAME',
    'DST',
    'SCOPE',
    'SELECTED SRC',
))
# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
