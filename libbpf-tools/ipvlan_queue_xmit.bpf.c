#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define	IFNAMSIZ	16

#ifndef printt
# define printt(fmt, ...)						\
	({								\
		char ____fmt[] = fmt;					\
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);	\
	})
#endif


static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
	return skb->head + skb->mac_header;
}


SEC("kprobe/ipvlan_queue_xmit")
int BPF_KPROBE(ipvlan_queue_xmit, struct sk_buff *skb, struct net_device *dev) {
  struct ethhdr eth = {};
  char ifname[IFNAMSIZ];

  unsigned char *head = BPF_CORE_READ(skb, head);
  int mac_header = BPF_CORE_READ(skb, mac_header);

  bpf_core_read(&eth, sizeof(eth),  head + mac_header);
  bpf_probe_read_str(ifname, IFNAMSIZ, dev->name);

  for (int i = 0; i < 6; i++) {
    printt("%d: %x %x\n", i, eth.h_dest[i], eth.h_source[i]);
  }
  printt("xmit dev: %s\n", ifname);
  printt("--------\n");

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
