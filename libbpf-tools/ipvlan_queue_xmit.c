#include <errno.h>
#include <unistd.h>

#include "ipvlan_queue_xmit.skel.h"
#include "map_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
  int err;
  struct ipvlan_queue_xmit_bpf *obj;

  libbpf_set_print(libbpf_print_fn);
  err = bump_memlock_rlimit();
  if (err) {
    warn("failed to increase rlimit: %s\n", strerror(errno));
    return 1;
  }

  obj = ipvlan_queue_xmit_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

  err = ipvlan_queue_xmit_bpf__load(obj);
  	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

  err = ipvlan_queue_xmit_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

  while (1) {
    sleep(1);
  }

cleanup:
  ipvlan_queue_xmit_bpf__destroy(obj);

  return 0;
}