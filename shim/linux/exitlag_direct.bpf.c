// SPDX-License-Identifier: GPL-2.0-or-later
// cgroup/sock_create hook: sockets created by processes listed in direct_pids get
// SO_MARK = BYPASS (0xff). The exitlag_nf_redir nft table returns early on that
// mark, so those sockets go out directly through the kernel instead of being
// TPROXY'd into exitlag-nf-redir. exitlag-nf-redir fills the map with native
// Linux processes that ExitLag does not need to see (browser, Discord, ...).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MARK_BYPASS 0xff

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // tgid (= /proc pid)
    __type(value, __u8);
} direct_pids SEC(".maps");

SEC("cgroup/sock_create")
int mark_direct(struct bpf_sock *sk)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&direct_pids, &tgid))
        sk->mark = MARK_BYPASS;
    return 1;  // always allow socket creation
}

char LICENSE[] SEC("license") = "GPL";
