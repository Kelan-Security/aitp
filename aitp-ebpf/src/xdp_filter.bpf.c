/*
 * XDP packet filter for AITP — eBPF enforcement layer.
 */

#include "common.h"

#if defined(__linux__) && __has_include(<linux/bpf.h>)
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#else
/* Portable fallbacks for non-Linux/IDE environments */
#define XDP_PASS 2
#define XDP_DROP 1
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#ifndef bpf_htons
static inline __u16 bpf_htons(__u16 x) { return (x << 8) | (x >> 8); }
#endif

struct xdp_md {
  __u32 data;
  __u32 data_end;
};
struct ethhdr {
  __u16 h_proto;
};
struct iphdr {
  __u8 ihl;
  __u8 protocol;
};
struct udphdr {
  __u16 dest;
};

#ifndef bpf_map_lookup_elem
static inline void *bpf_map_lookup_elem(void *map, void *key) { return 0; }
#endif
#endif

#define AITP_PORT 9999

/* eBPF hash map: session_id → permit_entry. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, struct permit_entry);
} permit_map SEC(".maps");

/* Packet drop counter (per-CPU array for performance). */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} drop_counter SEC(".maps");

SEC("xdp")
int aitp_xdp_filter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  /* Parse Ethernet header */
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  /* Only process IPv4 */
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  /* Parse IP header */
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  /* Only process UDP */
  if (ip->protocol != IPPROTO_UDP)
    return XDP_PASS;

  /* Parse UDP header */
  struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
  if ((void *)(udp + 1) > data_end)
    return XDP_PASS;

  /* Check destination port */
  if (udp->dest != bpf_htons(AITP_PORT))
    return XDP_PASS;

  /* Extract session_id (offset 3 of AITP header, 8 bytes) */
  __u8 *aitp_payload = (void *)(udp + 1);
  if ((void *)(aitp_payload + 11) > data_end)
    return XDP_DROP;

  __u64 session_id = 0;
#pragma unroll
  for (int i = 0; i < 8; i++) {
    session_id = (session_id << 8) | aitp_payload[3 + i];
  }

  /* Look up in permit map */
  struct permit_entry *permit = bpf_map_lookup_elem(&permit_map, &session_id);
  if (permit) {
    /* Optional: Add expiration check if bpf_ktime_get_real_ns is available.
     * For now, we rely on user-space cleanup for maximum compatibility. */
    return XDP_PASS;
  }

  /* No permit — drop and increment counter */
  __u32 key = 0;
  __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
  if (counter)
    __sync_fetch_and_add(counter, 1);

  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
