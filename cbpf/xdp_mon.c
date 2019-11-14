#include "bpf_helpers.h"
//#include <linux/tcp.h>


// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdrv4 {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

 struct tcphdr {
   __u16 source;
   __u16 dest;
 } __attribute__((packed));

 struct records{
	__u64 rx_packets;
	__u64 rx_bytes;
  __u16 rx_tcp;
};

BPF_MAP_DEF(stats4) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct records),
    .max_entries = 16,
};
BPF_MAP_ADD(stats4)

BPF_MAP_DEF(subnets) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 16,
};
BPF_MAP_ADD(subnets);

BPF_MAP_DEF(tcpmap) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 255,
};
BPF_MAP_ADD(tcpmap);

static inline int proc_tcp(struct xdp_md *ctx, __u32 nh_off) {
  void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

  
  if (data + nh_off + sizeof(struct tcphdr) + 4 > data_end) {
     return XDP_DROP;
  }

  struct tcphdr *tcp = data + nh_off;
  if (tcp->dest == 22 || tcp->source == 22) {
    __u32 index = 0;
    __u64 *counter = bpf_map_lookup_elem(&tcpmap, &index);
    if (counter) {
      (*counter)++; 
    }
  }

  return XDP_PASS;
}

static inline int proc_packet_v4(struct xdp_md *ctx, __u32 nh_off) {
  void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

   struct iphdrv4 *ip = data + nh_off;
   if (data + nh_off + sizeof(*ip) > data_end) {
     return XDP_ABORTED;
   }


   __u64 *rule_idx = bpf_map_lookup_elem(&subnets, &ip->saddr);
   if (rule_idx){
    __u32 index = *(__u32*)rule_idx; 
    struct records *recs  = bpf_map_lookup_elem(&stats4, &index);
      if (recs) {

        recs->rx_packets++;
        recs->rx_bytes += data_end - data;

        nh_off += sizeof(*ip);

        if (ip->protocol == 6) {
          recs->rx_tcp++;
          return proc_tcp(ctx, nh_off);
        }

      }

   } 

  return XDP_PASS;
}

SEC("xdp")
int monitor(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  __u32 eth_proto = eth->h_proto;
  __u32 nh_off = sizeof(struct ethhdr);

  if (data + nh_off > data_end) {
    return XDP_DROP;
  }

  // none ipv4 packets
  if (eth_proto != 0x08U) {
    return XDP_PASS;
  }

  return proc_packet_v4(ctx, nh_off);
}



char _license[] SEC("license") = "GPLv2";
