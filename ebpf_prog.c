#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#define VPN_PORT 9000


BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 256);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}


static inline int parse_udp(void *data, u64 nh_off, void *data_end) {
  struct udphdr *udph = data + nh_off;
  if((void*) &udph[1] > data_end)
    return 0;
  return udph->dest;
}

static inline int mv_ethhdr(void *data, u64 dst, void *data_end) {
  struct ethhdr *eth = data;
  struct ethhdr *eth_dst = data + dst;
  if(data + dst + sizeof(struct ethhdr) > data_end) return 0;
  eth_dst->h_dest[0] = eth->h_dest[0];
  eth_dst->h_dest[1] = eth->h_dest[1];
  eth_dst->h_dest[2] = eth->h_dest[2];
  eth_dst->h_dest[3] = eth->h_dest[3];
  eth_dst->h_dest[4] = eth->h_dest[4];
  eth_dst->h_dest[5] = eth->h_dest[5];
  eth_dst->h_source[0] = eth->h_source[0];
  eth_dst->h_source[1] = eth->h_source[1];
  eth_dst->h_source[2] = eth->h_source[2];
  eth_dst->h_source[3] = eth->h_source[3];
  eth_dst->h_source[4] = eth->h_source[4];
  eth_dst->h_source[5] = eth->h_source[5];
  eth_dst->h_proto = eth->h_proto;
  return 1;
}

int xdp_prog1(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
      return rc;
    //parse ether header
    h_proto = eth->h_proto;

    // care vlan header
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    //parse ip header
    if (h_proto == htons(ETH_P_IP)) {
      index = parse_ipv4(data, nh_off, data_end);
      nh_off += sizeof(struct iphdr);
    }
    else if (h_proto == htons(ETH_P_IPV6)) {
       index = parse_ipv6(data, nh_off, data_end);
       nh_off += sizeof(struct ipv6hdr);
    }
    else
        index = 0;

    if(index == 17) { //udp protocol
      h_proto = parse_udp(data, nh_off, data_end);

      if(h_proto == htons(VPN_PORT)) {
        nh_off +=  sizeof(struct udphdr);
        //It must be VPN encapsulated packet. let's decapsulate it!
        //mv_ethhdr(data, nh_off, data_end);
        bpf_xdp_adjust_head(ctx, nh_off);
        data_end = (void*)(long)ctx->data_end;
        data = (void*)(long)ctx->data;
        eth = data;
        if((void *)&eth[1] <= data_end)
          h_proto = eth->h_proto;
        else {
          h_proto = 114;
        }
      }
    }


    value = dropcnt.lookup(&index);
    if (value)
      *value = ntohs(h_proto);
    return rc;
}
