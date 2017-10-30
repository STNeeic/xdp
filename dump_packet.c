#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_TABLE("prog",int, int, prog_array, 8);
BPF_PERF_OUTPUT(events);


typedef enum {
  PRE_DUMP,
  PROCESS,
  POST_DUMP
} PROG_NUM;

#define IS_INVALID_ETH_HEADER(ptr, data_end, hdr) (ptr + sizeof(*hdr) > data_end)



int prog_entry(struct xdp_md *ctx)
{
  void* data = (void*)(long) ctx->data;
  void* data_end = (void*)(long) ctx->data_end;
  uint16_t h_proto;
  struct ethhdr *eth = data;


  //check ctx includes eth
  if(IS_INVALID_ETH_HEADER(data, data_end, eth)) {
    return XDP_PASS;
  }

  h_proto = eth->h_proto;

  if(h_proto == htons(ETH_P_IP) || h_proto == htons(ETH_P_IPV6)) {
    prog_array.call(ctx, (int) PRE_DUMP);
  }

  return XDP_PASS;
}

struct __attribute__ ((__packed__)) event {
  struct ethhdr eth;
  struct iphdr iph;
};

static __always_inline int dump_packet(struct xdp_md *ctx)
{
  // type of (ctx->data and ctx->data_end) are __u32.
  void* data = (void*)(long) ctx->data;
  void* data_end = (void*)(long) ctx->data_end;

  struct ethhdr* eth = data;
  struct event e_enter;
  if(eth + 1 > data_end) return XDP_DROP;
  memcpy(&e_enter, eth, sizeof(struct ethhdr));


  struct iphdr *iph = data + sizeof(struct ethhdr);
  if(iph + 1 > data_end) return XDP_DROP;
  memcpy((void*)&e_enter + sizeof(struct ethhdr), iph, sizeof(struct iphdr));

   events.perf_submit(ctx, &e_enter, sizeof(e_enter));



  return XDP_PASS;
}

int process(struct xdp_md *ctx)
{
  void* data = (void*)(long) ctx->data;
  void* data_end = (void*)(long) ctx->data_end;
  struct ethhdr* eth = data;
  if(eth + 1 > data_end) return XDP_DROP;
  eth->h_proto = 0x0081;
  prog_array.call(ctx, (int) POST_DUMP);
  return XDP_PASS;
}

int pre_dump_packet(struct xdp_md *ctx)
{
  dump_packet(ctx);
  prog_array.call(ctx, (int) PROCESS);
  return XDP_PASS;
}

int post_dump_packet(struct xdp_md *ctx)
{
  dump_packet(ctx);
  return XDP_PASS;
}
