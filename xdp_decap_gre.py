from bcc import BPF
import sys
if len(sys.argv) != 2:
    print("Usage: {0} [netdev]\n".format(sys.argv[0]))
    exit(1)


device = sys.argv[1]

bpf = BPF(src_file="dump_packet.c")

process = bpf.load_func("process", BPF.XDP)



bpf.attach_xdp(device, process)

while 1:
    bpf.kprobe_poll()
