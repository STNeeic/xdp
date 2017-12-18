from bcc import BPF
import sys
import ctypes as ct

class ETHHDR(ct.Structure):
    _fields_ = [
        ("h_dest", ct.c_ubyte * 6),
        ("h_source", ct.c_ubyte * 6),
        ("h_proto", ct.c_ubyte * 2)
    ]

class EthernetHeader:
    """Interface of ETHHDR"""
    def __init__(self, ethhdr):
        self.ethhdr = ethhdr
    def ub2hex(self, ub):
        hexlist = map(lambda x: "{0:0>2X}".format(x), ub)
        return " ".join(hexlist)
    def __str__(self):
        h_dest = self.ub2hex(self.ethhdr.h_dest)
        h_source = self.ub2hex(self.ethhdr.h_source)
        h_proto = self.ub2hex(self.ethhdr.h_proto)
        return "ETHHDR\nh_dest  :{0}\nh_source:{1}\nh_proto :{2}\n".format(h_dest, h_source, h_proto)



class IPHDR(ct.Structure):
    """ipv4 header for little endian cpus"""
    _fields_ = [
        ("ihl_version", ct.c_ubyte),
        ("tos", ct.c_ubyte),
        ##the following elements are __be16
        ##but __be16 doesn't exist in ctypes
        ##thus I use c_utype * 2
        ("tot_len", ct.c_ubyte * 2),
        ("myid", ct.c_ubyte * 2), #id is reserved
        ("frag_off", ct.c_ubyte * 2),

        ("ttl", ct.c_ubyte),
        ("protocol", ct.c_ubyte),
        ("check", ct.c_ubyte * 2),
        ("saddr", ct.c_ubyte * 4),
        ("daddr", ct.c_ubyte * 4)
    ]

class IPv4Header:
    """Interface for IPHDR"""
    def __init__(self,iphdr):
        self.iphdr = iphdr
    def ub2hex(self, cb):
        "similarly htons"
        return " ".join(map(lambda x:"{:0>2X}".format(x),cb))

    def strIpv4(self, addr_array):
        return ".".join(map(lambda x: "{}".format(x), addr_array))

    def __str__(self):
        iphdr = self.iphdr
        version = (iphdr.ihl_version & 0xf0) >> 4
        ihl = iphdr.ihl_version & 0x0f
        tos = iphdr.tos
        tot_len = self.ub2hex(iphdr.tot_len)
        myid = self.ub2hex(iphdr.myid)
        frag_off = self.ub2hex(iphdr.frag_off)
        ttl = iphdr.ttl
        protocol = iphdr.protocol
        check = self.ub2hex(iphdr.check)
        saddr = self.strIpv4(iphdr.saddr)
        daddr = self.strIpv4(iphdr.daddr)
        out = """\
IPv4 Header
 version:{0}
     ihl:{1}
     tos:{2:0=#8b}
 tot_len:{3}
      id:{4}
frag_off:{5}
     ttl:{6}
protocol:{7}
   check:{8}
   saddr:{9}
   daddr:{10}
""".format(version,ihl,tos,tot_len,myid,frag_off,ttl,protocol,check,saddr,daddr)
        return out


class GRE_BASE_HDR(ct.Structure):
    _fields_ = [
        ("flags", ct.c_ubyte * 2),
        ("protocol", ct.c_ubyte * 2)
    ]

class GRE_Header:
    def __init__(self, grehdr):
        self.grehdr = grehdr
    def ub2hex(self, cb):
        "similarly htons"
        return " ".join(map(lambda x:"{:0>2X}".format(x),cb))
    def has_checksum(self):
        return self.grehdr.flags & 0x8000 > 0
    def has_key(self):
        return self.grehdr.flags & 0x2000 > 0
    def has_sequence_num(self):
        return self.grehdr.flags & 0x1000 > 0
    def version(self):
        return self.grehdr.flags & 0x0007

    def __str__(self):
        grehdr = self.grehdr
        has_checksum = "1(has checksum)" if self.has_checksum() else "0(hasn't checksum)"
        has_key = "1(has key)" if self.has_key() else "0(hasn't key)"
        has_sequence = "1(has sequence)" if self.has_sequence_num() else "0(hasn't sequence)"
        version = self.version()
        protocol = self.ub2hex(grehdr.protocol)
        out = """\
GRE Header
About optional sequence:
\tchecksum:\t{0}
\tkey:\t{1}
\tsequence:\t{2}
version:\t{3}
protocol:\t{4}
""".format(has_checksum,has_key,has_sequence,version,protocol)
        return out


class HEADERS(ct.Structure):
    _fields_ = [
        ("ethhdr", ETHHDR),
        ("iphdr", IPHDR)
    ]

class HEADERS_with_GRE(ct.Structure):
    _fields_ = [
        ("ethhdr", ETHHDR),
        ("iphdr", IPHDR),
        ("grehdr", GRE_BASE_HDR),
        ("iphdr", IPHDR)
    ]

class Event:
    def __init__(self, data):
        "it needs data from perf buffer"
        self.event = ct.cast(data, ct.POINTER(HEADERS)).contents
        self.eth = EthernetHeader(self.event.ethhdr)
        self.iph = IPv4Header(self.event.iphdr)

    def __str__(self):
        return str(self.eth) + str(self.iph)






def print_event(cpu, data, size):
    event = Event(data)
    print(event)


if len(sys.argv) != 2:
    print("Usage: {0} [netdev]\n".format(sys.argv[0]))
    exit(1)


device = sys.argv[1]

bpf = BPF(src_file="dump_packet.c")

events = bpf["events"]
events.open_perf_buffer(print_event)

prog_entry = bpf.load_func("prog_entry", BPF.XDP)
pre_dump_packet = bpf.load_func("pre_dump_packet", BPF.XDP)
process = bpf.load_func("process_then_jump", BPF.XDP)
post_dump_packet = bpf.load_func("post_dump_packet", BPF.XDP)


prog_array = bpf["prog_array"]

prog_array[0] = pre_dump_packet.fd
prog_array[1] = process.fd
prog_array[2] = post_dump_packet.fd

bpf.attach_xdp(device, prog_entry)

while 1:
    bpf.kprobe_poll()
