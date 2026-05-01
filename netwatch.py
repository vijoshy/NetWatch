import argparse
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import (sniff, rdpcap, wrpcap,Ether, IP, IPv6, TCP, UDP, ICMP,ARP, DNS, Raw)
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich import box


console = Console()

captured_packets = []
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "dns": 0,
    "other": 0,
    "bytes": 0,
    "start_time": None,
}
flow_table = defaultdict(lambda: {"pkts": 0, "bytes": 0, "first": None, "last": None})
anomalies = []
running = True

def parse_packet(pkt):
    """Decode a packet and return a structured dict."""
    info = {
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "proto": "OTHER",
        "src": "?",
        "dst": "?",
        "sport": None,
        "dport": None,
        "length": len(pkt),
        "flags": "",
        "info": "",
    }

    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info["proto"] = "ARP"
        info["src"] = arp.psrc
        info["dst"] = arp.pdst
        op = "Who has" if arp.op == 1 else "Reply"
        info["info"] = f"{op} {arp.pdst} → {arp.psrc}"
        return info

    if pkt.haslayer(IP):
        ip = pkt[IP]
        info["src"] = ip.src
        info["dst"] = ip.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info["proto"] = "TCP"
            info["sport"] = tcp.sport
            info["dport"] = tcp.dport
            flags = []
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.P: flags.append("PSH")
            info["flags"] = " ".join(flags)
            info["info"] = f"{tcp.sport} → {tcp.dport}  [{info['flags']}]  Seq={tcp.seq}"

            if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
                info["proto"] = "HTTP"
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode(errors="replace")
                    first_line = payload.split("\r\n")[0][:60]
                    info["info"] = first_line

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info["proto"] = "UDP"
            info["sport"] = udp.sport
            info["dport"] = udp.dport
            info["info"] = f"{udp.sport} → {udp.dport}  Len={udp.len}"

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                info["proto"] = "DNS"
                if dns.qr == 0 and dns.qd:  # query
                    qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                    info["info"] = f"Query  {qname}"
                elif dns.qr == 1 and dns.an:  # response
                    qname = dns.qd.qname.decode(errors="replace").rstrip(".") if dns.qd else "?"
                    info["info"] = f"Reply  {qname}  ({dns.ancount} answers)"


        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            info["proto"] = "ICMP"
            icmp_types = {0: "Echo reply", 8: "Echo request", 3: "Dest unreachable",
                          11: "TTL exceeded", 5: "Redirect"}
            info["info"] = icmp_types.get(icmp.type, f"Type={icmp.type}")

    return info

def update_stats(info):
    stats["total"] += 1
    stats["bytes"] += info["length"]
    if stats["start_time"] is None:
        stats["start_time"] = time.time()

    proto = info["proto"].lower()
    if proto in stats:
        stats[proto] += 1
    else:
        stats["other"] += 1

    key = (info["src"], info["dst"], info.get("sport"), info.get("dport"), info["proto"])
    flow = flow_table[key]
    flow["pkts"] += 1
    flow["bytes"] += info["length"]
    now = time.time()
    if flow["first"] is None:
        flow["first"] = now
    flow["last"] = now

    detect_anomaly(info, flow, key)


def detect_anomaly(info, flow, key):
    """Simple heuristic anomaly detection."""
    src = info["src"]

    src_ports = {k[3] for k in flow_table if k[0] == src and k[4] == "TCP"}
    if len(src_ports) > 20:
        msg = f"[!] Possible port scan from {src} ({len(src_ports)} ports)"
        if msg not in anomalies:
            anomalies.append(msg)

    if "SYN" in info.get("flags", "") and "ACK" not in info.get("flags", ""):
        syn_flows = [k for k in flow_table if k[0] == src and k[4] == "TCP"]
        if len(syn_flows) > 30:
            msg = f"[!] Possible SYN flood from {src}"
            if msg not in anomalies:
                anomalies.append(msg)

    if info["length"] > 8000:
        msg = f"[!] Oversized packet ({info['length']} B) from {src}"
        if msg not in anomalies:
            anomalies.append(msg)

PROTO_COLORS = {
    "TCP":  "cyan",
    "UDP":  "yellow",
    "DNS":  "green",
    "HTTP": "blue",
    "ARP":  "magenta",
    "ICMP": "red",
    "OTHER": "white",
}


def build_packet_table(recent=30):
    t = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        expand=True,
        header_style="bold",
    )
    t.add_column("Time",     style="dim",    width=14)
    t.add_column("Proto",    width=6)
    t.add_column("Source",   width=22)
    t.add_column("Dest",     width=22)
    t.add_column("Len",      justify="right", width=6)
    t.add_column("Info",     ratio=1)

    for info in captured_packets[-recent:]:
        color = PROTO_COLORS.get(info["proto"], "white")
        src = f"{info['src']}:{info['sport']}" if info.get("sport") else info["src"]
        dst = f"{info['dst']}:{info['dport']}" if info.get("dport") else info["dst"]
        t.add_row(
            info["time"],
            Text(info["proto"], style=color),
            src,
            dst,
            str(info["length"]),
            info["info"],
        )
    return t


def build_stats_panel():
    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0
    pps = stats["total"] / elapsed if elapsed > 0 else 0
    bps = stats["bytes"] / elapsed if elapsed > 0 else 0

    lines = [
        f"[dim]Packets:[/]  [bold]{stats['total']}[/]   "
        f"[dim]Bytes:[/]  [bold]{stats['bytes']:,}[/]   "
        f"[dim]Rate:[/]  [bold]{pps:.1f} pkt/s  {bps/1024:.1f} KB/s[/]",
        "",
        f"  [cyan]TCP[/] {stats['tcp']}   "
        f"[yellow]UDP[/] {stats['udp']}   "
        f"[green]DNS[/] {stats['dns']}   "
        f"[red]ICMP[/] {stats['icmp']}   "
        f"[magenta]ARP[/] {stats['arp']}   "
        f"[white]Other[/] {stats['other']}",
    ]

    if anomalies:
        lines.append("")
        for a in anomalies[-3:]:
            lines.append(f"  [bold red]{a}[/]")

    return Panel("\n".join(lines), title="[bold]NetWatch[/]", subtitle="Ctrl+C to stop")


def build_flow_table(top=8):
    t = Table(box=box.SIMPLE_HEAD, show_edge=False, expand=True, header_style="bold")
    t.add_column("Flow",   ratio=1)
    t.add_column("Proto",  width=6)
    t.add_column("Pkts",   justify="right", width=7)
    t.add_column("Bytes",  justify="right", width=9)

    sorted_flows = sorted(flow_table.items(), key=lambda x: x[1]["bytes"], reverse=True)
    for (src, dst, sp, dp, proto), data in sorted_flows[:top]:
        src_s = f"{src}:{sp}" if sp else src
        dst_s = f"{dst}:{dp}" if dp else dst
        color = PROTO_COLORS.get(proto, "white")
        t.add_row(
            f"{src_s} → {dst_s}",
            Text(proto, style=color),
            str(data["pkts"]),
            f"{data['bytes']:,}",
        )
    return t


def render_live(live):
    layout = Layout()
    layout.split_column(
        Layout(build_stats_panel(), name="stats", size=6),
        Layout(name="main"),
    )
    layout["main"].split_row(
        Layout(Panel(build_packet_table(), title="Live packets", border_style="dim"), ratio=3),
        Layout(Panel(build_flow_table(), title="Top flows", border_style="dim"), ratio=2),
    )
    live.update(layout)

def packet_callback(pkt, live=None):
    info = parse_packet(pkt)
    captured_packets.append(info)
    update_stats(info)
    if live:
        render_live(live)


def print_summary():
    console.print()
    console.rule("[bold]Session summary[/]")

    t = Table(box=box.SIMPLE, show_edge=False)
    t.add_column("Metric", style="dim")
    t.add_column("Value",  style="bold")

    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0
    t.add_row("Duration",       f"{elapsed:.1f}s")
    t.add_row("Total packets",  str(stats["total"]))
    t.add_row("Total bytes",    f"{stats['bytes']:,}")
    t.add_row("Avg rate",       f"{stats['total']/elapsed:.1f} pkt/s" if elapsed else "—")
    t.add_row("TCP",            str(stats["tcp"]))
    t.add_row("UDP",            str(stats["udp"]))
    t.add_row("DNS",            str(stats["dns"]))
    t.add_row("ICMP",           str(stats["icmp"]))
    t.add_row("ARP",            str(stats["arp"]))
    t.add_row("Unique flows",   str(len(flow_table)))
    t.add_row("Anomalies",      str(len(anomalies)))

    console.print(t)

    if anomalies:
        console.print()
        console.print("[bold red]Anomalies detected:[/]")
        for a in anomalies:
            console.print(f"  {a}")


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch — Real-time Network Packet Sniffer & Protocol Analyzer"
    )
    parser.add_argument("-i", "--iface",  default=None,   help="Network interface (default: auto)")
    parser.add_argument("-f", "--filter", default=None,   help="BPF filter expression (e.g. 'tcp port 80')")
    parser.add_argument("-r", "--read",   default=None,   help="Read packets from .pcap file")
    parser.add_argument("-w", "--write",  default=None,   help="Save captured packets to .pcap file")
    parser.add_argument("-c", "--count",  default=0, type=int, help="Stop after N packets (0 = unlimited)")
    parser.add_argument("-s", "--stats",  action="store_true", help="Print summary stats on exit")
    args = parser.parse_args()

    def handle_sigint(sig, frame):
        global running
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    console.print(Panel.fit(
        "[bold cyan]NetWatch[/]  [dim]Network Packet Sniffer & Protocol Analyzer[/]",
        border_style="cyan"
    ))

    if args.read:
        console.print(f"[dim]Reading from [bold]{args.read}[/][/]")
        pkts = rdpcap(args.read)
        for pkt in pkts:
            packet_callback(pkt)
        print_summary()
        return

    console.print(
        f"[dim]Interface:[/] [bold]{args.iface or 'auto'}[/]  "
        f"[dim]Filter:[/] [bold]{args.filter or 'none'}[/]  "
        f"[dim]Count:[/] [bold]{'∞' if args.count == 0 else args.count}[/]"
    )
    console.print("[dim]Starting capture... (Ctrl+C to stop)[/]\n")

    with Live(console=console, refresh_per_second=4, screen=False) as live:
        try:
            sniff(
                iface=args.iface,
                filter=args.filter,
                count=args.count if args.count > 0 else 0,
                prn=lambda pkt: packet_callback(pkt, live),
                store=False,
            )
        except PermissionError:
            console.print("[bold red]Permission denied.[/] Run with sudo.")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error:[/] {e}")

    if args.write and captured_packets:
        console.print(f"\n[dim]Saving capture to [bold]{args.write}[/]...[/]")
        console.print("[yellow]Note:[/] Use -w with Scapy's wrpcap for raw packet saving.")

    if args.stats or True:
        print_summary()


if __name__ == "__main__":
    main()
