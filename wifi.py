from scapy.all import ARP, Ether, srp, conf, get_working_if
import socket
import argparse
import urllib.request
import json
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel

console = Console()
conf.L3socket = conf.L3socket

def get_mac_vendor(mac_address):
    """Asks a public API who manufactured the Wi-Fi chip using the MAC address."""
    try:
        # We use a free API to lookup the OUI (first 3 pairs of the MAC)
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode())
            if data.get('success') and data.get('company'):
                return data['company']
    except Exception:
        pass
    return None

def get_netbios_name_socket(ip):
    netbios_request = (
        b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x00\x00\x21\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.2)
            s.sendto(netbios_request, (ip, 137))
            data, _ = s.recvfrom(1024)
            if len(data) > 56 and data[56] > 0:
                return data[57:57+15].decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
    return None

def scan_network(network_ip):
    interfaces = conf.ifaces.values()
    for iface in interfaces:
        if iface.ip and iface.ip.startswith("192.168.1."):
            conf.iface = iface
            break
    else:
        conf.iface = get_working_if()
    
    init_info = f"[bold cyan]Target Subnet:[/bold cyan] {'.'.join(network_ip.split('.')[:3])}.0/24"
    console.print(Panel(init_info, title="[bold green]System Initialized[/bold green]", border_style="green", expand=False))

    clean_ip = ".".join(network_ip.split(".")[:3])
    ip_range = f"{clean_ip}.0/24"

    with console.status("[bold yellow]Running ARP Broadcast...[/bold yellow]", spinner="bouncingBar"):
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(broadcast / arp_request, timeout=2, inter=0.1, verbose=0)

    devices = []
    
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, complete_style="green"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Identifying Devices...", total=len(answered))
        
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.upper()
            
            progress.update(task, description=f"[cyan]Identifying [bold]{ip}[/bold]...")
            
            hostname = None
            if ip == conf.iface.ip:
                hostname = socket.gethostname()
            
            if not hostname:
                hostname = get_netbios_name_socket(ip)
                
            if not hostname:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    pass

            # IF THE DEVICE IS HIDING ITS NAME, LOOK UP ITS HARDWARE VENDOR
            if not hostname:
                vendor = get_mac_vendor(mac)
                if vendor:
                    hostname = f"[{vendor}] Device"
                elif ip.endswith(".1"):
                    hostname = "Network Router / Gateway"
                else:
                    hostname = "Unknown/Masked Hardware"

            devices.append({'IP': ip, 'MAC': mac, 'Hostname': hostname})
            progress.advance(task)

    return devices

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Professional Network Discovery Tool.')
    parser.add_argument('network_ip', type=str, help='The base IP address to scan.')
    args = parser.parse_args()

    results = scan_network(args.network_ip)

    if results:
        table = Table(title="\nActive Subnet Discovery Mapping", title_style="bold white", header_style="bold bright_white on blue", show_lines=True)
        table.add_column("IP Address", style="bright_green", justify="left")
        table.add_column("MAC Address", style="bright_yellow", justify="center")
        table.add_column("Device Identity / Manufacturer", style="bright_white", justify="left")

        for dev in results:
            table.add_row(dev['IP'], dev['MAC'], dev['Hostname'])

        console.print(table)
