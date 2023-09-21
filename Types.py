types = {
    2048: "IPv4",
    2049: "",
    2053: "",
    2054: "ARP",
    32821: "Reverse ARP",
    32923: "Appletalk",
    33011: "Appletalk AARP",
    33024: "",
    33079: "",
    34525: "IPv6",
    34827: "PPP",
    34887: "MPLS",
    34888: "",
    34915: "",
    34916: ""
}

"""
2048:Internet IP (IPv4)
2049:X.75 Internet
2053:X.25 Level 3
2054:ARP (Address Resolution Protocol)
32821:Reverse ARP
32923:Appletalk
33011:AppleTalk AARP (Kinetics)
33024:IEEE 802.1Q VLAN-tagged frames
33079:Novell IPX
34525:IPv6
34827:PPP
34887:MPLS
34888:MPLS wit upstream-assigned label
34915:PPPoE Discovery Stage
34916:PPPoE Session Stage
"""


etherTypes = {
    2054 : "ARP",
    2048 : "IPv4",
    35020 : "LLDP",
    34525 : "IPv6",
    36864 : "ECTP"
}

ipv4Protocol = {
    1 : "ICMP",
    2 : "IGMP",
    6 : "TCP",
    17 : "UDP",
    43: "PIM"
}

tcpProtocol = {
    20: "FTP-DATA",
    21: "FTP-CONTROL",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    137: "NETBIOS-NS",
    139: "NETBIOS-SSN",
    143: "IMAP",
    162: "SNMP-TRAP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    514: "SYSLOG",
    17500: "DB-LSP-DISC"
}

udpProtocol = {
    37: "TIME",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    161: "SNMP",
    162: "SNMP-TRAP",
    443: "HTTPS",
    512: "SYSLOG",
    520: "RIP",
    1900: "SSDP",
    5353: "MDNS",
    17500: "DB-LSP-DISC",
    33434: "TRACEROUTE"
}
pids = {
    8192: "CDP",
    8196: "DTP",
    267: "PVSTP+",
    32923: "AppleTalk"
}
saps = {
    66: "STP",
    224: "IPX",
    240: "NETBIOS"
}