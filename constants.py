

IEEE_SAPs = {
    0: 'Null LSAP',
    2: 'LLC Sublayer Management Function / Individual',
    3: 'LLC Sublayer Management Function / Group',
    6: 'IP (DoD Internet Protocol)',
    14: 'PROWAY (IEC 955) Network Management, Maintenance and Installation',
    66: 'BPDU (Bridge PDU / 802.1 Spanning Tree)',
    78: 'MMS (Manufacturing Message Service) EIA-RS 511',
    94: 'ISI IP',
    126: 'X.25 PLP (ISO 8208)',
    142: 'PROWAY (IEC 955) Active Station List Maintenance',
    170: 'SNAP (Sub-Network Access Protocol / non-IEEE SAPs)',
    224: 'IPX (Novell NetWare)',
    244: 'LAN Management',
    254: 'ISO Network Layer Protocol',
    255: 'Global DSAP',
}

ETHER_TYPES = {
    512: 'XEROX PUP',
    513: 'PUP Addr Trans',
    2048: 'Internet IP (IPv4)',
    2049: 'X.75 Internet',
    2053: 'X.25 Level 3',
    2054: 'ARP (Address Resolution Protocol)',
    32821: 'Reverse ARP',
    32923: 'AppleTalk',
    33011: 'AppleTalk AARP (Kinetics)',
    33024: 'IEEE 802.1Q VLAN-tagged frames',
    33079: 'Novell IPX',
    34525: 'IPv6',
    34827: 'PPP',
    34887: 'MPLS',
    34888: 'MPLS with upstream-assigned label',
    34915: 'PPPoE Discovery Stage',
    34916: 'PPPoE Session Stage',
}

IEEE_PID = {
    267: 'PVSTP+ (Per-VLAN Spanning Tree Plus)',
    768: 'XEROX NS IDP',
    8192: 'CDP',
    8196: 'DTP',
    12320: 'VTP',
}

PROTOCOLS = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    9: 'IGRP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    57: 'SKIP',
    80: 'HTTP',
    88: 'EIGRP',
    89: 'OSPF',
    115: 'L2TP',
    443: 'HTTPS',
    
}

UDP_PORTS = {
    7: 'echo',
    19: 'chargen',
    37: 'time',
    53: 'domain',
    67: 'bootps (DHCP)',
    68: 'bootpc (DHCP)',
    69: 'tftp',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    161: 'snmp',
    162: 'snmp-trap',
    500: 'isakmp',
    514: 'syslog',
    520: 'rip',
    33434: 'traceroute',
}

