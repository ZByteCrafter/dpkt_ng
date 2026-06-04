# dpkt_ng

[![Python package](https://github.com/z935642417/dpkt_ng/workflows/Python%20package/badge.svg)](https://github.com/z935642417/dpkt_ng/actions)
[![supported-versions](https://img.shields.io/pypi/pyversions/dpkt.svg)](https://pypi.python.org/pypi/dpkt)

**dpkt_ng** is a fork of [dpkt](https://github.com/kbandla/dpkt) with extensive protocol expansions and advanced traffic analysis features. It provides fast, simple packet parsing with definitions for **90+ network protocols** and tools for TCP stream reassembly, file extraction, and route topology reconstruction.

## What's New vs. Upstream dpkt

| Category | Upstream dpkt | dpkt_ng |
|----------|--------------|---------|
| Protocol parsers | ~40 | **90+** |
| Routing protocols | BGP, RIP, OSPF (basic) | BGP, RIP, **OSPFv2/v3**, **EIGRP**, **IS-IS** |
| Wireless | 802.11 basic | 802.11 + **HE/EHT IE parsers** (Wi-Fi 6/7) |
| Modern transport | — | **QUIC**, **HTTP/3**, **QPACK** |
| Tunneling | GRE, PPP | GRE, PPP, **L2TP**, **VXLAN**, **GTPv1/v2** |
| File transfer | — | **FTP**, **TFTP**, **SMB1/SMB2** |
| Email | — | **SMTP**, **POP3**, **IMAP4rev1** |
| Advanced features | — | **TCP stream reassembly**, **file carving**, **route topology** |

## Installation

```bash
pip install dpkt
```

Or from source:

```bash
git clone https://github.com/z935642417/dpkt_ng.git
cd dpkt_ng
pip install -e .
```

## Quick Start

### Basic Packet Parsing

```python
import dpkt

# Parse Ethernet frame
eth = dpkt.ethernet.Ethernet(buf)
ip = eth.data
tcp = ip.data
print(f'{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}')
```

### TCP Stream Reassembly

```python
from dpkt.stream import StreamReassembler

reasm = StreamReassembler()

# Feed packets from pcap
with open('capture.pcap', 'rb') as f:
    reader = dpkt.pcap.Reader(f)
    reasm.feed_pcap(reader)

# Access reassembled connections
for conn_id, conn in reasm.connections.items():
    request = conn.c2s.get_data()
    response = conn.s2c.get_data()
```

### File Carving (Extract Files from Pcap)

```python
from dpkt.filecarver import FileCarver

carver = FileCarver()
carver.load_pcap('capture.pcap')
files = carver.carve()

for f in files:
    print(f'{f.filename} ({f.protocol}, {len(f.data)} bytes)')
    f.export('output/')
```

### Route Topology Reconstruction

```python
from dpkt.topology import TopologyBuilder

topo = TopologyBuilder()
topo.load_pcap('routing.pcap')
topo.build()

# Query routing information
for prefix in topo.prefixes:
    print(f'{prefix.network}/{prefix.mask} via {prefix.next_hop} ({prefix.protocol})')
```

### QUIC / HTTP/3 Parsing

```python
from dpkt.quic import QUIC, QUICKeys
from dpkt.http3 import Http3DataFrame

# Parse QUIC packet
pkt = QUIC(buf)

# With decryption keys (from SSLKEYLOGFILE)
keys = QUICKeys.from_sslkeylog('sslkeys.log')
dec = pkt.decrypt(keys)

# Parse HTTP/3 frames from QUIC payload
for frame in pkt.frames:
    if isinstance(frame, QUICCryptoFrame):
        for tls_rec in frame.tls_records:
            print(f'TLS {tls_rec.type}: {len(tls_rec.data)} bytes')
```

### Routing Protocol Analysis

```python
from dpkt.ospf import OSPF
from dpkt.eigrp import EIGRP
from dpkt.isis import ISIS

# Parse OSPF
ospf = OSPF(buf)
if isinstance(ospf.data, OSPFv2LSU):
    for lsa in ospf.data.lsas:
        print(f'LSA Type {lsa.type}: {lsa.id}')

# Parse EIGRP
eigrp = EIGRP(buf)
for tlv in eigrp.tlvs:
    print(f'EIGRP TLV Type={tlv.type}')

# Parse IS-IS
isis = ISIS(buf)
for tlv in isis.tlvs:
    print(f'IS-IS TLV Type={tlv.type}')
```

### Wireless (802.11 + IE Parsing)

```python
from dpkt.ieee80211 import IEEE80211
from dpkt.ieee80211_ie import unpack_ies, IEEE80211IERSN

# Parse 802.11 frame
wlan = IEEE80211(buf)

# Parse Information Elements
ies = unpack_ies(wlan.body)
for ie in ies:
    if isinstance(ie, IEEE80211IERSN):
        print(f'RSN v{ie.version}: {len(ie.pairwise)} cipher suites')
```

### SMB File Transfer Parsing

```python
from dpkt.smb import SMB
from dpkt.smb2 import SMB2
from dpkt.nbss import NBSS

# Parse SMB2
smb = SMB2(buf)
if hasattr(smb, 'data') and isinstance(smb.data, SMB2Read):
    print(f'Read: {len(smb.data.file_data)} bytes')
```

## Supported Protocols

### Layer 2
Ethernet, 802.11 (with HE/EHT IE), PPP, PPPoE, SLL, SLL2, Loopback, STP, DTP, CDP, LLCD, Radiotap

### Layer 3
IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP, AH, ESP, GRE, IPIP, IPX, VRRP, HSRP, VXLAN

### Routing
BGP, OSPF (v2/v3), EIGRP, IS-IS, RIP, MRT

### Transport
TCP, UDP, SCTP, RTP, RTCP, **QUIC** (RFC 9000)

### Application
HTTP, **HTTP/2**, **HTTP/3** (RFC 9114), DNS, DHCP, **SMTP**, **POP3**, **IMAP4rev1**, FTP, TFTP, SIP, SIP, NTP, SNMP, Telnet, BGP, RIP

### Tunneling
**L2TP** (RFC 2661), GRE, PPP, PPPoE, **GTPv1/v2** (3GPP), **VXLAN** (RFC 7348)

### File Transfer / SMB
**SMB1** (MS-CIFS), **SMB2** (MS-SMB2), **NBSS** (RFC 1002), **FTP** (RFC 959), **TFTP** (RFC 1350)

### Compression
**QPACK** (RFC 9204), gzip

### Wireless
IEEE 802.11 (a/b/g/n/ac/ax/be), Radiotap, **HE IEs** (Wi-Fi 6), **EHT IEs** (Wi-Fi 7)

### Security
SSL/TLS, RADIUS, Diameter, STUN, **QUIC Keys**

### Other
ASN.1, RPC, NetFlow, PIM, TFTP, AIM, Yahoo Messenger, QQ, RFB, SCCP, TNS

## Advanced Features

### TCP Stream Reassembly (`dpkt.stream`)
- Bidirectional connection tracking
- Out-of-order segment reassembly with overlap handling
- Gap filling and flush modes
- Callback-based data delivery

### File Carving (`dpkt.filecarver`)
- Extract files from HTTP, FTP, SMTP, POP3, IMAP, SMB traffic
- MIME email attachment extraction
- Configurable extraction rules

### Route Topology (`dpkt.topology`)
- OSPF network graph construction
- IS-IS adjacency discovery
- BGP AS path extraction
- EIGRP topology mapping
- Prefix aggregation and summarization

## Testing

```bash
# Run all tests
python -m pytest dpkt/ -v

# Run specific protocol tests
python -m pytest dpkt/ospf.py dpkt/eigrp.py dpkt/isis.py -v

# Run with coverage
python -m pytest dpkt/ --cov=dpkt --cov-report=html
```

## Documentation

- [API Reference](https://kbandla.github.io/dpkt)
- [Design Documents](docs/superpowers/specs/)
- [Implementation Plans](docs/superpowers/plans/)

## License

BSD License. See [LICENSE](LICENSE) for details.

## Credits

- Original dpkt by [Dug Song](https://github.com/dugsong) and contributors
- Fork maintained by [z935642417](https://github.com/z935642417)
