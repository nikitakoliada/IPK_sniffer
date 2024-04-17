Author: Nikita Koliada

## IPK Sniffer

The IPK sniffer is a C-based network sniffer. It can capture and analyze network IPv4, IPv6 and ARP packets of various types on a specified network interface.

### Installation
> **Note!**
The program is made for UNIX-based systems only. In other cases the sniffer won't work.

To install the sniffer program, follow these steps:
1. Download the source code from the repository.
2. Compile the source code using Makefile:
```bash
make
```
3. Run the program (launch example)
```bash
./ipk-sniffer -i en0
```

- `ipk-sniffer` is the name of the sniffer program that will be created after `make`.
- `-i` option stands for **interface** sniffer captures packets from.

Program will start and print out first packet that it captures.

### Usage

```bash
./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```

- `-i interface` or `--interface interface`, where **interface** is network interface sniffer will listen to. If **interface** is not specified then the program will print list of available interfaces on user's device.
- `-p port` will filter captured packets by port. If this option is not set - all ports are considered.
- `--port-source` will filter captured packets by port source.
- `--port-destination` will filter captured packets by port destination.
- `-t` or `--tcp` will show only TCP packets.
- `-u` or `--idp` will show only UDP packets.
- `--icmp4` will show only ICMPv4 packets.
- `--icmp6` will display only ICMPv6 echo request/response.
- `--arp` will display only ARP frames.
- `--ndp` will display only ICMPv6 NDP packets.
- `--igmp` will display only IGMP packets
- `--mld` will display only MLD packets.
If none protocols are specified for filtering - all protocols are considered.
- `-n N` where (N >= 0). It limits the amout of packets that should be captured by sniffer. By defailt its value is 1 (one packet).
### Output
Capture packet will have the following form:
```bash
timestamp: 2024-04-14T17:34:03.676+02:00
src MAC: cc:08:fa:a7:73:9c
dst MAC: e2:94:67:c1:4d:b4
frame length: 109 bytes
src IP: 192.168.137.48
dst IP: 35.186.224.34
src port: 58673
dst port: 443

0x0000: e2 94 67 c1 4d b4 cc 08 fa a7 73 9c 08 00 45 00  ..g.M.....s...E.
0x0010: 00 5f 00 00 40 00 40 06 ec e3 c0 a8 89 30 23 ba  ._..@.@......0#.
0x0020: e0 22 e5 31 01 bb b5 07 21 e1 72 48 1b 12 80 18  .".1....!.rH....
0x0030: 08 00 f7 d7 00 00 01 01 08 0a 6e 46 ca 5c 7e 3a  ..........nF.\~:
0x0040: 22 8a 17 03 03 00 26 31 63 dd de 22 c6 f1 8c 42  ".....&1c.."...B
0x0050: a0 c1 7b 99 f1 78 6c 14 0b 13 6d 7c 42 8f 9f ee  ..{..xl...m|B...
0x0060: 0b 7f 51 23 d7 ea a9 d6 26 47 ec 5a 69           ..Q#....&G.Zi
```
Packet headers include timestamp details as well as source and destination information, which are formatted as IP addresses for both IPv4 and IPv6 protocols, along with the MAC addresses.

The packet content itself is presented in two formats:
- The first section displays the packet's content in hexadecimal form.
- The second section shows the ASCII representation of each hexadecimal value.

### Supported Protocols
The sniffer supports a limited range of protocols:

#### IPv4
##### TCP
TCP (Transmission Control Protocol) is designed for reliable, ordered, and error-checked data delivery between applications on an IP network. It functions at the Transport layer (Layer 4) of the OSI model.

##### UDP
UDP (User Datagram Protocol) is used for transmitting data over IP networks without establishing a connection, prioritizing speed over reliability. It is often used for applications where speed is critical, such as video streaming.

##### ICMPv4
ICMPv4 (Internet Control Message Protocol version 4) is utilized primarily for network diagnostics and error reporting. It operates at the Network layer (Layer 3) of the OSI model, and does not utilize ports.

##### IGMP
IGMP (Internet Group Management Protocol) is used for organizing multicast groups in IPv4 networks. It operates at the Network layer (Layer 3).

#### ARP
ARP (Address Resolution Protocol) maps network addresses to physical addresses but is limited to local networks only.

#### IPv6
IPv6 is the latest version of the Internet Protocol, set to eventually supersede IPv4.

##### NDP
NDP (Neighbor Discovery Protocol) is analogous to ARP but for IPv6. It helps in discovering and maintaining information about other network nodes without using ports, using message types instead.

##### MLD
MLD (Multicast Listener Discovery) is used for managing multicast group memberships in IPv6 networks, functioning at the Network layer (Layer 3).

##### ICMPv6
Like its IPv4 counterpart, ICMPv6 (Internet Control Message Protocol version 6) is used for network diagnostics and error reporting in IPv6 networks. It also operates at the Network layer and identifies messages by type rather than ports.

## Testing
For testing I have used [wireshark](https://www.wireshark.org/) in order to compare incoming packets and its content with IPK sniffer.

Additionally testing edge cases were used to see if sniffer works as expected.

## Bibliography
[PCAP tutorial in C. How to create sniffer](https://www.tcpdump.org/pcap.html)
[TCP/IP layers, IPv4 protocols. Header format](https://book.huihoo.com/iptables-tutorial/c171.htm)
[IPv6 protocols and how they work](https://www.spiceworks.com/tech/networking/articles/what-is-ipv6/)
