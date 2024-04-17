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
Header data of the packet will display timestamp, source and destination info in various forms (for IPv4 protocol it is ip address, for IPv6 protocol it is IPv6 address) with MAC addresses.

Below will be displayed packet itself in form where:
- First part represents content of the packet in hexadecimal form.
- Second - ASCII form of each hexadecimal value in the first part.

### Protocols
Sniffer works with limitted amount of protocols. Such as:

#### IPv4
##### TCP
TCP packets are used for reliable, ordered, and error-checked
delivery of data between applications over an IP network. TCP packets operate
at the Transport layer (Layer 4) of the OSI model.

##### UDP
UDP is a transport protocol used for sending data over IP networks. It is a connectionless protocol that does not guarantee reliable delivery of data or error checking. Mostly it is used in cases when amount of data is more required than its quality (such as streaming)

##### ICMPv4
ICMPv4 is used for diagnostics and error checking only.
There is no such concept as 'port' for this type of protocol, additionaly
it operates within layer 3, while the ports are at layer 4 of OSI. For generating such traffic people usually use `ping <ip>`.

##### IGMP
IGMP protocol operates at network layer 3 of the OSI model, while ports are associated with layer 4 (transport level). IGMP is a network layer protocol used to set up multicasting on networks that use the Internet Protocol version 4 (IPv4)

#### ARP
ARP is a protocol used to map a network address
to a physical address. It has its limitations - it works only in local enviroment

#### IPv6
IPv6 is the most recent version of the Internet Protocol, designed to eventually replace IPv4.

##### NDP
NDP is a protocol in IPv6 that is used to
discover and maintain information about other nodes on the same link.NDP does not use ports, instead they use message type just like ICMPv6

##### MLD
MLD operates at the network layer (Layer 3) of the OSI model, and does not use any ports like transport layer protocols such as TCP or UDP.

##### ICMPv6
ICMPv6 is a protocol that operates at the network layer (Layer 3) of the OSI model, just like MLD. ICMPv6 messages are sent and received using IPv6 protocol, and do not use ports. ICMPv6 messages are identified by their message type field, which is part of the ICMPv6 header in the IPv6 packet.

## Testing
For testing I have used [wireshark](https://www.wireshark.org/) in order to compare incoming packets and its content with IPK sniffer.

Additionally testing edge cases were used to see if sniffer works as expected.

## Bibliography
[PCAP tutorial in C. How to create sniffer](https://www.tcpdump.org/pcap.html)
[TCP/IP layers, IPv4 protocols. Header format](https://book.huihoo.com/iptables-tutorial/c171.htm)
[IPv6 protocols and how they work](https://www.spiceworks.com/tech/networking/articles/what-is-ipv6/)
