#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <signal.h>

#define BUFFER_INTERACE_LENGTH 1024
#define BUFFER_FILTER_LENGTH 4096
#define BUFFER_MAC_LENGTH 18
#define TIME_LENGTH 1024
#define ETHER_SIZE 14
#define ETH_ALEN 6

/* 
    Author: Nikita Koliada
    Date: 2024-04-17
*/


// Function to print an error message and exit the program
void error(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

// Structure to hold the command-line options
struct Config
{
    char interface[BUFFER_INTERACE_LENGTH];
    int tcp;
    int udp;
    int port;
    int port_source;
    int port_destination;
    int arp;
    int icmp4;
    int icmp6;
    int igmp;
    int mld;
    int ndp;
    int num_packets;
} typedef Config;

// Function to initialize the configuration structure
void init_config(struct Config *cfg)
{
    cfg->tcp = 0;
    cfg->udp = 0;
    cfg->port = -1; // -1 indicates no port filter
    cfg->port_source = -1;
    cfg->port_destination = -1;
    cfg->arp = 0;
    cfg->icmp4 = 0;
    cfg->icmp6 = 0;
    cfg->igmp = 0;
    cfg->mld = 0;
    cfg->ndp = 0;
    cfg->num_packets = 1; // Default to 1 packet if -n is not specified
}

// Print usage information
void usage(char *program_name)
{
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -i, --interface=INTERFACE    Set the interface to sniff\n");
    printf("  -t, --tcp                    Capture TCP segments\n");
    printf("  -u, --udp                    Capture UDP datagrams\n");
    printf("  -p, --port=PORT              Filter TCP/UDP packets by port\n");
    printf("  --port-source=PORT           Filter TCP/UDP packets by source port\n");
    printf("  --port-destination=PORT      Filter TCP/UDP packets by destination port\n");
    printf("  --arp                        Capture ARP frames\n");
    printf("  --icmp4                      Capture ICMPv4 packets\n");
    printf("  --icmp6                      Capture ICMPv6 packets\n");
    printf("  --igmp                       Capture IGMP packets\n");
    printf("  --mld                        Capture MLD packets\n");
    printf("  --ndp                        Capture NDP packets\n");
    printf("  -n NUM                       Number of packets to capture\n");
}

pcap_if_t *get_network_interfaces()
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get the list of network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        error("pcap_findalldevs() failed: %s\n", errbuf);
    }

    return alldevs;
}

void print_network_interfaces()
{
    // Get the list of network interfaces
    pcap_if_t *item = get_network_interfaces();

    // Print the list of network interfaces
    while (item)
    {
        printf("%s\n", item->name);
        item = item->next;
    }

    // Free the allocated memory
    pcap_freealldevs(item);
    exit(EXIT_SUCCESS);
}

void free_allocations(pcap_if_t *alldevs, pcap_t *handle)
{
    if (alldevs != NULL)
    {
        pcap_freealldevs(alldevs);
    }
    if (handle != NULL)
    {
        pcap_close(handle);
    }
}
Config parse_args(int argc, char *argv[])
{
    int opt;
    Config config;
    init_config(&config);

    if (argc == 2 && strcmp(argv[1], "-i") == 0)
    {
        print_network_interfaces();
        exit(EXIT_SUCCESS);
    }

    const struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"help", no_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"port-source", required_argument, 0, 1},
        {"port-destination", required_argument, 0, 2},
        {"arp", no_argument, 0, 3},
        {"icmp4", no_argument, 0, 4},
        {"icmp6", no_argument, 0, 5},
        {"igmp", no_argument, 0, 6},
        {"mld", no_argument, 0, 7},
        {"ndp", no_argument, 0, 8},
        {"n", required_argument, 0, 'n'},
        {0, 0, 0, 0}};

    // Parse the command-line options
    while ((opt = getopt_long(argc, argv, "i:p:n:tuh", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'i':
            strcpy(config.interface, optarg);
            break;
        case 't':
            config.tcp = 1;
            break;
        case 'u':
            config.udp = 1;
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 1:
            config.port_source = atoi(optarg);
            break;
        case 2:
            config.port_destination = atoi(optarg);
            break;
        case 3:
            config.arp = 1;
            break;
        case 4:
            config.icmp4 = 1;
            break;
        case 5:
            config.icmp6 = 1;
            break;
        case 6:
            config.igmp = 1;
            break;
        case 7:
            config.mld = 1;
            break;
        case 8:
            config.ndp = 1;
            break;
        case 'n':
            config.num_packets = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case '?':
            // TODO check if it's the only arg
            if (optopt == 'i')
            {
                print_network_interfaces();
            }
            if (optopt)
            {
                error("Option \'%c\' is invalid. Type --help or -h for help", optopt);
            }
            else
            {
                error("Arguments are not valid. Type --help or -h for help");
            }
            break;
        default:
            error("Unrecognized option. Type --help or -h for help");
            break;
        }
    }

    // if no filters were set, set all of them
    if (!(config.tcp || config.udp || config.arp || config.icmp4 || config.icmp6 || config.igmp || config.mld || config.ndp))
    {
        config.tcp = 1;
        config.udp = 1;
        config.arp = 1;
        config.icmp4 = 1;
        config.icmp6 = 1;
        config.igmp = 1;
        config.mld = 1;
        config.ndp = 1;
    }

    return config;
}

void write_filter_exp(char *filter_exp, Config config)
{
    char *ptr = filter_exp;
    int written = 0;

    // Write the filter expression based on the configuration
    // The filter expression is a combination of the selected protocols and ports
    if (config.tcp || config.udp)
    {
        if (config.tcp)
        {
            char *filter = "tcp";
            if (config.port != -1)
            {
                ptr += sprintf(ptr, (written++ == 0) ? "(%s port %d)" : " or (%s port %d)", filter, config.port);
            }
            else if (config.port_source != -1 || config.port_destination != -1)
            {
                if (config.port_source != -1 && config.port_destination != -1)
                {
                    ptr += sprintf(ptr, (written++ == 0) ? "(%s src port %d and %s dst port %d)" : " or (%s src port %d and %s dst port %d)", filter, config.port_source, filter, config.port_destination);
                }
                else
                {
                    if (config.port_source != -1)
                    {
                        ptr += sprintf(ptr, (written++ == 0) ? "(%s src port %d)" : " or (%s src port %d)", filter, config.port_source);
                    }
                    if (config.port_destination != -1)
                    {
                        ptr += sprintf(ptr, (written++ == 0) ? "(%s dst port %d)" : " or (%s dst port %d)", filter, config.port_destination);
                    }
                }
            }
            else
            {
                ptr += sprintf(ptr, (written++ == 0) ? "%s" : " or %s", filter);
            }
        }
        if (config.udp)
        {
            char *filter = "udp";
            if (config.port != -1)
            {
                ptr += sprintf(ptr, (written++ == 0) ? "(%s port %d)" : " or (%s port %d)", filter, config.port);
            }
            else if (config.port_source != -1 || config.port_destination != -1)
            {
                if (config.port_source != -1 && config.port_destination != -1)
                {
                    ptr += sprintf(ptr, (written++ == 0) ? "(%s src port %d and %s dst port %d)" : " or (%s src port %d and %s dst port %d)", filter, config.port_source, filter, config.port_destination);
                }
                else
                {
                    if (config.port_source != -1)
                    {
                        ptr += sprintf(ptr, (written++ == 0) ? "(%s src port %d)" : " or (%s src port %d)", filter, config.port_source);
                    }
                    if (config.port_destination != -1)
                    {
                        ptr += sprintf(ptr, (written++ == 0) ? "(%s dst port %d)" : " or (%s dst port %d)", filter, config.port_destination);
                    }
                }
            }
            else
            {
                ptr += sprintf(ptr, (written++ == 0) ? "%s" : " or %s", filter);
            }
        }
    }
    if (config.arp)
    {
        ptr += sprintf(ptr, (written++ == 0) ? "arp" : " or arp");
    }

    if (config.icmp4)
    {
        ptr += sprintf(ptr, (written++ == 0) ? "icmp" : " or icmp");
    }

    if (config.icmp6)
    {
        ptr += sprintf(ptr, (written++ == 0) ? "icmp6" : " or icmp6");
    }

    if (config.igmp)
    {
        ptr += sprintf(ptr, (written++ == 0) ? "igmp" : " or igmp");
    }

    if (config.mld)
    {
        ptr += sprintf(ptr, (written++ == 0) ? "(icmp6 and icmp6[0] >= 130 and icmp6[0] <= 132)" : " or (icmp6 and icmp6[0] >= 130 and icmp6[0] <= 132)");
    }

    if (config.ndp)
    {
        ptr += sprintf(ptr, (written++ == 0) ? "(icmp6 and icmp6[0] >= 133 and icmp6 and icmp6[0] <= 136)" : " or (icmp6 and icmp6[0] >= 133 and icmp6 and icmp6[0] <= 136)");
    }
}

char *convert_to_rfc3339(const struct pcap_pkthdr *packet_header)
{
    if (!packet_header)
        return NULL;

    // Allocate memory for the output RFC 3339 formatted string
    char *formatted_time = malloc(TIME_LENGTH);
    if (!formatted_time)
        return NULL;

    // Extract and convert time
    struct tm *local_time = localtime(&packet_header->ts.tv_sec);
    char date_time[30];
    strftime(date_time, sizeof(date_time), "%Y-%m-%dT%H:%M:%S", local_time);

    // Format microseconds and timezone offset
    int millisec = packet_header->ts.tv_usec / 1000;
    long timezone_offset = local_time->tm_gmtoff;
    int hours_offset = timezone_offset / 3600;
    int minutes_offset = (timezone_offset % 3600) / 60;

    snprintf(formatted_time, TIME_LENGTH, "%s.%03d%+03d:%02d", date_time, millisec, hours_offset, minutes_offset);

    return formatted_time;
}
char *bytes_to_hex(uint8_t *bytes)
{
    // Dynamically allocating memory to hold address string.
    char *hex = malloc(BUFFER_MAC_LENGTH);
    if (hex == NULL)
    {
        return NULL;
    }
    hex[0] = '\0'; //  start with an empty string.

    int pos = 0; // keep track of the current position in the hex string.

    for (int i = 0; i < ETH_ALEN; i++)
    {
        // sprintf returns the number of characters written
        pos += sprintf(&hex[pos], (i < ETH_ALEN - 1 ? "%02x:" : "%02x"), bytes[i]);
    }
    return hex;
}

void display_packet_contents(const unsigned char *data, int len)
{
    for (int line = 0; line < len; line += 16)
    {
        printf("\n0x%04x: ", line);

        // Print hex values
        int line_end = line + 16;
        for (int pos = line; pos < line_end; pos++)
        {
            if (pos < len)
                printf("%02x ", data[pos]);
            else
                printf("   ");
        }

        // Print ASCII representation
        printf(" ");
        for (int pos = line; pos < line_end && pos < len; pos++)
        {
            unsigned char char_val = data[pos];
            printf("%c", isprint(char_val) ? char_val : '.');
        }
    }
    printf("\n");
}

void procces_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet; // packet header

    // Print the packet information
    printf("\n\n");

    printf("timestamp: %s\n", convert_to_rfc3339(header));
    printf("src MAC: %s\n", bytes_to_hex(eth_header->ether_shost)); 
    printf("dst MAC: %s\n", bytes_to_hex(eth_header->ether_dhost)); 
    printf("frame length: %d bytes\n", header->caplen);

    // Check if the packet is an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip_header = (struct ip *)(packet + ETHER_SIZE); // ipv4 header
        printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_SIZE + ip_header->ip_hl * 4); // tcp header
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_SIZE + ip_header->ip_hl * 4); // udp header
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
        else
        {
            // in other cases, there woulb no such thing as 'port'
        }
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
    {
        struct ether_arp *arp_header = (struct ether_arp *)(packet + ETHER_SIZE); // arp header
        printf("src IP: %s\n", inet_ntoa(*(struct in_addr *)arp_header->arp_spa));
        printf("dst IP: %s\n", inet_ntoa(*(struct in_addr *)arp_header->arp_tpa));
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)
    {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_SIZE); // ipv6 header
        char src_ip6[INET6_ADDRSTRLEN];
        char dst_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip6, INET6_ADDRSTRLEN);
        printf("src IP: %s\n", src_ip6);
        printf("dst IP: %s\n", dst_ip6);
    }
    else
    {
        // in other cases, no other type is supproted
    }
    display_packet_contents(packet, header->caplen);
}

int main(int argc, char *argv[])
{
    Config config = parse_args(argc, argv);
    if (optind < argc)
    {
        error("Option \'%s\' is not valid", argv[optind]);
    }
    if (strlen(config.interface) == 0)
    {
        print_network_interfaces();
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *alldevs;
    alldevs = get_network_interfaces();

    struct bpf_program fp;
    char filter_exp[256];

    write_filter_exp(filter_exp, config);

    pcap_t *handle = pcap_open_live(config.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        free_allocations(alldevs, handle);
        error("Couldn't open device %s: %s\n", config.interface, errbuf);
    }

    // Compile the filter expression

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        free_allocations(alldevs, handle);
        error("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        free_allocations(alldevs, handle);
        error("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }

    // Start capturing packets
    if (pcap_loop(handle, config.num_packets, procces_packet, NULL) < 0)
    {
        free_allocations(alldevs, handle);
        error("pcap_loop() failed: %s\n", pcap_geterr(handle));
    }

    // Close the handle and free the allocated alldevs
    free_allocations(alldevs, handle);

    return 0;
}
