#include <stdio.h>
#include <string.h>
#include <pcap.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
typedef struct ethernet_packet
{
    u_char destination[ETHER_ADDR_LEN];
    u_char source[ETHER_ADDR_LEN];
    u_char ethertype[2];
} ethernet_packet_t;

/* IP header */
typedef struct ip_packet
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
} ip_packet_t;

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

void ethernet_format_address(char *out, u_char *address)
{
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (i != ETHER_ADDR_LEN - 1)
            sprintf(out + i * 3, "%02x:", address[i]);
        else
            sprintf(out + i * 3, "%02x", address[i]);
    }
}

void ip_format_address(char *out, struct in_addr address)
{
    char *converted = inet_ntoa(address);
    strcpy(out, converted);
}

void packet_callback(u_char *args, const struct pcap_pkthdr *header,
                     const u_char *packet)
{
    static long int first_arrival_sec = 0;
    static u_char is_first = 1;
    if (is_first)
    {
        first_arrival_sec = header->ts.tv_sec;
        is_first = 0;
    }

    const long time = header->ts.tv_sec - first_arrival_sec;

    ethernet_packet_t *ethernet_packet = (ethernet_packet_t *)packet;
    char ethernet_source_str[64], ethernet_destination_str[64];
    ethernet_format_address(ethernet_source_str, ethernet_packet->source);
    ethernet_format_address(ethernet_destination_str, ethernet_packet->destination);

    printf("[%ld] - Length: %u Recorded Length: %u\n", time, header->len, header->caplen);
    printf("Ethernet: %s -> %s Type: 0x%02x%02x\n", ethernet_source_str, ethernet_destination_str, ethernet_packet->ethertype[0], ethernet_packet->ethertype[1]);

    if (ethernet_packet->ethertype[0] == 0x08 && ethernet_packet->ethertype[1] == 0x00)
    {
        ip_packet_t *ip_packet = (ip_packet_t *)(packet + sizeof(ethernet_packet_t));
        char source_str[4 * 3 + 4], destination_str[4 * 3 + 4];
        ip_format_address(source_str, ip_packet->ip_src);
        ip_format_address(destination_str, ip_packet->ip_dst);
        printf("IP: %s -> %s Length:%u TTL: %u\n", source_str, destination_str, ip_packet->ip_len, ip_packet->ip_ttl);
    }

    printf("\n");
}

int main()
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        fprintf(stderr, "No device found.");
        return 1;
    }
    printf("%s\n", device);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open handle.");
        return 1;
    }
    pcap_loop(handle, 10, packet_callback, NULL);
    pcap_close(handle);
    return 0;
}