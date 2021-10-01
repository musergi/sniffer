#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "ethernet.h"
#include "ipv4.h"

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

    const ethernet_header_t *ethernet_header = ethernet_get_header(packet);
    char ethernet_source_str[64], ethernet_destination_str[64], ethertype_str[10];
    ethernet_address_str(ethernet_source_str, 64, ethernet_header->source_address);
    ethernet_address_str(ethernet_destination_str, 64, ethernet_header->destination_address);
    ethernet_ethertype_str(ethertype_str, 10, ethernet_header->ethertype);

    printf("[%ld] - Length: %u Recorded Length: %u\n", time, header->len, header->caplen);
    printf("Ethernet: %s -> %s Type: %s\n", ethernet_source_str, ethernet_destination_str, ethertype_str);

    if (ethernet_header->ethertype[0] == 0x08 && ethernet_header->ethertype[1] == 0x00)
    {
        const ipv4_header_t *ip_header = ipv4_get_header(ethernet_get_data(packet));
        const size_t addr_str_size = 4 * 3 + 4;
        char source_str[addr_str_size], destination_str[addr_str_size];
        ipv4_address_str(source_str, addr_str_size, ip_header->source);
        ipv4_address_str(destination_str, addr_str_size, ip_header->destination);
        printf("IP: %s -> %s Length:%u TTL: %u\n", source_str, destination_str, ip_header->length, ip_header->ttl);
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
        fprintf(stderr, "No device found.\n");
        return 1;
    }
    printf("%s\n", device);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open handle.\n");
        return 1;
    }
    pcap_loop(handle, 10, packet_callback, NULL);
    pcap_close(handle);
    return 0;
}