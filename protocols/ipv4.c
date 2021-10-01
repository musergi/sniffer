#include "ipv4.h"

bool ipv4_is(const ethernet_header_t *ethernet_header)
{
    return ethernet_header->ethertype[0] == 0x08 && ethernet_header->ethertype[1] == 0x00;
}

const ipv4_header_t *ipv4_get_header(const u_char *data)
{
    return (ipv4_header_t *)data;
}

void ipv4_address_str(char *str, size_t size, const struct in_addr address)
{
    char *converted = inet_ntoa(address);
    if (size < strlen(converted))
        return;
    strcpy(str, converted);
}