#include "ethernet.h"

const ethernet_header_t *ethernet_get_header(const u_char *data)
{
    return (ethernet_header_t *)data;
}

const u_char *ethernet_get_data(const u_char *data)
{
    return data + sizeof(ethernet_header_t);
}

void ethernet_address_str(char *str, size_t size, const u_char *address)
{
    if (size < ETHERNET_ADDRESS_SIZE * 3)
        return;
    for (int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
    {
        if (i > 0)
            str += sprintf(str, ":");
        str += sprintf(str, "%02x", address[i]);
    }
}

void ethernet_ethertype_str(char *str, size_t size, const u_char *ethertype)
{
    if (size < 7)
        return;
    unsigned short type = ((unsigned short)ethertype[0] << 8) + ethertype[1];
    switch (type)
    {
    case ETHERTYPE_IPV4:
        sprintf(str, "IPv4");
        break;
    case ETHERTYPE_IPV6:
        sprintf(str, "IPv6");
        break;
    case ETHERTYPE_ARP:
        sprintf(str, "ARP");
        break;

    default:
        sprintf(str, "0x%04x", type);
        break;
    }
}