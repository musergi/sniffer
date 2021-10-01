#ifndef PROTOCOLS_IPV4_H
#define PROTOCOLS_IPV4_H

#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include "ethernet.h"

/**
 * @brief Masks to get particular flags or fields in the offset bytes.
 */
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* don't fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

/**
 * @brief IPv4 header struct.
 */
typedef struct ipv4_header
{
    u_char vhl;                         /* version << 4 | header length >> 2 */
    u_char tos;                         /* type of service */
    u_short length;                     /* total length */
    u_short id;                         /* identification */
    u_short offset;                     /* fragment offset field */
    u_char ttl;                         /* time to live */
    u_char protocol;                    /* protocol */
    u_short checksum;                   /* checksum */
    struct in_addr source, destination; /* source and dest address */
} ipv4_header_t;

bool ipv4_is(const ethernet_header_t *ethernet_header);
const ipv4_header_t *ipv4_get_header(const u_char *data);
void ipv4_address_str(char *str, size_t size, const struct in_addr address);

#endif