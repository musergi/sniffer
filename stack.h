#ifndef STACK_H
#define STACK_H

#include <pcap.h>

typedef unsigned int byte;

/**
 * @brief Size in bytes of an ethernet address
 */
#define ETHERNET_ADDRESS_SIZE 6

/**
 * @brief Struct holding the header data for Ethernet.
 */
typedef struct ethernet_header {
    byte destination_address[ETHERNET_ADDRESS_SIZE];
    byte source_address[ETHERNET_ADDRESS_SIZE];
    byte ethertype[2];
} ethernet_header_t;

/**
 * @brief Receives a pointer to the raw data and returns a pointer to the
 * ethernet header.
 *
 * @param data Byte pointer to the bytes on the wire.
 * @return ethernet_header_t* Pointer to the part of the bytes representing the
 * ethernet header.
 */
ethernet_header_t *ethernet_get_header(byte *data);

/**
 * @brief Receives a pointer to raw data and offsets the pointer to point to the
 * start of the corresponding Ethernet data.
 *
 * @param data Byte pointer to the bytes on the wire.
 * @return byte* Byte pointer to the first byte of ethernet data.
 */
byte *ethernet_get_data(byte *data);

/**
 * @brief Converts an Ethernet address into a human readable format (e.g
 * ff:ff:ff:ff:ff:ff). It will do nothing if the address does not fit. in the
 * provided string.
 *
 * @param str String to store the address into.
 * @param size Size of the passed string to avoid overflow.
 * @param address Bytes representing the address, ETHERNET_ADDRESS_SIZE will be
 * assumed, be careful with bound overflow.
 */
void ethernet_address_str(char *str, size_t size, byte *address);

/**
 * @brief Converts an Ethertype into a human readable protocol. If the ethertype
 * is not implemented by the developper a hex representation of the type will be
 * returned.
 *
 * @param str String to store the address into.
 * @param size Size of the passed string to avoid overflow.
 * @param ethertype Bytes representing the ethertype, the first being the upper
 * byte and the second the lower byte.
 */
void ethernet_ethertype_str(char *str, size_t size, byte *ethertype);

#endif