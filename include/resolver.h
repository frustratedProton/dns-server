#ifndef RESOLVER_H
#define RESOLVER_H

#include "packet.h"
#include <stdint.h>

int lookup(const char *qname, QueryType qtype, uint8_t server_ip[4],
           uint16_t server_port, DnsPacket *out);
int recursive_lookup(const char *qname, QueryType qtype, DnsPacket *out);

#endif