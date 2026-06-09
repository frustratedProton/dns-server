#ifndef CACHE_H
#define CACHE_H

// #include "buffer.h"
#include "packet.h"
#include <time.h>

#define MAX_CACHE_RECORDS 12
#define CACHE_SIZE 128

/*
 * Cache Entry
 * Store cache with key-value pair for lookup
 * key = {qname, qtype} -> "google.com" + A
 * value = {answer record} -> [142.250.x.x, ...]
 * expiry = {current_time + ttl}
 */
typedef struct {
  char qname[QNAME_MAX];
  QueryType qtype;
  DnsRecord records[MAX_CACHE_RECORDS];
  size_t records_count;
  time_t expires_at;
  int valid;
  int is_negative; // 1 -> NXDOMAIN, 0 -> NORMAL
  DnsRecord soa;
  int has_soa;
} CacheEntry;

void cache_init();
void cache_store(const char *qname, QueryType qtype, DnsPacket *pkt);
void cache_store_negative(const char *qname, QueryType qtype, uint32_t ttl,
                          DnsPacket *response);
int cache_lookup(const char *qname, QueryType qtype, DnsPacket *out);


#endif