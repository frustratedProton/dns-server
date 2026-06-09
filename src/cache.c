#include "../include/cache.h"
#include <stdlib.h>
#include <string.h>

CacheEntry cache[CACHE_SIZE];

void cache_init() {
  for (int i = 0; i < CACHE_SIZE; i++)
    cache[i].valid = 0;
}

static size_t cache_find_slot() {
  // look for an invalid spot by looking thru the arr
  // (feels kinds slow if cache becomes large - should be fine for 12)
  for (int i = 0; i < CACHE_SIZE; i++)
    if (!cache[i].valid)
      return i;

  // if no invalid spot found
  // look for an expired slot
  time_t now = time(NULL);
  for (int i = 0; i < CACHE_SIZE; i++)
    if (cache[i].expires_at <= now)
      return i;

  // if no expired slot found
  // evict entry closest to expiring
  // and return it
  size_t oldest = 0;
  for (int i = 1; i < CACHE_SIZE; i++)
    if (cache[i].expires_at < cache[oldest].expires_at)
      oldest = i;
  return oldest;
}

void cache_store(const char *qname, QueryType qtype, DnsPacket *pkt) {
  if (pkt->answers_count == 0)
    return;

  size_t slot = cache_find_slot();
  CacheEntry *entry = &cache[slot];

  strncpy(entry->qname, qname, QNAME_MAX - 1);
  entry->qname[QNAME_MAX - 1] = '\0';
  entry->qtype = qtype;
  entry->records_count = 0;
  entry->valid = 1;
  entry->is_negative = 1;

  // store ttl of first record for expiry
  entry->expires_at = time(NULL) + pkt->answers[0].ttl;

  for (size_t i = 0; i < pkt->answers_count && i < MAX_CACHE_RECORDS; i++)
    entry->records[entry->records_count++] = pkt->answers[i];
}

void cache_store_negative(const char *qname, QueryType qtype, uint32_t ttl,
                          DnsPacket *response) {
  size_t slot = cache_find_slot();
  CacheEntry *e = &cache[slot];

  strncpy(e->qname, qname, QNAME_MAX - 1);
  e->qname[QNAME_MAX - 1] = '\0';
  e->qtype = qtype;
  e->records_count = 0;
  e->expires_at = time(NULL) + ttl;
  e->valid = 1;
  e->is_negative = 1;
  e->has_soa = 0;

  /* store the SOA from authorities */
  for (size_t i = 0; i < response->authorities_count; i++) {
    if (response->authorities[i].kind == DNS_RECORD_SOA) {
      e->soa = response->authorities[i];
      e->has_soa = 1;
      break;
    }
  }
}
int cache_lookup(const char *qname, QueryType qtype, DnsPacket *out) {
  time_t now = time(NULL);

  for (int i = 0; i < CACHE_SIZE; i++) {
    CacheEntry *entry = &cache[i];

    // skip invalid entries
    if (!entry->valid)
      continue;
    // skip if qtype doenst match
    if (entry->qtype.num != qtype.num)
      continue;
    // skip if qname doesnt match
    if (strcmp(entry->qname, qname))
      continue;
    // if expired, mark entry as invalid
    if (entry->expires_at <= now) {
      entry->valid = 0;
      return 0;
    }
    // if negative cache hit, domain doesnt exit
    if (entry->is_negative) {
      dns_packet_init(out);
      out->header.rescode = NXDOMAIN;
      out->header.response = 1;
      out->header.recursion_available = 1;

      if (entry->has_soa) {
        out->authorities = calloc(1, sizeof(DnsRecord));
        if (out->authorities) {
          out->authorities[0] = entry->soa;
          uint32_t remaining = (uint32_t)(entry->expires_at - time(NULL));
          out->authorities[0].ttl = remaining;
          out->authorities_count = 1;
        }
      }

      return 1;
    }

    // build DnsPacket from cached records
    dns_packet_init(out);
    out->answers = calloc(entry->records_count, sizeof(DnsRecord));
    if (!out->answers)
      return 0;

    out->answers_count = entry->records_count;
    uint32_t remaining = (uint32_t)(entry->expires_at - now);

    for (size_t j = 0; j < entry->records_count; j++) {
      out->answers[j] = entry->records[j];
      out->answers[j].ttl = remaining; // reset ttl
    }

    out->header.rescode = NOERROR;
    out->header.recursion_available = 1;
    out->header.response = 1;

    return 1;
  }

  return 0;
}
