#ifndef PACKET_H
#define PACKET_H

#include "buffer.h"

#include <stdint.h>

/*
 * ResultCode
 */
typedef enum {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  NOTIMP = 4,
  REFUSED = 5
} ResultCode;

ResultCode resultcode_from_num(uint8_t num);
const char *resultcode_to_str(ResultCode rc);

/*
 * DNS HEADER
 */
typedef struct {
  uint16_t id;

  int recursion_desired;
  int truncated_message;
  int authoritative_answer;
  uint8_t opcode;
  int response;

  ResultCode rescode;
  int checking_disabled;
  int authed_data;
  int z;
  int recursion_available;

  uint16_t questions;
  uint16_t answers;
  uint16_t authoritative_entries;
  uint16_t resource_entries;
} DnsHeader;

void dns_header_init(DnsHeader *h);
int dns_header_read(DnsHeader *h, BytePacketBuffer *bfp);
int dns_header_write(DnsHeader *h, BytePacketBuffer *bfp);

/*
 * Query Type
 */
typedef enum {
  QUERY_UNKNOWN = 0,
  QUERY_A = 1,
  QUERY_NS = 2,
  QUERY_CNAME = 5,
  QUERY_SOA = 6,
  QUERY_MX = 15,
  QUERY_AAAA = 28,
} QueryTypeKind;

typedef struct {
  QueryTypeKind kind;
  uint16_t num;
} QueryType;

const char *querytype_to_str(QueryType qt);
QueryType querytype_from_num(uint16_t num);
uint16_t querytype_to_num(QueryType qt);

/*
 * DNSQuestion
 */
typedef struct {
  char name[QNAME_MAX];
  QueryType qtype;
} DnsQuestion;

void dns_question_init(DnsQuestion *q);
int dns_questions_read(DnsQuestion *q, BytePacketBuffer *bfp);
int dns_question_write(DnsQuestion *q, BytePacketBuffer *bfp,
                       CompressTable *ct);

/*
 * DNS RECORD
 */
typedef enum {
  DNS_RECORD_UNKNOWN = 0,
  DNS_RECORD_A = 1,
  DNS_RECORD_NS = 2,
  DNS_RECORD_CNAME = 5,
  DNS_RECORD_MX = 15,
  DNS_RECORD_AAAA = 28,
  DNS_RECORD_SOA = 6,
} DnsRecordKind;

typedef struct {
  DnsRecordKind kind;
  char domain[QNAME_MAX];
  uint32_t ttl;

  uint8_t addr[4];      /* A record */
  uint16_t addr6[8];    /* AAAA record */
  char host[QNAME_MAX]; /* NS, CNAME, MX */
  uint16_t priority;    /* MX */

  uint16_t qtype;    /* UNKNOWN */
  uint16_t data_len; /* UNKNOWN */

  // SOA field
  char mname[QNAME_MAX]; /* Primary Namespace */
  char rname[QNAME_MAX]; /* responsible mailbox */
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum; /* negative caching TTL */
} DnsRecord;

int dns_record_read(BytePacketBuffer *bfp, DnsRecord *out);
int dns_record_write(DnsRecord *r, BytePacketBuffer *bfp, CompressTable *ct);

/*
 * DNS PACKET
 */
typedef struct {
  DnsHeader header;
  DnsQuestion *questions;
  DnsRecord *answers;
  DnsRecord *authorities;
  DnsRecord *resources;

  // counts for dynamically allocated arrays
  size_t questions_count;
  size_t answers_count;
  size_t authorities_count;
  size_t resources_count;
} DnsPacket;

void dns_packet_init(DnsPacket *pkt);
void dns_packet_free(DnsPacket *pkt);
int dns_packet_get_random_a(DnsPacket *pkt, uint8_t out_addr[4]);
int dns_packet_get_resolved_ns(DnsPacket *pkt, const char *qname,
                               uint8_t out_addr[4]);
const char *dns_packet_get_unresolved_ns(DnsPacket *pkt, const char *qname);
int dns_packet_from_buffer(BytePacketBuffer *bfp, DnsPacket *pkt);
int dns_packet_write(DnsPacket *pkt, BytePacketBuffer *bfp);
uint32_t dns_packet_get_soa_minimum(DnsPacket *pkt, uint32_t default_ttl);

void print_record(DnsRecord *r);
void print_packet(DnsPacket *pkt);

#endif