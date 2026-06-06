#include <arpa/inet.h>
#include <complex.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 512
#define QNAME_MAX 256
#define CACHE_SIZE 128
#define MAX_CACHE_RECORDS 12

typedef struct {
  uint8_t buf[BUFFER_SIZE];
  size_t pos;
} BytePacketBuffer;

void buffer_init(BytePacketBuffer *bfp) {
  memset(bfp->buf, 0, BUFFER_SIZE);
  bfp->pos = 0;
}

int buffer_step(BytePacketBuffer *bfp, size_t steps) {
  bfp->pos += steps;
  return 0;
}

int buffer_seek(BytePacketBuffer *bfp, size_t pos) {
  bfp->pos = pos;
  return 0;
}

// read a single byte and move by one step
int buffer_read(BytePacketBuffer *bfp, uint8_t *out) {
  if (bfp->pos > BUFFER_SIZE)
    return -1;
  *out = bfp->buf[bfp->pos++];
  return 0;
}

int buffer_get(BytePacketBuffer *bfp, size_t pos, uint8_t *out) {
  if (pos >= BUFFER_SIZE)
    return -1;
  *out = bfp->buf[pos];
  return 0;
}

int buffer_read_u16(BytePacketBuffer *bfp, uint16_t *out) {
  uint8_t b1, b2;
  if (buffer_read(bfp, &b1) || buffer_read(bfp, &b2))
    return -1;
  *out = (b1 << 8) | b2;
  return 0;
}

int buffer_read_u32(BytePacketBuffer *bfp, uint32_t *out) {
  uint8_t b1, b2, b3, b4;
  if (buffer_read(bfp, &b1) || buffer_read(bfp, &b2) || buffer_read(bfp, &b3) ||
      buffer_read(bfp, &b4))
    return -1;

  *out = ((uint32_t)b1 << 24) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 8) |
         ((uint32_t)b4);

  return 0;
}

int buffer_set(BytePacketBuffer *bfp, size_t pos, uint8_t val) {
  bfp->buf[pos] = val;
  return 0;
}

int buffer_set_u16(BytePacketBuffer *bfp, size_t pos, uint16_t val) {
  if (buffer_set(bfp, pos, (val >> 8) & 0xFF))
    return -1;
  if (buffer_set(bfp, pos + 1, (val >> 0) & 0xFF))
    return -1;
  return 0;
}

/*
 * read a qname
 */

int buffer_read_qname(BytePacketBuffer *bfp, char *out, size_t out_size) {
  size_t pos = bfp->pos;
  int jumped = false;
  int max_jumps = 5;
  int jumps = 0;

  size_t out_len = 0;

  while (true) {
    if (jumps > max_jumps)
      return -1;

    uint8_t len;
    if (buffer_get(bfp, pos, &len))
      return -1;

    // if len has two most significant bit set,
    // it represent a jump to other offset in packet
    if ((len & 0xC0) == 0xC0) {
      uint8_t b2;
      if (buffer_get(bfp, pos + 1, &b2))
        return -1;

      uint16_t offset = ((len ^ 0xC0) << 8) | b2;

      if (!jumped)
        buffer_seek(bfp, pos + 2);

      pos = offset;
      jumped = true;
      jumps++;
    } else {
      pos++;

      if (len == 0)
        break;

      if (out_len != 0 && out_len < out_size - 1) {
        out[out_len++] = '.'; // delimiter
      }

      for (int i = 0; i < len; i++) {
        if (out_len >= out_size - 1)
          break;

        uint8_t c;

        if (buffer_get(bfp, pos + i, &c))
          return -1;

        out[out_len++] = (char)tolower(c);
      }
      pos += len;
    }
  }
  out[out_len] = '\0';

  if (!jumped)
    buffer_seek(bfp, pos);

  return 0;
}

int buffer_write(BytePacketBuffer *bfp, uint8_t val) {
  if (bfp->pos >= BUFFER_SIZE)
    return -1;
  bfp->buf[bfp->pos++] = val;
  return 0;
}

int buffer_write_u8(BytePacketBuffer *bfp, uint8_t val) {
  return buffer_write(bfp, val);
}

// mask with 1111111111111(0xFF) to keep only the lowest 8 bits
// and discard the remaining.
int buffer_write_u16(BytePacketBuffer *bfp, uint16_t val) {
  if (buffer_write(bfp, (val >> 8) & 0xFF))
    return -1;
  if (buffer_write(bfp, (val >> 0) & 0xFF))
    return -1;
  return 0;
}

int buffer_write_u32(BytePacketBuffer *bfp, uint32_t val) {
  if (buffer_write(bfp, (val >> 24) & 0xFF))
    return -1;
  if (buffer_write(bfp, (val >> 16) & 0xFF))
    return -1;
  if (buffer_write(bfp, (val >> 8) & 0xFF))
    return -1;
  if (buffer_write(bfp, (val >> 0) & 0xFF))
    return -1;
  return 0;
}

int buffer_write_qname(BytePacketBuffer *bfp, const char *qname) {
  char tmp[QNAME_MAX];
  strncpy(tmp, qname, QNAME_MAX - 1);
  tmp[QNAME_MAX - 1] = '\0';

  char *label = strtok(tmp, ".");
  while (label != NULL) {
    size_t len = strlen(label);
    // each label can be atmost 63 characters long
    // RFC 1035
    if (len > 0x3f)
      return -1;

    if (buffer_write_u8(bfp, (uint8_t)len))
      return -1;

    for (size_t i = 0; i < len; i++) {
      if (buffer_write_u8(bfp, (uint8_t)label[i]))
        return -1;
    }
    label = strtok(NULL, ".");
  }
  return buffer_write_u8(bfp, 0);
}

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

ResultCode resultcode_from_num(uint8_t num) {
  switch (num) {
  case 1:
    return FORMERR;
  case 2:
    return SERVFAIL;
  case 3:
    return NXDOMAIN;
  case 4:
    return NOTIMP;
  case 5:
    return REFUSED;
  default:
    return NOERROR;
  }
}
static const char *resultcode_to_str(ResultCode rc) {
  switch (rc) {
  case NOERROR:
    return "NOERROR";
  case FORMERR:
    return "FORMERR";
  case SERVFAIL:
    return "SERVFAIL";
  case NXDOMAIN:
    return "NXDOMAIN";
  case NOTIMP:
    return "NOTIMP";
  case REFUSED:
    return "REFUSED";
  default:
    return "UNKNOWN";
  }
}

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

void dns_header_init(DnsHeader *h) { memset(h, 0, sizeof(DnsHeader)); }

int dns_header_read(DnsHeader *h, BytePacketBuffer *bfp) {
  uint16_t flags;

  if (buffer_read_u16(bfp, &h->id))
    return -1;
  if (buffer_read_u16(bfp, &flags))
    return -1;

  uint8_t a = flags >> 8;
  uint8_t b2 = flags & 0xFF;

  h->recursion_desired = (a & (1 << 0)) > 0;
  h->truncated_message = (a & (1 << 1)) > 0;
  h->authoritative_answer = (a & (1 << 2)) > 0;
  h->opcode = (a >> 3) & 0x0F;
  h->response = (a & (1 << 7)) > 0;

  h->rescode = resultcode_from_num(b2 & 0x0F);
  h->checking_disabled = (b2 & (1 << 4)) > 0;
  h->authed_data = (b2 & (1 << 5)) > 0;
  h->z = (b2 & (1 << 6)) > 0;
  h->recursion_available = (b2 & (1 << 7)) > 0;

  if (buffer_read_u16(bfp, &h->questions))
    return -1;
  if (buffer_read_u16(bfp, &h->answers))
    return -1;
  if (buffer_read_u16(bfp, &h->authoritative_entries))
    return -1;
  if (buffer_read_u16(bfp, &h->resource_entries))
    return -1;

  return 0;
}

int dns_header_write(DnsHeader *h, BytePacketBuffer *bfp) {
  if (buffer_write_u16(bfp, h->id))
    return -1;

  uint8_t a = (h->recursion_desired & 0x1) |
              ((h->truncated_message & 0x1) << 1) |
              ((h->authoritative_answer & 0x1) << 2) |
              ((h->opcode & 0xF) << 3) | ((h->response & 0x1) << 7);

  uint8_t b = (h->rescode & 0xF) | ((h->checking_disabled & 0x1) << 4) |
              ((h->authed_data & 0x1) << 5) | ((h->z & 0x1) << 6) |
              ((h->recursion_available & 0x1) << 7);

  if (buffer_write_u8(bfp, a))
    return -1;
  if (buffer_write_u8(bfp, b))
    return -1;

  if (buffer_write_u16(bfp, h->questions))
    return -1;
  if (buffer_write_u16(bfp, h->answers))
    return -1;
  if (buffer_write_u16(bfp, h->authoritative_entries))
    return -1;
  if (buffer_write_u16(bfp, h->resource_entries))
    return -1;

  return 0;
}

typedef enum {
  QUERY_UNKNOWN = 0,
  QUERY_A = 1,
  QUERY_NS = 2,
  QUERY_CNAME = 3,
  QUERY_MX = 4,
  QUERY_AAAA = 5
} QueryTypeKind;

typedef struct {
  QueryTypeKind kind;
  uint16_t num;
} QueryType;

static const char *querytype_to_str(QueryType qt) {
  switch (qt.kind) {
  case QUERY_A:
    return "A";
  case QUERY_NS:
    return "NS";
  case QUERY_CNAME:
    return "CNAME";
  case QUERY_MX:
    return "MX";
  case QUERY_AAAA:
    return "AAAA";
  default:
    return "UNKNOWN";
  }
}

QueryType querytype_from_num(uint16_t num) {
  QueryType qt;
  switch (num) {
  case 1:
    qt.kind = QUERY_A;
    qt.num = num;
    break;
  case 2:
    qt.kind = QUERY_NS;
    qt.num = num;
    break;
  case 5:
    qt.kind = QUERY_CNAME;
    qt.num = num;
    break;
  case 15:
    qt.kind = QUERY_MX;
    qt.num = num;
    break;
  case 28:
    qt.kind = QUERY_AAAA;
    qt.num = num;
    break;
  default:
    qt.kind = QUERY_UNKNOWN;
    qt.num = num;
    break;
  }
  return qt;
}

uint16_t querytype_to_num(QueryType qt) { return qt.num; }

/*
 * DNSQuestion
 */

typedef struct {
  char name[QNAME_MAX];
  QueryType qtype;
} DnsQuestion;

void dns_question_init(DnsQuestion *q) {
  memset(q->name, 0, QNAME_MAX);
  q->qtype = querytype_from_num(0);
}

int dns_questions_read(DnsQuestion *q, BytePacketBuffer *bfp) {
  if (buffer_read_qname(bfp, q->name, QNAME_MAX))
    return -1;

  uint16_t qtype_num;
  if (buffer_read_u16(bfp, &qtype_num))
    return -1;

  q->qtype = querytype_from_num(qtype_num);

  uint16_t class;
  if (buffer_read_u16(bfp, &class))
    return -1;
  return 0;
}

int dns_question_write(DnsQuestion *q, BytePacketBuffer *bfp) {
  if (buffer_write_qname(bfp, q->name))
    return -1;
  if (buffer_write_u16(bfp, querytype_to_num(q->qtype)))
    return -1;
  if (buffer_write_u16(bfp, 1))
    return -1;
  return 0;
}

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
} DnsRecord;

int dns_record_read(BytePacketBuffer *bfp, DnsRecord *out) {
  if (buffer_read_qname(bfp, out->domain, QNAME_MAX))
    return -1;

  uint16_t qname_type;
  if (buffer_read_u16(bfp, &qname_type))
    return -1;

  QueryType qtype = querytype_from_num(qname_type);

  uint16_t class;
  if (buffer_read_u16(bfp, &class))
    return -1;
  if (buffer_read_u32(bfp, &out->ttl))
    return -1;

  uint16_t data_len;
  if (buffer_read_u16(bfp, &data_len))
    return -1;

  switch (qtype.kind) {
  case QUERY_A: {
    uint32_t raw_addr;
    if (buffer_read_u32(bfp, &raw_addr))
      return -1;

    out->kind = DNS_RECORD_A;
    out->addr[0] = (raw_addr >> 24) & 0xFF;
    out->addr[1] = (raw_addr >> 16) & 0xFF;
    out->addr[2] = (raw_addr >> 8) & 0xFF;
    out->addr[3] = (raw_addr >> 0) & 0xFF;
    break;
  }
  case QUERY_AAAA: {
    uint32_t r1, r2, r3, r4;
    if (buffer_read_u32(bfp, &r1))
      return -1;
    if (buffer_read_u32(bfp, &r2))
      return -1;
    if (buffer_read_u32(bfp, &r3))
      return -1;
    if (buffer_read_u32(bfp, &r4))
      return -1;

    out->kind = DNS_RECORD_AAAA;
    out->addr6[0] = (r1 >> 16) & 0xFFFF;
    out->addr6[1] = (r1 >> 0) & 0xFFFF;
    out->addr6[2] = (r2 >> 16) & 0xFFFF;
    out->addr6[3] = (r2 >> 0) & 0xFFFF;
    out->addr6[4] = (r3 >> 16) & 0xFFFF;
    out->addr6[5] = (r3 >> 0) & 0xFFFF;
    out->addr6[6] = (r4 >> 16) & 0xFFFF;
    out->addr6[7] = (r4 >> 0) & 0xFFFF;
    break;
  }
  case QUERY_NS:
    out->kind = DNS_RECORD_NS;
    if (buffer_read_qname(bfp, out->host, QNAME_MAX))
      return -1;
    break;

  case QUERY_CNAME:
    out->kind = DNS_RECORD_CNAME;
    if (buffer_read_qname(bfp, out->host, QNAME_MAX))
      return -1;
    break;

  case QUERY_MX:
    out->kind = DNS_RECORD_MX;
    if (buffer_read_u16(bfp, &out->priority))
      return -1;
    if (buffer_read_qname(bfp, out->host, QNAME_MAX))
      return -1;
    break;
  default:
    if (buffer_step(bfp, data_len))
      return -1;

    out->kind = DNS_RECORD_UNKNOWN;
    out->qtype = qname_type;
    out->data_len = data_len;
    break;
  }

  return 0;
}

int dns_record_write(DnsRecord *r, BytePacketBuffer *bfp) {
  switch (r->kind) {
  case DNS_RECORD_A:
    if (buffer_write_qname(bfp, r->domain))
      return -1;
    if (buffer_write_u16(bfp, 1))
      return -1;
    if (buffer_write_u16(bfp, 1))
      return -1;
    if (buffer_write_u32(bfp, r->ttl))
      return -1;
    if (buffer_write_u16(bfp, 4))
      return -1;
    if (buffer_write_u8(bfp, r->addr[0]))
      return -1;
    if (buffer_write_u8(bfp, r->addr[1]))
      return -1;
    if (buffer_write_u8(bfp, r->addr[2]))
      return -1;
    if (buffer_write_u8(bfp, r->addr[3]))
      return -1;
    break;

  case DNS_RECORD_NS:
  case DNS_RECORD_CNAME: {
    uint16_t type_num = (r->kind == DNS_RECORD_NS) ? 2 : 5;
    if (buffer_write_qname(bfp, r->domain))
      return -1;
    if (buffer_write_u16(bfp, type_num))
      return -1;
    if (buffer_write_u16(bfp, 1))
      return -1;
    if (buffer_write_u32(bfp, r->ttl))
      return -1;

    size_t pos = bfp->pos;
    if (buffer_write_u16(bfp, 0))
      return -1;
    if (buffer_write_qname(bfp, r->host))
      return -1;

    uint16_t size = (uint16_t)(bfp->pos - (pos + 2));
    if (buffer_set_u16(bfp, pos, size))
      return -1;
    break;
  }

  case DNS_RECORD_MX: {
    if (buffer_write_qname(bfp, r->domain))
      return -1;
    if (buffer_write_u16(bfp, 15))
      return -1;
    if (buffer_write_u16(bfp, 1))
      return -1;
    if (buffer_write_u32(bfp, r->ttl))
      return -1;

    size_t pos = bfp->pos;
    if (buffer_write_u16(bfp, 0))
      return -1;
    if (buffer_write_u16(bfp, r->priority))
      return -1;
    if (buffer_write_qname(bfp, r->host))
      return -1;

    uint16_t size = (uint16_t)(bfp->pos - (pos + 2));
    if (buffer_set_u16(bfp, pos, size))
      return -1;
    break;
  }

  case DNS_RECORD_AAAA: {
    if (buffer_write_qname(bfp, r->domain))
      return -1;
    if (buffer_write_u16(bfp, 28))
      return -1;
    if (buffer_write_u16(bfp, 1))
      return -1;
    if (buffer_write_u32(bfp, r->ttl))
      return -1;
    if (buffer_write_u16(bfp, 16))
      return -1;
    for (int i = 0; i < 8; i++) {
      if (buffer_write_u16(bfp, r->addr6[i]))
        return -1;
    }
    break;
  }

  default:
    printf("Skipping UNKNOWN record for domain: %s\n", r->domain);
    break;
  }

  return 0;
}

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

void dns_packet_init(DnsPacket *pkt) {
  dns_header_init(&pkt->header);
  pkt->questions = NULL;
  pkt->answers = NULL;
  pkt->authorities = NULL;
  pkt->resources = NULL;
  pkt->questions_count = 0;
  pkt->answers_count = 0;
  pkt->authorities_count = 0;
  pkt->resources_count = 0;
}

void dns_packet_free(DnsPacket *pkt) {
  free(pkt->questions);
  free(pkt->answers);
  free(pkt->authorities);
  free(pkt->resources);
}

int dns_packet_get_random_a(DnsPacket *pkt, uint8_t out_addr[4]) {
  for (size_t i = 0; i < pkt->answers_count; i++) {
    if (pkt->answers[i].kind == DNS_RECORD_A) {
      memcpy(out_addr, pkt->answers[i].addr, 4);
      return 1;
    }
  }
  return 0;
}

int dns_packet_get_resolved_ns(DnsPacket *pkt, const char *qname,
                               uint8_t out_addr[4]) {
  for (size_t i = 0; i < pkt->authorities_count; i++) {
    DnsRecord *ns = &pkt->authorities[i];
    if (ns->kind != DNS_RECORD_NS)
      continue;

    size_t domain_len = strlen(ns->domain);
    size_t qname_len = strlen(qname);
    if (qname_len < domain_len ||
        strcmp(qname + qname_len - domain_len, ns->domain) != 0)
      continue;

    /* find matching A record in resources */
    for (size_t j = 0; j < pkt->resources_count; j++) {
      DnsRecord *r = &pkt->resources[j];
      if (r->kind == DNS_RECORD_A && strcmp(r->domain, ns->host) == 0) {
        memcpy(out_addr, r->addr, 4);
        return 1;
      }
    }
  }
  return 0;
}

/* returns host of first NS record in authorities matching qname, or NULL */
const char *dns_packet_get_unresolved_ns(DnsPacket *pkt, const char *qname) {
  for (size_t i = 0; i < pkt->authorities_count; i++) {
    DnsRecord *r = &pkt->authorities[i];
    if (r->kind == DNS_RECORD_NS) {
      /* check if qname ends with this domain */
      size_t domain_len = strlen(r->domain);
      size_t qname_len = strlen(qname);
      if (qname_len >= domain_len &&
          strcmp(qname + qname_len - domain_len, r->domain) == 0) {
        return r->host;
      }
    }
  }
  return NULL;
}

int dns_packet_from_buffer(BytePacketBuffer *bfp, DnsPacket *pkt) {
  dns_packet_init(pkt);

  if (dns_header_read(&pkt->header, bfp))
    return -1;

  pkt->questions = calloc(pkt->header.questions, sizeof(DnsQuestion));
  for (uint16_t i = 0; i < pkt->header.questions; i++) {
    dns_question_init(&pkt->questions[i]);
    if (dns_questions_read(&pkt->questions[i], bfp))
      return -1;
    pkt->questions_count++;
  }

  pkt->answers = calloc(pkt->header.answers, sizeof(DnsRecord));
  for (uint16_t i = 0; i < pkt->header.answers; i++) {
    if (dns_record_read(bfp, &pkt->answers[i]))
      return -1;
    pkt->answers_count++;
  }

  pkt->authorities =
      calloc(pkt->header.authoritative_entries, sizeof(DnsRecord));
  for (uint16_t i = 0; i < pkt->header.authoritative_entries; i++) {
    if (dns_record_read(bfp, &pkt->authorities[i]))
      return -1;
    pkt->authorities_count++;
  }

  pkt->resources = calloc(pkt->header.resource_entries, sizeof(DnsRecord));
  for (uint16_t i = 0; i < pkt->header.resource_entries; i++) {
    if (dns_record_read(bfp, &pkt->resources[i]))
      return -1;
    pkt->resources_count++;
  }

  return 0;
}
int dns_packet_write(DnsPacket *pkt, BytePacketBuffer *bfp) {
  pkt->header.questions = (uint16_t)pkt->questions_count;
  pkt->header.answers = (uint16_t)pkt->answers_count;
  pkt->header.authoritative_entries = (uint16_t)pkt->authorities_count;
  pkt->header.resource_entries = (uint16_t)pkt->resources_count;

  if (dns_header_write(&pkt->header, bfp))
    return -1;

  for (size_t i = 0; i < pkt->questions_count; i++)
    if (dns_question_write(&pkt->questions[i], bfp))
      return -1;

  for (size_t i = 0; i < pkt->answers_count; i++)
    if (dns_record_write(&pkt->answers[i], bfp))
      return -1;

  for (size_t i = 0; i < pkt->authorities_count; i++)
    if (dns_record_write(&pkt->authorities[i], bfp))
      return -1;

  for (size_t i = 0; i < pkt->resources_count; i++)
    if (dns_record_write(&pkt->resources[i], bfp))
      return -1;

  return 0;
}

/*
 * print helpers
 */

static void print_record(DnsRecord *r) {
  switch (r->kind) {
  case DNS_RECORD_A:
    printf("A {\n");
    printf("    domain: \"%s\",\n", r->domain);
    printf("    addr: %u.%u.%u.%u,\n", r->addr[0], r->addr[1], r->addr[2],
           r->addr[3]);
    printf("    ttl: %u\n", r->ttl);
    printf("}\n");
    break;

  case DNS_RECORD_AAAA:
    printf("AAAA {\n");
    printf("    domain: \"%s\",\n", r->domain);
    printf("    addr: %x:%x:%x:%x:%x:%x:%x:%x,\n", r->addr6[0], r->addr6[1],
           r->addr6[2], r->addr6[3], r->addr6[4], r->addr6[5], r->addr6[6],
           r->addr6[7]);
    printf("    ttl: %u\n", r->ttl);
    printf("}\n");
    break;

  case DNS_RECORD_NS:
    printf("NS {\n");
    printf("    domain: \"%s\",\n", r->domain);
    printf("    host: \"%s\",\n", r->host);
    printf("    ttl: %u\n", r->ttl);
    printf("}\n");
    break;

  case DNS_RECORD_CNAME:
    printf("CNAME {\n");
    printf("    domain: \"%s\",\n", r->domain);
    printf("    host: \"%s\",\n", r->host);
    printf("    ttl: %u\n", r->ttl);
    printf("}\n");
    break;

  case DNS_RECORD_MX:
    printf("MX {\n");
    printf("    domain: \"%s\",\n", r->domain);
    printf("    priority: %u,\n", r->priority);
    printf("    host: \"%s\",\n", r->host);
    printf("    ttl: %u\n", r->ttl);
    printf("}\n");
    break;

  default:
    printf("UNKNOWN {\n");
    printf("    domain: \"%s\",\n", r->domain);
    printf("    qtype: %u,\n", r->qtype);
    printf("    data_len: %u,\n", r->data_len);
    printf("    ttl: %u\n", r->ttl);
    printf("}\n");
    break;
  }
}

void print_packet(DnsPacket *pkt) {
  printf("DnsHeader {\n");
  printf("    id: %u,\n", pkt->header.id);
  printf("    recursion_desired: %s,\n",
         pkt->header.recursion_desired ? "true" : "false");
  printf("    truncated_message: %s,\n",
         pkt->header.truncated_message ? "true" : "false");
  printf("    authoritative_answer: %s,\n",
         pkt->header.authoritative_answer ? "true" : "false");
  printf("    opcode: %u,\n", pkt->header.opcode);
  printf("    response: %s,\n", pkt->header.response ? "true" : "false");
  printf("    rescode: %s,\n", resultcode_to_str(pkt->header.rescode));
  printf("    checking_disabled: %s,\n",
         pkt->header.checking_disabled ? "true" : "false");
  printf("    authed_data: %s,\n", pkt->header.authed_data ? "true" : "false");
  printf("    z: %s,\n", pkt->header.z ? "true" : "false");
  printf("    recursion_available: %s,\n",
         pkt->header.recursion_available ? "true" : "false");
  printf("    questions: %u,\n", pkt->header.questions);
  printf("    answers: %u,\n", pkt->header.answers);
  printf("    authoritative_entries: %u,\n", pkt->header.authoritative_entries);
  printf("    resource_entries: %u\n", pkt->header.resource_entries);
  printf("}\n");

  for (size_t i = 0; i < pkt->questions_count; i++) {
    printf("DnsQuestion {\n");
    printf("    name: \"%s\",\n", pkt->questions[i].name);
    printf("    qtype: %s\n", querytype_to_str(pkt->questions[i].qtype));
    printf("}\n");
  }

  for (size_t i = 0; i < pkt->answers_count; i++)
    print_record(&pkt->answers[i]);

  for (size_t i = 0; i < pkt->authorities_count; i++)
    print_record(&pkt->authorities[i]);

  for (size_t i = 0; i < pkt->resources_count; i++)
    print_record(&pkt->resources[i]);
}

int lookup(const char *qname, QueryType qtype, uint8_t server_ip[4],
           uint16_t server_port, DnsPacket *out) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  int opt = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in local = {0};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  // setting htons(0) so that os can pick any available ephemeral port
  local.sin_port = htons(0);

  if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0) {
    perror("bind");
    close(sockfd);
    return -1;
  }

  DnsPacket pkt;
  dns_packet_init(&pkt);
  pkt.header.id = 6666;
  pkt.header.recursion_desired = 1;

  pkt.questions = calloc(1, sizeof(DnsQuestion));
  pkt.questions_count = 1;
  dns_question_init(&pkt.questions[0]);
  strncpy(pkt.questions[0].name, qname, QNAME_MAX - 1);
  pkt.questions[0].qtype = qtype;

  BytePacketBuffer req;
  buffer_init(&req);

  if (dns_packet_write(&pkt, &req)) {
    fprintf(stderr, "lookup: failed to write packet\n");
    dns_packet_free(&pkt);
    close(sockfd);
    return -1;
  }

  struct sockaddr_in dest = {0};
  dest.sin_family = AF_INET;
  dest.sin_port = htons(server_port);
  memcpy(&dest.sin_addr.s_addr, server_ip, 4);

  if (sendto(sockfd, req.buf, req.pos, 0, (struct sockaddr *)&dest,
             sizeof(dest)) < 0) {
    perror("sendto");
    dns_packet_free(&pkt);
    close(sockfd);
    return -1;
  }

  BytePacketBuffer res;
  buffer_init(&res);

  struct sockaddr_in src;
  socklen_t src_len = sizeof(src);
  if (recvfrom(sockfd, res.buf, BUFFER_SIZE, 0, (struct sockaddr *)&src,
               &src_len) < 0) {
    perror("recvfrom");
    dns_packet_free(&pkt);
    close(sockfd);
    return -1;
  }

  close(sockfd);
  dns_packet_free(&pkt);

  return dns_packet_from_buffer(&res, out);
}

int recursive_lookup(const char *qname, QueryType qtype, DnsPacket *out) {
  // starting with *a.root-servers.net*
  uint8_t ns[4] = {198, 41, 0, 4};

  for (;;) {
    printf("attempting lookup of %s %s with ns %u.%u.%u.%u\n",
           querytype_to_str(qtype), qname, ns[0], ns[1], ns[2], ns[3]);

    uint8_t ns_copy[4];
    memcpy(ns_copy, ns, 4);

    DnsPacket response;
    // send the query to the active server
    if (lookup(qname, qtype, ns_copy, 53, &response) != 0)
      return -1;

    // got answers and no error? work complete
    if (response.answers_count > 0 && response.header.rescode == NOERROR) {
      *out = response;
      return 0;
    }

    // if we got NXDOMAIN, that means the name doenst exists
    if (response.header.rescode == NXDOMAIN) {
      *out = response;
      return 0;
    }

    // otherwise we continue looking for new nameserver based on
    // ns we got and a corresponding record
    // if this succeeds, swith to new ns and continue the loop
    uint8_t new_ns[4];
    if (dns_packet_get_resolved_ns(&response, qname, new_ns)) {
      memcpy(ns, new_ns, 4);
      dns_packet_free(&response);
      continue;
    }

    // no resolved ns?? try to get an nameserver based on NS
    // and look it up;
    const char *unresolved = dns_packet_get_unresolved_ns(&response, qname);
    if (!unresolved) {
      *out = response;
      return 0;
    }

    char ns_name[QNAME_MAX];
    strncpy(ns_name, unresolved, QNAME_MAX - 1);
    ns_name[QNAME_MAX - 1] = '\0';
    dns_packet_free(&response);

    // recursively look into NS host
    DnsPacket recursive_response;
    QueryType a_type = querytype_from_num(1);
    if (recursive_lookup(ns_name, a_type, &recursive_response) != 0)
      return -1;

    if (dns_packet_get_random_a(&recursive_response, new_ns)) {
      memcpy(ns, new_ns, 4);
      dns_packet_free(&recursive_response);
    } else {
      *out = recursive_response;
      return 0;
    }
  }
}

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
} CacheEntry;

static CacheEntry cache[CACHE_SIZE];

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

  // store ttl of first record for expiry
  entry->expires_at = time(NULL) + pkt->answers[0].ttl;

  for (size_t i = 0; i < pkt->answers_count && i < MAX_CACHE_RECORDS; i++)
    entry->records[entry->records_count++] = pkt->answers[i];
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

int handle_query(int sockfd) {
  BytePacketBuffer req_buf;
  buffer_init(&req_buf);

  struct sockaddr_in src;
  socklen_t src_len = sizeof(src);

  if (recvfrom(sockfd, req_buf.buf, BUFFER_SIZE, 0, (struct sockaddr *)&src,
               &src_len) < 0) {
    perror("recvfrom");
    return -1;
  }

  DnsPacket request;
  if (dns_packet_from_buffer(&req_buf, &request)) {
    fprintf(stderr, "handle_query: failed to parse request\n");
    return -1;
  }

  DnsPacket packet;
  dns_packet_init(&packet);
  packet.header.id = request.header.id;
  packet.header.recursion_desired = 1;
  packet.header.recursion_available = 1;
  packet.header.response = 1;

  if (request.questions_count > 0) {
    DnsQuestion *question = &request.questions[0];
    printf("Received query: DnsQuestion { name: \"%s\", qtype: %s }\n",
           question->name, querytype_to_str(question->qtype));

    DnsPacket result;
    if (recursive_lookup(question->name, question->qtype, &result) == 0) {
      packet.questions = calloc(1, sizeof(DnsQuestion));
      packet.questions_count = 1;
      packet.questions[0] = *question;

      packet.header.rescode = result.header.rescode;

      if (result.answers_count > 0) {
        packet.answers = calloc(result.answers_count, sizeof(DnsRecord));
        packet.answers_count = result.answers_count;
        memcpy(packet.answers, result.answers,
               result.answers_count * sizeof(DnsRecord));

        for (size_t i = 0; i < result.answers_count; i++) {
          printf("Answer: ");
          print_record(&result.answers[i]);
        }
      }

      if (result.authorities_count > 0) {
        packet.authorities =
            calloc(result.authorities_count, sizeof(DnsRecord));
        packet.authorities_count = result.authorities_count;
        memcpy(packet.authorities, result.authorities,
               result.authorities_count * sizeof(DnsRecord));
      }

      if (result.resources_count > 0) {
        packet.resources = calloc(result.resources_count, sizeof(DnsRecord));
        packet.resources_count = result.resources_count;
        memcpy(packet.resources, result.resources,
               result.resources_count * sizeof(DnsRecord));
      }

      dns_packet_free(&result);
    } else {
      packet.header.rescode = SERVFAIL;
    }
  } else {
    packet.header.rescode = FORMERR;
  }

  /* encode and send response */
  BytePacketBuffer res_buf;
  buffer_init(&res_buf);

  if (dns_packet_write(&packet, &res_buf)) {
    fprintf(stderr, "handle_query: failed to write response\n");
    dns_packet_free(&request);
    dns_packet_free(&packet);
    return -1;
  }

  if (sendto(sockfd, res_buf.buf, res_buf.pos, 0, (struct sockaddr *)&src,
             src_len) < 0) {
    perror("sendto");
    dns_packet_free(&request);
    dns_packet_free(&packet);
    return -1;
  }

  dns_packet_free(&request);
  dns_packet_free(&packet);
  return 0;
}

int main(void) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  int opt = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in local = {0};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  local.sin_port = htons(2053);

  if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0) {
    perror("bind");
    close(sockfd);
    return 1;
  }

  printf("DNS server listening on port 2053\n");

  for (;;) {
    if (handle_query(sockfd) != 0)
      fprintf(stderr, "an error occurred handling query\n");
  }

  close(sockfd);
  return 0;
}