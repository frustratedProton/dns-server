#include <complex.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 512

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

typedef enum {
  QUERY_UNKNOWN = 0,
  QUERY_A = 1,
} QueryTypeKind;

typedef struct {
  QueryTypeKind kind;
  uint16_t num;
} QueryType;

QueryType querytype_from_num(uint16_t num) {
  QueryType qt;
  switch (num) {
  case 1:
    qt.kind = QUERY_A;
    qt.num = 1;
    break;
  default:
    qt.kind = QUERY_UNKNOWN;
    qt.num = 0;
    break;
  }
  return qt;
}

uint16_t querytype_to_num(QueryType qt) { return qt.num; }

/*
 * DNSQuestion
 */

typedef struct {
  char name[256];
  QueryType qtype;
} DnsQuestion;

void dns_question_init(DnsQuestion *q) {
  memset(q->name, 0, 256);
  q->qtype = querytype_from_num(0);
}

int dns_questions_read(DnsQuestion *q, BytePacketBuffer *bfp) {
  if (buffer_read_qname(bfp, q->name, 256))
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

/*
 * DNS RECORD
 */

typedef enum { DNS_RECORD_UNKNOWN = 0, DNS_RECORD_A = 1 } DnsRecordKind;

typedef struct {
  DnsRecordKind kind;
  char domain[256];
  uint32_t ttl;
  uint8_t addr[4];
  uint16_t qtype;
  uint16_t data_len;
} DnsRecord;

int dns_record_read(BytePacketBuffer *bfp, DnsRecord *out) {
  if (buffer_read_qname(bfp, out->domain, 256))
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