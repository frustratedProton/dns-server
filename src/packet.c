#include "../include/packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
const char *resultcode_to_str(ResultCode rc) {
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

const char *querytype_to_str(QueryType qt) {
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
  case QUERY_SOA:
    return "SOA";
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
  case 6:
    qt.kind = QUERY_SOA;
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

int dns_question_write(DnsQuestion *q, BytePacketBuffer *bfp,
                       CompressTable *ct) {
  if (buffer_write_qname(bfp, q->name))
    return -1;

  compress_table_add(ct, q->name, 12);

  if (buffer_write_u16(bfp, querytype_to_num(q->qtype)))
    return -1;
  if (buffer_write_u16(bfp, 1))
    return -1;
  return 0;
}

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

  case QUERY_SOA:
    out->kind = DNS_RECORD_SOA;
    if (buffer_read_qname(bfp, out->mname, QNAME_MAX))
      return -1;
    if (buffer_read_qname(bfp, out->rname, QNAME_MAX))
      return -1;
    if (buffer_read_u32(bfp, &out->serial))
      return -1;
    if (buffer_read_u32(bfp, &out->refresh))
      return -1;
    if (buffer_read_u32(bfp, &out->retry))
      return -1;
    if (buffer_read_u32(bfp, &out->expire))
      return -1;
    if (buffer_read_u32(bfp, &out->minimum))
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

int dns_record_write(DnsRecord *r, BytePacketBuffer *bfp, CompressTable *ct) {
  switch (r->kind) {
  case DNS_RECORD_A:
    if (buffer_write_qname_compressed(bfp, r->domain, ct))
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
    if (buffer_write_qname_compressed(bfp, r->domain, ct))
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
    if (buffer_write_qname_compressed(bfp, r->host, ct))
      return -1;

    uint16_t size = (uint16_t)(bfp->pos - (pos + 2));
    if (buffer_set_u16(bfp, pos, size))
      return -1;
    break;
  }

  case DNS_RECORD_MX: {
    if (buffer_write_qname_compressed(bfp, r->domain, ct))
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
    if (buffer_write_qname_compressed(bfp, r->host, ct))
      return -1;

    uint16_t size = (uint16_t)(bfp->pos - (pos + 2));
    if (buffer_set_u16(bfp, pos, size))
      return -1;
    break;
  }

  case DNS_RECORD_AAAA: {
    if (buffer_write_qname_compressed(bfp, r->domain, ct))
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

  case DNS_RECORD_SOA:
    if (buffer_write_qname(bfp, r->domain))
      return -1;
    if (buffer_write_u16(bfp, 6))
      return -1;
    if (buffer_write_u16(bfp, 1))
      return -1;
    if (buffer_write_u32(bfp, r->ttl))
      return -1;

    size_t soa_pos = bfp->pos;
    if (buffer_write_u16(bfp, 0))
      return -1;
    if (buffer_write_qname(bfp, r->mname))
      return -1;
    if (buffer_write_qname(bfp, r->rname))
      return -1;
    if (buffer_write_u32(bfp, r->serial))
      return -1;
    if (buffer_write_u32(bfp, r->refresh))
      return -1;
    if (buffer_write_u32(bfp, r->retry))
      return -1;
    if (buffer_write_u32(bfp, r->expire))
      return -1;
    if (buffer_write_u32(bfp, r->minimum))
      return -1;

    uint16_t soa_size = (uint16_t)(bfp->pos - (soa_pos + 2));
    if (buffer_set_u16(bfp, soa_pos, soa_size))
      return -1;
    break;

  default:
    printf("Skipping UNKNOWN record for domain: %s\n", r->domain);
    break;
  }

  return 0;
}

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

  CompressTable ct;
  compress_table_init(&ct);

  for (size_t i = 0; i < pkt->questions_count; i++)
    if (dns_question_write(&pkt->questions[i], bfp, &ct))
      return -1;

  for (size_t i = 0; i < pkt->answers_count; i++)
    if (dns_record_write(&pkt->answers[i], bfp, &ct))
      return -1;

  for (size_t i = 0; i < pkt->authorities_count; i++)
    if (dns_record_write(&pkt->authorities[i], bfp, &ct))
      return -1;

  for (size_t i = 0; i < pkt->resources_count; i++)
    if (dns_record_write(&pkt->resources[i], bfp, &ct))
      return -1;

  return 0;
}

uint32_t dns_packet_get_soa_minimum(DnsPacket *pkt, uint32_t default_ttl) {
  for (size_t i = 0; i < pkt->authorities_count; i++) {
    if (pkt->authorities[i].kind == DNS_RECORD_SOA)
      return pkt->authorities[i].minimum;
  }
  return default_ttl;
}

/*
 * print helpers
 */
void print_record(DnsRecord *r) {
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

  case DNS_RECORD_SOA:
    printf("SOA {\n");
    printf("    domain:  \"%s\",\n", r->domain);
    printf("    mname:   \"%s\",\n", r->mname);
    printf("    rname:   \"%s\",\n", r->rname);
    printf("    serial:  %u,\n", r->serial);
    printf("    refresh: %u,\n", r->refresh);
    printf("    retry:   %u,\n", r->retry);
    printf("    expire:  %u,\n", r->expire);
    printf("    minimum: %u\n", r->minimum);
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