#include "../include/buffer.h"
#include "../include/packet.h"
#include "../include/cache.h"
#include <arpa/inet.h>
#include <complex.h>
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

#define QNAME_MAX 256
#define COMPRESS_MAX 64

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

// currently im just adding forward declaration for this function
// TODO: REFRECTOR this monster
void cache_store_negative(const char *qname, QueryType qtype, uint32_t ttl,
                          DnsPacket *response);

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
      uint32_t neg_ttl = dns_packet_get_soa_minimum(&response, 300);
      cache_store_negative(qname, qtype, neg_ttl, &response);
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
    int from_cache = cache_lookup(question->name, question->qtype, &result);

    if (from_cache) {
      printf("Cache hit: %s\n", question->name);
    } else {
      if (recursive_lookup(question->name, question->qtype, &result) != 0) {
        packet.header.rescode = SERVFAIL;
        goto send;
      }
      cache_store(question->name, question->qtype, &result);
    }

    packet.questions = calloc(1, sizeof(DnsQuestion));
    packet.questions_count = 1;
    packet.questions[0] = *question;
    packet.header.rescode = result.header.rescode;

    packet.answers = calloc(result.answers_count, sizeof(DnsRecord));
    packet.answers_count = 0;

    for (size_t i = 0; i < result.answers_count; i++) {
      packet.answers[packet.answers_count++] = result.answers[i];
      if (!from_cache) {
        printf("Answer: ");
        print_record(&result.answers[i]);
      }
    }

    packet.authorities = calloc(result.authorities_count, sizeof(DnsRecord));
    packet.authorities_count = 0;
    for (size_t i = 0; i < result.authorities_count; i++)
      packet.authorities[packet.authorities_count++] = result.authorities[i];

    packet.resources = calloc(result.resources_count, sizeof(DnsRecord));
    packet.resources_count = 0;
    for (size_t i = 0; i < result.resources_count; i++)
      packet.resources[packet.resources_count++] = result.resources[i];

    dns_packet_free(&result);

  } else {
    packet.header.rescode = FORMERR;
  }

/* encode and send response */
send:;
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
  cache_init();
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