#include "../include/buffer.h"
#include "../include/cache.h"
#include "../include/packet.h"
#include "../include/resolver.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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