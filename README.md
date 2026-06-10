# DNS Server

A DNS server written in C for learning how the DNS protocol works.

Started from Emil Hernvall's guide [dnsguide](https://github.com/EmilHernvall/dnsguide)
but extended with caching, negative caching, name compression, and _some_ security hardening.

## Build

```bash
make
```

## Run

```bash
build/main
```

The server listens on port 2053 over UDP. Test it with dig:

```bash
dig @127.0.0.1 -p 2053 google.com
dig @127.0.0.1 -p 2053 www.yahoo.com MX
dig @127.0.0.1 -p 2053 google.com AAAA
```

## How it works

Incoming queries are received on port 2053 over UDP. Each query is resolved
recursively starting from the root nameservers, walking down the DNS hierarchy
until an answer is found, then returned to the client.

Responses are cached with their TTL so repeated queries are served instantly
without hitting the network again. Negative responses (NXDOMAIN) are also
cached using the TTL from the SOA record.

## Features

- Recursive resolution from root nameservers
- Positive caching with TTL expiration
- Negative caching with SOA minimum TTL
- DNS name compression on responses
- Some Compression pointer security validation


## Packet examples

To view the included packet dumps use hexdump:

```bash
hexdump -C query_packet.txt
hexdump -C response_packet.txt
```
