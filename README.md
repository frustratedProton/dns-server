# [WIP] DNS Server

A very simple DNS server written in C for learning how the DNS protocol works.

Based on Emil Hernvall's guide [dnsguide](https://github.com/EmilHernvall/dnsguide).

## Build

```bash
gcc main.c -o build/main -Wall -Wextra -Wpedantic
```

### Run

```bash
build/main
```

The server listens on port 2053 by default. Test it with dig:

```bash
dig @127.0.0.1 -p 2053 google.com
dig @127.0.0.1 -p 2053 www.yahoo.com MX
dig @127.0.0.1 -p 2053 google.com AAAA
```

### How it works

Incoming queries are received on port 2053 over UDP. 
Each query is forwarded recursively starting from the root nameservers, walking down the DNS hierarchy 
until an answer is found, then returned to the client.

### Supported record types

- A
- AAAA
- NS
- CNAME
- MX

### Packet Examples

To view the included packet dumps, use `hexdump`:

```bash
hexdump -C query_packet.txt
```
```bash
hexdump -C response_packet.txt
```
