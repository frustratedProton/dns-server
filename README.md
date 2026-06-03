#[WIP] DNS Server.

A very simple DNS server written in C for learning how the DNS protocol works.

### Build

```bash
gcc main.c -o build/main -Wall -Wextra -Wpedantic
```

Run the binary
```bash
build/main
```

### Packet Examples

View the included packet dumps:

hexdump -C query_packet.txt
hexdump -C response_packet.txt