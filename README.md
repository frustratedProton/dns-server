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
To view the included packet dumps, use `hexdump`:

```bash
hexdump -C query_packet.txt
```
```bash
hexdump -C response_packet.txt
```