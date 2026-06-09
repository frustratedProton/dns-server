#ifndef BUFFER_H
#define BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BUFFER_SIZE 512
#define QNAME_MAX 256
#define COMPRESS_MAX 64

typedef struct {
  uint8_t buf[BUFFER_SIZE];
  size_t pos;
} BytePacketBuffer;

void buffer_init(BytePacketBuffer *bfp);
int buffer_step(BytePacketBuffer *bfp, size_t steps);
int buffer_seek(BytePacketBuffer *bfp, size_t pos);
int buffer_read(BytePacketBuffer *bfp, uint8_t *out);
int buffer_get(BytePacketBuffer *bfp, size_t pos, uint8_t *out);
int buffer_read_u16(BytePacketBuffer *bfp, uint16_t *out);
int buffer_read_u32(BytePacketBuffer *bfp, uint32_t *out);
int buffer_set(BytePacketBuffer *bfp, size_t pos, uint8_t val);
int buffer_set_u16(BytePacketBuffer *bfp, size_t pos, uint16_t val);
int buffer_read_qname(BytePacketBuffer *bfp, char *out, size_t out_size);

typedef struct {
  char name[QNAME_MAX];
  size_t offset;
} CompressEntry;

typedef struct {
  CompressEntry entries[COMPRESS_MAX];
  size_t count;
} CompressTable;

void compress_table_init(CompressTable *ct);
int compress_table_find(CompressTable *ct, const char *name);
void compress_table_add(CompressTable *ct, const char *name, size_t offset);

int buffer_write(BytePacketBuffer *bfp, uint8_t val);
int buffer_write_u8(BytePacketBuffer *bfp, uint8_t val);
int buffer_write_u16(BytePacketBuffer *bfp, uint16_t val);
int buffer_write_u32(BytePacketBuffer *bfp, uint32_t val);
int buffer_write_qname(BytePacketBuffer *bfp, const char *qname);
int buffer_write_qname_compressed(BytePacketBuffer *bfp, const char *qname,
                                  CompressTable *ct);

#endif