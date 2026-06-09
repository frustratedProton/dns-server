#include "../include/buffer.h"
#include <ctype.h>
#include <string.h>

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

void compress_table_init(CompressTable *ct) { ct->count = 0; }

int compress_table_find(CompressTable *ct, const char *name) {
  for (size_t i = 0; i < ct->count; i++)
    if (strcmp(ct->entries[i].name, name) == 0)
      return (int)ct->entries[i].offset;
  return -1;
}

void compress_table_add(CompressTable *ct, const char *name, size_t offset) {
  if (ct->count >= COMPRESS_MAX)
    return;
  strncpy(ct->entries[ct->count].name, name, QNAME_MAX - 1);
  ct->entries[ct->count].name[QNAME_MAX - 1] = '\0';
  ct->entries[ct->count].offset = offset;
  ct->count++;
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

      uint16_t offset = (((uint16_t)len ^ 0xC0) << 8) | b2;

      if (offset >= BUFFER_SIZE)
        return -1;
      if (offset >= pos)
        return -1;

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

int buffer_write_qname_compressed(BytePacketBuffer *bfp, const char *qname,
                                  CompressTable *ct) {
  char tmp[QNAME_MAX];
  strncpy(tmp, qname, QNAME_MAX - 1);
  tmp[QNAME_MAX - 1] = '\0';

  char *cursor = tmp;

  while (*cursor != '\0') {
    // check if suffix exists in CompressTable
    int found = compress_table_find(ct, cursor);
    if (found >= 0) {
      //   write a compression pointer
      if (buffer_write_u8(bfp, 0xC0 | ((found >> 8) & 0xFF)))
        return -1;
      if (buffer_write_u8(bfp, found & 0xFF))
        return -1;
      return 0;
    }

    compress_table_add(ct, cursor, bfp->pos);

    char *dot = strchr(cursor, '.');
    size_t label_len = dot ? (size_t)(dot - cursor) : strlen(cursor);

    if (label_len > 0x3f)
      return -1;

    if (buffer_write_u8(bfp, (uint8_t)label_len))
      return -1;
    for (size_t i = 0; i < label_len; i++) {
      if (buffer_write_u8(bfp, (uint8_t)cursor[i]))
        return -1;
    }

    cursor += label_len;
    if (*cursor == '.')
      cursor++;
  }
  return buffer_write_u8(bfp, 0);
}
