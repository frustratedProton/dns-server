CC     = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Iinclude
SRC    = src/buffer.c \
         src/packet.c \
         src/cache.c  \
         src/resolver.c \
         src/main.c
TARGET = build/main

$(TARGET): $(SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: clean