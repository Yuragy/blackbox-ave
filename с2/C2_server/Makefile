CC = gcc
BUILD_TYPE ?= release

CFLAGS_RELEASE = -O2 -Wall -pthread
CFLAGS_DEBUG = -g -O0 -Wall -pthread

ifeq ($(BUILD_TYPE),debug)
	CFLAGS = $(CFLAGS_DEBUG)
else
	CFLAGS = $(CFLAGS_RELEASE)
endif

TARGET = c2_server

all: $(TARGET)

$(TARGET): c2_server.c config.h
	$(CC) $(CFLAGS) -o $(TARGET) c2_server.c

config.h: config.h.in
	@echo "#define DEFAULT_PORT 4444" > config.h
	@echo "#define BUFFER_SIZE 512" >> config.h
	@echo "#define MAX_CLIENTS 100" >> config.h

clean:
	rm -f $(TARGET) config.h
