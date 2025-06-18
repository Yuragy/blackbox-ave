CC = gcc
BUILD_TYPE ?= release

CFLAGS_RELEASE = -O2 -Wall -pthread `pkg-config --cflags sqlite3`
CFLAGS_DEBUG = -g -O0 -Wall -pthread `pkg-config --cflags sqlite3`

ifeq ($(BUILD_TYPE),debug)
	CFLAGS = $(CFLAGS_DEBUG)
else
	CFLAGS = $(CFLAGS_RELEASE)
endif

TARGET = c2_client

all: $(TARGET)

$(TARGET): c2_client.c sql_manager.c config.h
	$(CC) $(CFLAGS) -o $(TARGET) c2_client.c sql_manager.c -lsqlite3

config.h: config.h.in
	@echo "#define SERVER_IP \"127.0.0.1\"" > config.h
	@echo "#define SERVER_PORT 4444" >> config.h
	@echo "#define BUFFER_SIZE 512" >> config.h
	@echo "#define DB_PATH \"client_events.db\"" >> config.h

clean:
	rm -f $(TARGET) config.h
