CC=gcc
CFLAGS=-Wall -Wextra -O3 -std=c99
LDFLAGS=-lpcap -lsqlite3 -lpthread

SRCDIR=src
SOURCES=$(wildcard $(SRCDIR)/*.c)
OBJECTS=$(SOURCES:.c=.o)
TARGET=bandwidth_optimizer

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	mkdir -p /etc/bandwidth_optimizer
	cp config/* /etc/bandwidth_optimizer/

.PHONY: all clean install