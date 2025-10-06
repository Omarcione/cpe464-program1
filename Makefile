CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99
LDFLAGS = -lpcap

TARGET = trace
SRC = trace.c eth.c ip.c checksum.c arp.c icmp.c ip.c tcp.c udp.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
