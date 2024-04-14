SRC=ipk-sniffer.c
OUT=ipk-sniffer
CC=gcc
CFLAGS=-Wall -Werror

run:
	$(CC) $(SRC) $(CFLAGS) -o $(OUT) -lpcap

clean:
	rm $(OUT)