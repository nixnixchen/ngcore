# CC = g++

LIBDIR = ./lib
BIN_DIR = ./bin

INCLUDES = -I include

LDFLAGS = -static -L$(LIBDIR) -lLIEF
CFLAGS :=  -O2 -Wall -fPIC -g $(INCLUDES) $(LDFLAGS)

SRCS = src/ngcore.c src/elf_parser.c
OBJS = $(SRCS:.c=.o)

all:  ngcore

ngcore:$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN_DIR)/$@ 

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

elf_parser: src/elf_parser.c
	$(CC)  $< -o $(BIN_DIR)/$@ $(CFLAGS)

clean:
	rm -f ngcore

.PHONY: all clean
