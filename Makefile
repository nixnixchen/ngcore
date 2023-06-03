# CC = g++

LIBDIR = ./lib
BIN_DIR = ./bin

INCLUDES = -I include

LDFLAGS = -static -L$(LIBDIR) -lLIEF
CFLAGS :=  -O2 -Wall -fPIC -g $(INCLUDES) $(LDFLAGS)

all:  ngcore

ngcore: src/ngcore.c
	$(CC)  $< -o $(BIN_DIR)/$@ $(CFLAGS)

elf_test: src/modify_elf.c
	$(CC)  $< -o $(BIN_DIR)/$@ $(CFLAGS)

clean:
	rm -f ngcore

.PHONY: all clean
