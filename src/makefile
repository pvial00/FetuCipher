CC=gcc
CFLAGS=-O3 -std=c99
TARGET=fetucrypt
all: $(TARGET)

$(TARGET): fetu_crypt.c
	$(CC) fetu_crypt.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
