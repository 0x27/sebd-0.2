CC=gcc
STRIP=strip
CFLAGS=-O2
CLIBS= -lcrypt

TARGET=mkpasswd

all: $(TARGET)

$(TARGET): 
	$(CC) $(CFLAGS) $(CLIBS) mkpasswd.c -o $(TARGET)
	$(STRIP) mkpasswd

clean:
	rm -rf $(TARGET)
