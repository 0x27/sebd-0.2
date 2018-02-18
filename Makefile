CC=gcc
SERVER_LIBS= -lutil -Wall
CLIENT_LIBS= -lcrypt
CLIENT= client
SERVER= sebd
SRC=src
CRYPTO=crypto
BIN=bin
STRIP=strip

all: $(SERVER) $(CLIENT)

$(SERVER):
	$(CC) $(SERVER_LIBS) $(CRYPTO)/aes.c $(CRYPTO)/pel.c $(CRYPTO)/sha1.c $(SRC)/sebd.c -o $(SERVER)
	mv -f $(SERVER) $(BIN)/
	$(STRIP) $(BIN)/$(SERVER)

$(CLIENT):
	$(CC) $(CLIENT_LIBS) $(CRYPTO)/aes.c $(CRYPTO)/pel.c $(CRYPTO)/sha1.c $(SRC)/client.c -o $(CLIENT)
	mv -f $(CLIENT) $(BIN)/
	$(STRIP) $(BIN)/$(CLIENT)

clean:
	rm -rf $(BIN)/$(SERVER) $(BIN)/$(CLIENT)
    
  
