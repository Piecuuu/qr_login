LIBS = -lcjson -lwebsockets -lcrypto -lcurl

debug: CFLAGS ?= -g
debug:
	$(CC) qr_login.c -std=gnu99 $(CFLAGS) $(LDFLAGS) $(LIBS) -o qr_login

release: CFLAGS ?= -O2
release:
	$(CC) qr_login.c -std=gnu99 $(CFLAGS) $(LDFLAGS) $(LIBS) -o qr_login

clean:
	-rm qr_login
