FLAGS = -Wall -Wextra -pedantic -std=c++14 -Wno-vla-extension
# macOS w/ Homebrew
OPENSSL = -I/usr/local/Cellar/openssl@1.1/1.1.1d/include -L/usr/local/Cellar/openssl@1.1/1.1.1d/lib

# remote cs w/ Linuxbrew
# OPENSSL = -I/import/linux/home1/zhalper3/.linuxbrew/Cellar/openssl/1.0.2p/include -L/import/linux/home1/zhalper3/.linuxbrew/Cellar/openssl/1.0.2p/lib

all: fscrypt

fscrypt: fscrypt.cpp main.cpp
	g++ $(FLAGS) $(OPENSSL) main.cpp fscrypt.cpp -lcrypto -o fscrypt

run: fscrypt
	./fscrypt

clean:
	rm fscrypt

.PHONY: clean run