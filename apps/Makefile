CC := arm-linux-gnueabihf-g++
CCFLAGS := -std=c++11 -Wall

sha3: sha3.cpp
	$(CC) $(CCFLAGS) deps/axidriver.cpp deps/sha3driver.cpp sha3.cpp -o sha3

devicedna: devicedna.cpp
	$(CC) $(CCFLAGS) deps/axidriver.cpp devicedna.cpp -o devicedna

rsa512: rsa512.cpp
	$(CC) $(CCFLAGS) deps/axidriver.cpp deps/rsadriver.cpp rsa512.cpp -o rsa512
