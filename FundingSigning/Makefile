all: cpp-openssl cpp-cryptopp

cpp-openssl:
	g++ -Wall main-openssl.cpp -o signing-example-cpp-openssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto

cpp-cryptopp:
	g++ -Wall main-cryptopp.cpp -o signing-example-cpp-cryptopp -lcryptopp -I../../cryptopp -L../../cryptopp 

clean:
	rm signing-example-cpp-openssl
	rm signing-example-cpp-cryptopp
