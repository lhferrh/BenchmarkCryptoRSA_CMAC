# BenchmarkCryptoRSA_CMAC
A Benchmark to test signing and verification time taken by CMAC with AES and RSA with the cyphers SHA1, SHA256, Whirlpool, SHA384.

Intructions to run the benchmark:
1- Install crypto++:  sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
2- Create a file book.txt with many lines of text. The program is going to input message from this file.
3- Compile the code: g++ -g3 -ggdb -O3 -DDEBUG -I/usr/include/cryptopp BenchmarkTemplate.cpp -o BenchmarkTemplate.exe -lcryptopp -lpthread
4- Run the code ./NameProgram [iterations] [messageLength] 

