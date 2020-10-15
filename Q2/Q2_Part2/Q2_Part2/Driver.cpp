// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "des.h"
using CryptoPP::DES;

#include "modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "hrtimer.h";

#include "nbtheory.h";

void generatePrimeNumber(CryptoPP::Integer* primes, double* times, int i) {
	AutoSeededRandomPool prng;
	CryptoPP::ThreadUserTimer timer;

	timer.StartTimer();

	CryptoPP::Integer prime = CryptoPP::MaurerProvablePrime(prng, 768);

	double time = timer.ElapsedTimeAsDouble();

	//Set the passed in arrays with the numbers
	primes[i] = prime;
	times[i] = time;

	//return time;
	cout << prime << endl;
	cout << time << endl;
}

int main(int argc, char* argv[])
{
	CryptoPP::Integer primes[10];
	double times[10];

	//int i = 0;
	for (int i = 0; i < 10; i++) {
		generatePrimeNumber(primes, times, i);
	}

	/*
	for (int i = 0; i < 10; i++) {
		cout << "Prime Number 1" << endl;
		cout << primes[10] << endl;
		cout << "Time: " << times[i] << endl;
		cout << endl;
	}
	*/
	
	return 0;
}

