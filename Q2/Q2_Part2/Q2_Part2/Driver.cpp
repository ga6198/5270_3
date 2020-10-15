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

bool inArray(CryptoPP::Integer arr[10], CryptoPP::Integer itemToFind) {
	for (int i = 0; i < 10; i++) {
		if (arr[i] == itemToFind) {
			return true;
		}
	}

	return false;
}

void generatePrimeNumber(CryptoPP::Integer (&primes)[10], double (&times)[10], int i) {
	AutoSeededRandomPool prng;
	CryptoPP::ThreadUserTimer timer;

	timer.StartTimer();

	CryptoPP::Integer prime = CryptoPP::MaurerProvablePrime(prng, 768);

	double time = timer.ElapsedTimeAsDouble();

	//check if the number was in the array already
	while (inArray(primes, prime)) {
		//if in the array, regenerate the number
		prime = CryptoPP::MaurerProvablePrime(prng, 768);

		time = timer.ElapsedTimeAsDouble();
	}

	//Set the passed in arrays with the numbers
	primes[i] = prime;
	times[i] = time;

	//return time;
	//cout << prime << endl;
	//cout << time << endl;

	cout << "Number " << i << " generated" << endl;
}

int main(int argc, char* argv[])
{
	CryptoPP::Integer primes[10];
	double times[10];

	//int i = 0;
	for (int i = 0; i < 10; i++) {
		generatePrimeNumber(primes, times, i);
	}

	
	for (int i = 0; i < 10; i++) {
		cout << "Prime Number " << i << endl;
		cout << primes[i] << endl;
		cout << "Generation Time: " << times[i] << " seconds" << endl;
		cout << endl;
	}
	
	
	return 0;
}

