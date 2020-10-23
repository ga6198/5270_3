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

#include "rsa.h";
#include "rsa.cpp";
#include <fstream>;

bool inArray(CryptoPP::Integer arr[10], CryptoPP::Integer itemToFind) {
	for (int i = 0; i < 10; i++) {
		if (arr[i] == itemToFind) {
			return true;
		}
	}

	return false;
}

void generatePrimeNumber(CryptoPP::Integer(&primes)[10], double(&times)[10], int i) {
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

void printThroughput(double total_time, double total_bytes) {
	cout << "Time: " << total_time << " seconds" << endl;
	double throughput = total_bytes / total_time;
	cout << "Throughput: " << throughput << " bytes per second" << endl;
	cout << endl;
}

void encAndDec(int n, int input_e, string plaintext) {
	
	AutoSeededRandomPool rng;

	CryptoPP::AlgorithmParameters settings = CryptoPP::MakeParameters(CryptoPP::Name::ModulusSize(), n)(CryptoPP::Name::PublicExponent(), input_e);

	CryptoPP::InvertibleRSAFunction params;
	//params.GenerateRandomWithKeySize(rng, n); // n of 768 will generate p and q of 384 bits
	params.GenerateRandom(rng, settings);

	CryptoPP::Integer na = params.GetModulus();
	//params.SetModulus(asdf);
	CryptoPP::Integer pa = params.GetPrime1();
	CryptoPP::Integer qa = params.GetPrime2();

	//reset e and d according to assignment
	//CryptoPP::Integer e = CryptoPP::Integer(input_e);
	//CryptoPP::Integer d = e.InverseMod(CryptoPP::LCM(pa - 1, qa - 1));
	//params.SetPublicExponent(e);
	//params.SetPrivateExponent(d);

	CryptoPP::Integer da = params.GetPrivateExponent();
	CryptoPP::Integer ea = params.GetPublicExponent();

	cout << "RSA Parameters:" << endl;
	cout << " n: " << na << endl;
	cout << " p: " << pa << endl;
	cout << " q: " << qa << endl;
	cout << " d: " << da << endl;
	cout << " e: " << ea << endl;

	//Keys
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);

	cout << "Private key ok: " << privateKey.Validate(rng, 3) << endl;

	//Encryption
	//read from file
	double total_bytes = 1040384; //1 char is 1 bytes, 1040384 characters total
	double total_time = 0;
	CryptoPP::RSAES_OAEP_SHA_Encryptor enc(publicKey);

	int plain_max_length = enc.FixedMaxPlaintextLength();

	cout << "Max plaintext length: " << plain_max_length << endl;

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();
	
	string ciphertext = "";
	cout << "Encrypting..." << endl;
	for (int i = 0; i < total_bytes; i = i + plain_max_length) {
		string current_plain = plaintext.substr(i, plain_max_length); //get 54 characters
		//cout << current_plain << endl;

		string current_cipher;
		try {
			//StringSource ss1(plaintext, true,
			StringSource ss1(current_plain, true,
				new CryptoPP::PK_EncryptorFilter(rng, enc,
					new StringSink(current_cipher)
				) // PK_EncryptorFilter
			); // StringSource
			//cout << current_cipher.length() << endl;
			ciphertext += current_cipher;
		}
		catch (CryptoPP::Exception & e) {
			cout << e.what() << endl;
		}
	}
	total_time = timer.ElapsedTimeAsDouble();
	printThroughput(total_time, total_bytes);

	//cout << ciphertext << endl;

	//Decryption
	CryptoPP::RSAES_OAEP_SHA_Decryptor dec(privateKey);
	int cipher_max_length = dec.FixedCiphertextLength();
	cout << "Max ciphertext length: " << cipher_max_length << endl;

	CryptoPP::ThreadUserTimer decTimer;
	decTimer.StartTimer();

	string recoveredPlaintext = "";
	SecByteBlock recovered(dec.MaxPlaintextLength(ciphertext.size()));
	cout << "Decrypting..." << endl;
	
	//dec.Decrypt(rng, (CryptoPP::byte*)ciphertext, ciphertext.size(), recovered);

	for (int i = 0; i < total_bytes; i = i + cipher_max_length) {
		string current_cipher = ciphertext.substr(i, cipher_max_length); 
		//cout << current_cipher << endl;

		string current_plain;
		try {
			//StringSource ss1(plaintext, true,
			StringSource ss1(current_cipher, true,
				new CryptoPP::PK_DecryptorFilter(rng, dec,
					new StringSink(current_plain)
				) // PK_DecryptorFilter
			); // StringSource

			recoveredPlaintext += current_plain;
		}
		catch (CryptoPP::Exception & e) {
			cout << e.what() << endl;
		}
	}
	total_time = decTimer.ElapsedTimeAsDouble();
	printThroughput(total_time, total_bytes);

	//cout << "Recovered plaintext:" << endl;
	//cout << recoveredPlaintext << endl << endl;
}

int main(int argc, char* argv[])
{
	//Load the plaintext for both encryptions and decryptions
	string plaintext = "";
	std::ifstream myfile("plain.txt");
	if (myfile.is_open()) {
		string line;
		while (getline(myfile, line)) {
			plaintext += line;
		}

		myfile.close();
	}
	//cout << plaintext << endl;

	cout << "Encryption and Decryption with n=768, e=65537" << endl;
	encAndDec(768, 65537, plaintext); //54 keylength

	cout << "Encryption and Decryption with n=1024, e=5" << endl;
	encAndDec(1024, 5, plaintext); //86 keylength
	
	/*
	AutoSeededRandomPool rng;

	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 768); //will generate p and q of 384 bits


	CryptoPP::Integer na = params.GetModulus();
	//params.SetModulus(asdf);
	CryptoPP::Integer pa = params.GetPrime1();
	CryptoPP::Integer qa = params.GetPrime2();

	//reset e and d according to assignment
	CryptoPP::Integer e = CryptoPP::Integer(65537);
	CryptoPP::Integer d = e.InverseMod(CryptoPP::LCM(pa-1, qa-1));
	params.SetPublicExponent(e);
	params.SetPrivateExponent(d);

	CryptoPP::Integer da = params.GetPrivateExponent();
	CryptoPP::Integer ea = params.GetPublicExponent();

	cout << "RSA Parameters:" << endl;
	cout << " n: " << na << endl;
	cout << " p: " << pa << endl;
	cout << " q: " << qa << endl;
	cout << " d: " << da << endl;
	cout << " e: " << ea << endl;
	
	//Keys
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);
	
	//Encryption
	//read from file
	double total_bytes = 1040384; //1 char is 1 bytes, 1040384 characters total
	double total_time = 0;
	CryptoPP::RSAES_OAEP_SHA_Encryptor enc(publicKey);
	
	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();
	
	for (int i = 0; i < total_bytes; i = i + 54) {
		string current_plain = plaintext.substr(i, 54); //get 54 characters
		cout << current_plain << endl;

		string ciphertext;
		try {
			//StringSource ss1(plaintext, true,
			StringSource ss1(current_plain, true,
				new CryptoPP::PK_EncryptorFilter(rng, enc,
					new StringSink(ciphertext)
				) // PK_EncryptorFilter
			); // StringSource
		}
		catch (CryptoPP::Exception & e) {
			cout << e.what() << endl;
		}

		
	}
	total_time = timer.ElapsedTimeAsDouble();
	*/

























	//n: 768 bits, e: 65537 bits

	//Generating first key
	//AutoSeededRandomPool prng;
	//CryptoPP::Integer p = CryptoPP::MaurerProvablePrime(prng, 384);
	//CryptoPP::Integer q = CryptoPP::MaurerProvablePrime(prng, 384);

	/*
	//CryptoPP::InvertibleRSAFunction params;
	AutoSeededRandomPool prng;
	CryptoPP::Integer e = CryptoPP::Integer(65537);
	CryptoPP::RSAPrimeSelector selector(e);
	
	//Generate close primes p and q
	CryptoPP::AlgorithmParameters primeParam = CryptoPP::MakeParametersForTwoPrimesOfEqualSize(768) //n of 768 bits
	(CryptoPP::Name::PointerToPrimeSelector(), selector.GetSelectorPointer());
	CryptoPP::Integer p;
	CryptoPP::Integer q;
	p.GenerateRandom(prng, primeParam);
	q.GenerateRandom(prng, primeParam);

	cout << p << endl;
	cout << q << endl;
	
	//calculate d
	CryptoPP::Integer d = e.InverseMod(CryptoPP::LCM(p-1, q-1));

	//calculate n
	CryptoPP::Integer n = p * q;

	//Set Parameters for RSA


	CryptoPP::RSA::PrivateKey privateKey();
	*/

	return 0;
}

