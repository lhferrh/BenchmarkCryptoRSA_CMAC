// g++ -g3 -ggdb -O3 -DDEBUG -I/usr/include/cryptopp BenchmarkTemplate.cpp -o BenchmarkTemplate.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp BenchmarkCMACandRSA2.cpp -o BenchmarkCMACandRSA2.exe -lcryptopp -lpthread

// sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "cmac.h"
using CryptoPP::CMAC;

#include "aes.h"
using CryptoPP::AES;

#include "sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;
using CryptoPP::SHA384;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;

#include "pssr.h"
using CryptoPP::PSS;

#include "sha.h"
using CryptoPP::SHA1;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/whrlpool.h>

#include <iostream>
#include <fstream>
#include <string>
#include <math.h>
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <sys/time.h>
using namespace std;


/*
       	Constants declaration  
	                                    */
static vector<string> MessageVector;
const char nameFile[] = "Book.txt";

/*
       	End constants declaration  
	                                    */



/*
       	Function section  
	                               */
typedef unsigned long long timestamp_t;
static timestamp_t
// get_timestamp returns a timeStamp
get_timestamp (){
	struct timeval now;
	gettimeofday (&now, NULL);
	return  now.tv_usec + (timestamp_t)now.tv_sec * 1000000;
}

// generateMessageVector generate a vector with messages
void generateMessageVector(int vectorSize, int sizeMessage){
	ifstream file;
    char c;
    file.open (nameFile);
    string message = "";
    int i = 0;
    while( !file.eof() && i < vectorSize*sizeMessage ){
        file.get(c);
        message.push_back(c);
        i++;
        if(  i%sizeMessage == 0 ){
            MessageVector.push_back(message);
            message = "";
        }
    }
    file.close();
}

void SaveKey( const RSA::PublicKey& PublicKey, const string& filename )
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void SaveKey( const RSA::PrivateKey& PrivateKey, const string& filename )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PublicKey& PublicKey )
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

/*
       End function section  
	                               */

struct KeyPairHex {
  string publicKey;
  string privateKey;
};


///  CryptoPP can be SHA1, SHA256, Whirlpool, SHA384

// https://github.com/openssl/openssl/blob/master/include/openssl/sha.h
//using Signer   = CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::Whirlpool>::Signer;
//using Verifier = CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::Whirlpool>::Verifier;


/*
//RSA key generator
KeyPairHex RsaGenerateHexKeyPair(unsigned int aKeySize) {
    KeyPairHex keyPair;

    // PGP Random Pool-like generator
    CryptoPP::AutoSeededRandomPool rng;

    // generate keys
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, aKeySize);
    CryptoPP::RSA::PublicKey publicKey(privateKey);

    // save keys
    publicKey.Save( CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(keyPair.publicKey)).Ref());
    privateKey.Save(CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(keyPair.privateKey)).Ref());

    return keyPair;
}

// RSA Signature generator
string RsaSignString(const string &aPrivateKeyStrHex,
                                 const string &aMessage) {

    // decode and load private key (using pipeline)
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(CryptoPP::StringSource(aPrivateKeyStrHex, true,
                                            new CryptoPP::HexDecoder()).Ref());

    // sign message
    std::string signature;
    Signer signer(privateKey);
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::StringSource ss(aMessage, true,
                                new CryptoPP::SignerFilter(rng, signer,
                                new CryptoPP::HexEncoder(
                                    new CryptoPP::StringSink(signature))));

    return signature;
}


// RSA Verification function
bool RsaVerifyString(const string &aPublicKeyStrHex,
                            const string &aMessage,
                            const string &aSignatureStrHex) {

    // decode and load public key (using pipeline)
    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Load(CryptoPP::StringSource(aPublicKeyStrHex, true,
                                            new CryptoPP::HexDecoder()).Ref());

    // decode signature
    std::string decodedSignature;
    CryptoPP::StringSource ss(aSignatureStrHex, true,
                                new CryptoPP::HexDecoder(
                                new CryptoPP::StringSink(decodedSignature)));

    // verify message
    bool result = false;
    Verifier verifier(publicKey);
    CryptoPP::StringSource ss2(decodedSignature + aMessage, true,
                             new CryptoPP::SignatureVerificationFilter(verifier,
                               new CryptoPP::ArraySink((byte*)&result,
                                                       sizeof(result))));

  return result;
}


// RSA Signature generator
string RsaSign(const  Signer signer, const string &aMessage) {

    // sign message
    string signature;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::StringSource ss(aMessage, true,
                                new CryptoPP::SignerFilter(rng, signer,
                                new CryptoPP::HexEncoder(
                                    new CryptoPP::StringSink(signature))));

    return signature;
}


// RSA Verification function
bool RsaVerify(const Signer verifier,
                            const string &aMessage,
                            const string &aSignatureStrHex) {


    bool result = false;/*
    // decode signature
    std::string decodedSignature;
    CryptoPP::StringSource ss(aSignatureStrHex, true,
                                new CryptoPP::HexDecoder(
                                new CryptoPP::StringSink(decodedSignature)));

    // verify message

    CryptoPP::StringSource ss2(decodedSignature + aMessage, true,
                             new CryptoPP::SignatureVerificationFilter(verifier,
                               new CryptoPP::ArraySink((byte*)&result,
                                                       sizeof(result))));
*//*
  return result;
}


int RSASignatureValidation(){

}

// Benchmarks
int RSABenchamark(int rep,  double *timeB, int key_size = 3072, int max_rep = 1){
    KeyPairHex keypair;
    bool RsaVerification;
    string signature, mac, privKey, plain;
    timestamp_t t0, t1;
    double secsS, secsV;
    int i;
    secsS, secsV = 0;
    //Start key generation
    //RSA key generation
    keypair = RsaGenerateHexKeyPair(key_size);

    //Generate a signer and a verifier for this key.
    CryptoPP::RSA::PublicKey publicKey;
    CryptoPP::RSA::PrivateKey privateKey;
    // decode and load private key (using pipeline)
    privateKey.Load(CryptoPP::StringSource(keypair.privateKey, true, new CryptoPP::HexDecoder()).Ref());
    Signer signer(privateKey);
    // decode and load public key (using pipeline)
    publicKey.Load(CryptoPP::StringSource(keypair.publicKey, true, new CryptoPP::HexDecoder()).Ref());
    Verifier verifier(publicKey);

    i=0;
    while( rep < max_rep ){

        plain = MessageVector[i];
        
        // SIGNATURE
        //___________________________________________________________  INIT TIME 
        t0 = get_timestamp();
        //RSA message signature
        signature = "";
        signature = RsaSignString(keypair.privateKey,plain);
        t1 = get_timestamp();
        //___________________________________________________________  END TIME
        secsS += (t1 - t0) / 1000000.0L;

           
        // MESSAGE VERIFICATION
        //___________________________________________________________  INIT TIME 
        t0 = get_timestamp();
        //RSA message verification
        RsaVerification = RsaVerifyString(keypair.publicKey, plain, signature);
        t1 = get_timestamp();
        if (!RsaVerification){
            cerr << "RSA failed verifying a message" << endl;
            return -1;
        }
        //___________________________________________________________  END TIME
        secsV += (t1 - t0) / 1000000.0L;

        i++;
        if(i >= MessageVector.size() && rep < max_rep){
            i = 0;
            rep++;
        }
    }
    
    if( timeB != NULL ){
        timeB[0] = secsS;
        timeB[1] = secsV;
    }
   
    return 0;
}
*/





class BenchmarkCMAC { 
    private:
        ///  CryptoPP can be SHA1, SHA256, Whirlpool, SHA384
        // https://github.com/openssl/openssl/blob/master/include/openssl/sha.h
        string privKey;
        SecByteBlock key;
        CMAC< AES > cmac;

    public:
        BenchmarkCMAC(unsigned int aKeySize)  : key(aKeySize) {
            this->privKey = "";
            //key = SecByteBlock(aKeySize);
            CmacGenerateHexKey(aKeySize);            
        }

       //CMAC-AES key generator
        void CmacGenerateHexKey(unsigned int aKeySize) {
            string privKey = "";
            AutoSeededRandomPool prng;
            prng.GenerateBlock(this->key, this->key.size()); // Key is a SecByteBlock that contains the key.

            StringSource ss(key, key.size(), true, new HexEncoder(new StringSink(this->privKey)) // HexEncoder
            ); // StringSource

        }
        
        // CMAC-AES Signature generator
        string CmacSignString( const string &aMessage) {
            string mac = "";

            //KEY TRANSFORMATION.
            //SecByteBlock privKey( (const unsigned char *)(aPrivateKeyStrHex.data()), aPrivateKeyStrHex.size()) ;
            
            //CMAC< AES > cmac(this->privKey, this->privKey.size());

            StringSource ss1(aMessage, true, new HashFilter(this->cmac,new StringSink(mac))); 
        
            return mac;
        }

    
        // CMAC-AES Verification function
        bool CmacVerifyString(const string &aMessage,  const string &mac) {
            bool res = true;
            
            // KEY TRANSFORMATION
            //https://stackoverflow.com/questions/26145776/string-to-secbyteblock-conversion
            //SecByteBlock privKey( (const unsigned char *)(aPublicKeyStrHex.data()), aPublicKeyStrHex.size()) ;
            //CMAC< AES > cmac(this->privKey, this->privKey.size());	
            const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

            // MESSAGE VERIFICATION
            //StringSource::StringSource(const char * string, bool pumpAll, BufferedTransformation * attachment = NULL)
            StringSource ss3(aMessage + mac, true, new HashVerificationFilter(this->cmac, NULL, flags)); // StringSource
                        
            return res;
        }
    
        // Benchmarks
        int getPerformance(int iterations,  double *timeB,  int max_rep = 1){
            int k;
            bool CmacVerification = false;
            string signature, mac, privKey, plain;
            timestamp_t t0, t1;
            double secsS, secsV;
            int i, rep;
            secsS, secsV = 0;

            CMAC< AES > cmac(this->key, this->key.size());
            this->cmac = cmac;
            timeB[0] = timeB[1] = 0;
            rep = i = 0;
            cout << rep << "   " << max_rep << endl;
            while( rep < max_rep ){
                plain = MessageVector[i];
                
                // SIGNATURE
                //___________________________________________________________  INIT TIME 
                t0 = get_timestamp();
                //RSA message signature
                mac = "";
                mac = this->CmacSignString(plain);
                t1 = get_timestamp();
                //___________________________________________________________  END TIME
                secsS += (t1 - t0) / 1000000.0L;

                
                // MESSAGE VERIFICATION
                //___________________________________________________________  INIT TIME 
                t0 = get_timestamp();
                //RSA message verification
                CmacVerification = this->CmacVerifyString(plain, mac);
                t1 = get_timestamp();
                if (!CmacVerification){
                    cerr << "RSA failed verifying a message" << endl;
                    return -1;
                }
                //___________________________________________________________  END TIME
                secsV += (t1 - t0) / 1000000.0L;

                i++;
                if(i >= MessageVector.size() && rep < max_rep){
                    k = i;
                    i = 0;
                    rep++;
                }
            }
            
            cout << k << endl;
            //cout << secsS << "   " << secsV << endl;
            if( timeB != NULL ){
                timeB[0] = secsS;
                timeB[1] = secsV;
            }
        
            return 0;
        }
};

/*Class to create a benchmark for RSA*/
template <class T>
class BenchmarkRSA { 
    private:
        ///  CryptoPP can be SHA1, SHA256, Whirlpool, SHA384
        // https://github.com/openssl/openssl/blob/master/include/openssl/sha.h
        KeyPairHex keypair;
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::RSA::PrivateKey privateKey;
        typename CryptoPP::RSASS<CryptoPP::PSSR,  T >::Signer  signer;
        typename CryptoPP::RSASS<CryptoPP::PSSR,  T >::Verifier  verifier;

    public:
        BenchmarkRSA(unsigned int aKeySize){
            RsaGenerateHexKeyPair(aKeySize);
            
            //signer();
            //verifier(this->publicKey);
            
            /*
            typename CryptoPP::RSASS<CryptoPP::PSSR, T >::Signer signer(privateKey);
            typename CryptoPP::RSASS<CryptoPP::PSSR, T >::Verifier verifier(publicKey);
            */
            
            
        }

        //RSA key generator
        void RsaGenerateHexKeyPair(unsigned int aKeySize) {
            // PGP Random Pool-like generator
            CryptoPP::AutoSeededRandomPool rng;
            cout << "key size " << aKeySize << endl;
            // generate keys
            
            this->privateKey.GenerateRandomWithKeySize(rng, aKeySize);
            this->publicKey = (this->privateKey);

            
            this->publicKey.Save( CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(this->keypair.publicKey)).Ref());
            this->privateKey.Save(CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(this->keypair.privateKey)).Ref());


            /*
            //// test
            CryptoPP::RSA::PrivateKey privateKey;
            privateKey.GenerateRandomWithKeySize(rng, aKeySize);
            CryptoPP::RSA::PublicKey publicKey(privateKey);
            //this->signer = CryptoPP::RSASS<CryptoPP::PSSR, T >::Signer(privateKey);
            //this->verifier = CryptoPP::RSASS<CryptoPP::PSSR, T >::Verifier(publicKey);
            

            string signature = "";
            string aMessage = "mierda";
            CryptoPP::StringSource ss(aMessage, true,
                                        new CryptoPP::SignerFilter(rng, this->signer,
                                        new CryptoPP::HexEncoder(
                                            new CryptoPP::StringSink(signature))));
            ///
            */
        }
        
        // RSA Signature generator
        string RsaSign( const string &aMessage) {
            // sign message

            string signature;
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::StringSource ss(aMessage, true,
                                        new CryptoPP::SignerFilter(rng, this->signer,
                                        new CryptoPP::HexEncoder(
                                            new CryptoPP::StringSink(signature))));

            return signature;
        }

        // RSA Verification function
        bool RsaVerify( const string &aMessage, const string &aSignatureStrHex) {
            bool result = false;
            // decode signature
            std::string decodedSignature;
            CryptoPP::StringSource ss(aSignatureStrHex, true,
                                        new CryptoPP::HexDecoder(
                                        new CryptoPP::StringSink(decodedSignature)));

            // verify message
            CryptoPP::StringSource ss2(decodedSignature + aMessage, true,
                                    new CryptoPP::SignatureVerificationFilter(this->verifier,
                                    new CryptoPP::ArraySink((byte*)&result,
                                                            sizeof(result))));
            
            return result;
        }

        // Benchmarks
        int getPerformance(int iterations,  double *timeB,  int max_rep = 1){
            bool RsaVerification = false;
            string signature, mac, privKey, plain;
            timestamp_t t0, t1;
            double secsS, secsV;
            int i, rep;
            secsS, secsV = 0;

            
            typename CryptoPP::RSASS<CryptoPP::PSSR, T >::Signer signer(this->privateKey);
            typename CryptoPP::RSASS<CryptoPP::PSSR, T >::Verifier verifier(this->publicKey);
            this->signer =  signer;
            this->verifier = verifier;
            
            timeB[0] = timeB[1] = 0;
            rep = i = 0;
            cout << rep << "   " << max_rep << endl;
            while( rep < max_rep ){
                plain = MessageVector[i];
                
                // SIGNATURE
                //___________________________________________________________  INIT TIME 
                t0 = get_timestamp();
                //RSA message signature
                signature = "";
                signature = this->RsaSign(plain);
                t1 = get_timestamp();
                //___________________________________________________________  END TIME
                secsS += (t1 - t0) / 1000000.0L;

                
                // MESSAGE VERIFICATION
                //___________________________________________________________  INIT TIME 
                t0 = get_timestamp();
                //RSA message verification
                RsaVerification = this->RsaVerify( plain, signature);
                t1 = get_timestamp();
                if (!RsaVerification){
                    cerr << "CMAC failed verifying a message" << endl;
                    return -1;
                }
                //___________________________________________________________  END TIME
                secsV += (t1 - t0) / 1000000.0L;

                i++;
                if(i >= MessageVector.size() && rep < max_rep){
                    i = 0;
                    rep++;
                }
            }

            //cout << secsS << "   " << secsV << endl;
            if( timeB != NULL ){
                timeB[0] = secsS;
                timeB[1] = secsV;
            }
        
            return 0;
        }
};

int main(int argc, char* argv[])
{
    
    int iterations ;
    int messageSize ;
    int vectorSize = 0;
    int max_rep = 0;
    int i = 0 , RSA_key_size, CMAC_key_size;
    int rep = 0;
	double secsRSASign , secsRSAValidate, secsCMACSign, secsCMACValidate ;
   
    string signature, mac, privKey, plain;
    bool RsaVerification, CmacVerification;
    secsRSASign = secsRSAValidate = secsCMACSign = secsCMACValidate = 0;
    vector<double> secs;
    

    if ( argc < 3){
        cerr << "Missing parameters: "<< argv[0] << " [int]iteration [int]messagaSize" <<endl;
        return -1;
    }
    iterations = atoi(argv[1]);
    messageSize = atoi(argv[2]);
    cout << "Executing " << argv[0] << ", iterations: " << iterations  << ", message size:  " << messageSize << endl;

    if( iterations < 2000000){
        vectorSize = iterations;
        max_rep = 1;
    }
    else{
        vectorSize = 2000000;
        max_rep = iterations/2000000;
    }
    cout << max_rep << endl;
	generateMessageVector(vectorSize,messageSize);
    
   
    double timeB[2];
    //  CryptoPP can be Whirlpool, SHA384
	BenchmarkRSA<CryptoPP::Whirlpool> benchmarkRSAWhirlpool(3072);
    benchmarkRSAWhirlpool.getPerformance(iterations, timeB, max_rep);
    cout << "RSA-Whirlpool" << endl;
    cout << timeB[0] << "   " << timeB[1] << endl;
	
    //  CryptoPP can be  SHA384
	BenchmarkRSA<CryptoPP:: SHA384> benchmarkRSASHA384(3072);
    benchmarkRSASHA384.getPerformance(iterations, timeB, max_rep);

    cout << "RSA-SHA384" << endl;
    cout << timeB[0] << "   " << timeB[1] << endl;

    //  CryptoPP can be SHA256
    BenchmarkRSA<CryptoPP:: SHA256> benchmarkSHA256(3072);
    benchmarkSHA256.getPerformance(iterations, timeB, max_rep);

    cout << "RSA-SHA256" << endl;
    cout << timeB[0] << "   " << timeB[1] << endl;

    // CryptoPP can be SHA1
    BenchmarkRSA<CryptoPP:: SHA1> benchmarkSHA1(3072);
    benchmarkSHA1.getPerformance(iterations, timeB, max_rep);

    cout << "RSA-SHA1" << endl;
    cout << timeB[0] << "   " << timeB[1] << endl;
    
    // CMAC-AES
    BenchmarkCMAC benchmarkCMAC(16);
    benchmarkCMAC.getPerformance(iterations, timeB, max_rep);

    cout << "CMAC-AES" << endl;
    cout << timeB[0] << "   " << timeB[1] << endl;
	//https://www.cryptopp.com/docs/ref/class_p_k___verifier.html#a447ba2b73d8fa9e37b1995f3710032b8

	return 0;
}

