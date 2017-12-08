#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include <functional>
#include <memory>
#include <stdexcept>
#include <random>
#include <chrono>
#include <gmpxx.h>
#include <functional>

#include "cryptomath.h"

using namespace std;

enum class Mode{None, Encrypt, Decrypt, Generate};

struct rsa_key
{
    mpz_class n;
    mpz_class de;
};

bool processArgs(int argc, char** argv, Mode& op, string& file1, string& file2, string& file3, uint64_t& bits);
void help(string name, string msg = "");

void generateKey(const uint64_t& bits, pair<rsa_key, rsa_key>& out);
void loadKey(istream& in, rsa_key& key);
void saveKey(ostream& out, rsa_key& key);

void encrypt(istream& in, ostream& out, const rsa_key& publick);
void decrypt(istream& in, ostream& out, const rsa_key& privatek);

uint64_t blockSize(const mpz_class& n);

int main(int argc, char** argv)
{
    string file1, file2, file3;
    uint64_t bits;
    Mode operation;

    if(!processArgs(argc, argv, operation, file1, file2, file3, bits))
    {
        return 1;
    }
    
    if(operation == Mode::Generate)
    {
        ofstream pub(file1);
        if(!pub)
        {
            cerr << "Unable to open public key file " << file1 << endl;
            return 2;
        }

        ofstream priv(file2);
        if(!priv)
        {
            cerr << "Unable to open private key file " << file2 << endl;
            pub.close();
            return 2;
        }

        try{
            cout << "Generating keys..." << endl;
            pair<rsa_key, rsa_key> keys;
            generateKey(bits, keys);
            cout << "Saving keys..." << endl;
            saveKey(pub, keys.first);
            saveKey(priv, keys.second);
        }catch(exception& ex){
            cerr << "Unable to generate public/private pair: " << ex.what() << endl;
            pub.close();
            priv.close();
            return 5;
        }

        pub.close();
        priv.close();
    }
    else
    {
        ifstream fin(file1);
        if(!fin)
        {
            cerr << "Unable to open input file " << file1 << endl;
            return 2;
        }

        ofstream fout(file2);
        if(!fout)
        {
            cerr << "Unable to open output file " << file2 << endl;
            fin.close();
            return 2;
        }

        ifstream keyFile(file3);
        if(!keyFile)
        {
            cerr << "Unable to open key file " << file3 << endl;
            fin.close();
            fout.close();
            return 2;
        }

        rsa_key k;
        try{
            cout << "Loading key..." << endl;
            loadKey(keyFile, k);
        }catch(exception& ex){
            cerr << "Unable to load key: " << ex.what() << endl;
            fin.close();
            fout.close();
            keyFile.close();
            return 3;
        }

        try{
            cout << "Processing file..." << endl;
            if(operation == Mode::Encrypt)
            {
                encrypt(fin, fout, k);
            }
            else
            {
                decrypt(fin, fout, k);
            }
        }catch(exception& ex){
            cerr << "Error during processing: " << ex.what() << endl;
            fin.close();
            fout.close();
            keyFile.close();
            return 4;
        }

        fin.close();
        fout.close();
        keyFile.close();
    }

    return 0;
}

void generateKey(const uint64_t& bits, pair<rsa_key, rsa_key>& out)
{
    auto t = std::chrono::system_clock::now();
    mt19937_64 reng(chrono::duration_cast<chrono::milliseconds>(t.time_since_epoch()).count());

    //Choose e to be 65537
    out.first.de = 65537;

    //Pick p until p % e is not 1
    mpz_class p;
    do
    {
        p = cryptomath::randomPrime<mpz_class, mt19937_64>(reng, bits/2);
    }while(cryptomath::mod<mpz_class>(p, out.first.de) == 1);

    //Pick q until q % e is not 1
    mpz_class q; 
    do
    {
        q = cryptomath::randomPrime<mpz_class, mt19937_64>(reng, bits-bits/2);
    }while(cryptomath::mod<mpz_class>(q, out.first.de) == 1);

    //Calculate n
    out.first.n = out.second.n = p * q;

    if(out.first.n < 256)
        throw std::logic_error("n less than 256, use more bits");

    //Calculate phi(n)
    mpz_class phi = (p - 1) * (q - 1);

    //Calculate d
    out.second.de = cryptomath::inverseMod<mpz_class>(out.first.de, phi);
}

void loadKey(istream& in, rsa_key& key)
{
    in >> hex >> key.de >> key.n;
}

void saveKey(ostream& out, rsa_key& key)
{
    out << hex << key.de << endl << key.n << endl;
}

uint64_t blockSize(const mpz_class& n)
{
    mpz_class a = 1;
    uint64_t p = 0;

    while(a*255 < n)
    {
        a = a*256;
        p++;
    }

    return p;
}

void encrypt(istream& in, ostream& out, const rsa_key& publick)
{
    uint64_t chars = blockSize(publick.n);
    while(in)
    {
        //Buffer
        unsigned char c = 0;

        //Block
        mpz_class block = 0;

        //Read a block or until end of file; whichever is first
        for(uint64_t i=0; i < chars && (c = in.get()); block = block + c*cryptomath::powInt<mpz_class>(256, chars-(i++)-1));

        //Encrypt and write
        out << hex << cryptomath::powMod<mpz_class>(block, publick.de, publick.n) << " ";
    }
}

void decrypt(istream& in, ostream& out, const rsa_key& privatek)
{
    uint64_t chars = blockSize(privatek.n);  
    
    while(in)
    {
        //Buffer
        mpz_class block;

        //Read block
        in >> hex >> block;

        //Decrypt
        block = cryptomath::powMod<mpz_class>(block, privatek.de, privatek.n);

        //Divider
        mpz_class power = cryptomath::powInt<mpz_class>(256, chars-1);

        //Decompose into characters and write
        for(uint64_t i=0; i < chars; i++)
        {
            unsigned char c = mpz_class(block / power).get_ui();
            block = block - c*power;
            power = power / 256;
            out << c;
        }
    }
}

bool processArgs(int argc, char** argv, Mode& op, string& file1, string& file2, string& file3, uint64_t& bits)
{
    file1 = file2 = file3 = "";
    bits = 0;

    op = Mode::None;

    for(int i=1; i<argc; i++)
    {
        string arg = argv[i];

        if(arg == "-g")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose 1 mode [-g, -e, -d]");
                return false;
            }

            op = Mode::Generate;
            if(i >= argc - 3)
            {
                help(argv[0], "Generate with -g [public key file] [private key file] [bits]");
                return false;
            }

            file1 = argv[++i];
            file2 = argv[++i];

            try{
                bits = stoull(argv[++i]);
            }catch(exception& ex){
                help(argv[0], "Failed to convert " + string(argv[i]) + " to a number: " + ex.what());
                return false;
            }
        }
        else if(arg == "-e")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose 1 mode [-g, -e, -d]");
                return false;
            }

            op = Mode::Encrypt;
            if(i >= argc - 3)
            {
                help(argv[0], "Encrypt with -e [input file] [output file] [public key file]");
                return false;
            }

            file1 = argv[++i];
            file2 = argv[++i];
            file3 = argv[++i];
        }
        else if(arg == "-d")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose 1 mode [-g, -e, -d]");
                return false;
            }

            op = Mode::Decrypt;
            if(i >= argc - 3)
            {
                help(argv[0], "Encrypt with -e [input file] [output file] [private key file]");
                return false;
            }

            file1 = argv[++i];
            file2 = argv[++i];
            file3 = argv[++i];
        }
        else if(arg == "-h")
        {
            help(argv[0], "");
            return false;
        }
        else
        {
            help(argv[0], "Unknown option: " + arg);
            return false;
        }
    }

    if(op == Mode::None)
    {
        help(argv[0], "Choose 1 mode [-g, -e, -d]");
        return false;
    }

    return true;
}

void help(string name, string msg)
{
    cout << msg << endl;
}
