/*! \file

\page rsa RSA Tool

\section background_rsa
The RSA (Rivest–Shamir–Adleman) algorithm is a public/private key system based upon the commonly 
accepted idea that factoring very large numbers is difficult. 

The general algorithm is as follows
    - Person A picks two large numbers, \f$ p \f$ and \f$ q \f$
    - Person A computes \f$ n = p*q \f$
    - Person A computes \f$ \phi(n) = (p-1)(q-1)\f$
    - Person A picks some \f$ e \f$, the encryption exponent, such that \f$ 1 < e < \phi(n) \f$ and \f$ gcd(e, \phi(n)) = 1 \f$
    - Person A computes \f$ d \f$ such that \f$ de = 1 \f$ mod \f$ \phi(n) \f$
    - Person A publishes \f$ e, n \f$ - This is the public key
    - Person B has a message \f$ m \f$ to send Person A
    - Person B computes \f$ c = m^e\f$ mod \f$ n \f$ (If \f$ m > n \f$, break it into pieces)
    - Person B sends \f$ c \f$ to Person A
    - Person A decrypts \f$ m = c^d \f$ mod \f$ n \f$

The basis for this algorithm lies in Fermat's Little Theorem(\f$ a^{p-1} = 1 \f$ mod \f$ p \f$) and the fact that
\f$ ed = 1 \f$ mod \f$ \phi(n) \f$. 

We can write \f$ ed-1 = 0 \f$ mod \f$ \phi(n) \f$, which means \f$ ed-1 \f$ divides \f$ \phi(n) \f$ or \f$ ed-1 = k(p-1) = h(q-1) \f$ for some \f$ k, h \f$.

So, if we write our encrypted message using this exponent, we can see that \f$ m^{ed} \f$ is clearly just \f$ m \f$
\f[m^{ed} = m^{ed-1}m = m^{k(p-1)}m = m^{(p-1)^k}m \f]
If we're working mod \f$ p \f$, then we can write \f$ m^{(p-1)^k}m = m^{1^k}m = m^1m = m \f$. By a similar argument, the same applies to \f$ q \f$, so
we can know that working mod \f$ pq = n \f$, the statement holds.

As stated above, the encryption exponent \f$ e \f$ and \f$ n \f$ make up the public key. The private key is made up of \f$ d \f$, the decryption exponenet
and \f$ n \f$. It seems pretty obvious that the private key, \f$ p \f$, and \f$ q \f$ should be kept private; however, it is less obvious that \f$ \phi(n) \f$
should also remain private. This is because knowing \f$ \phi(n) \f$ is enough information to factor \f$ n \f$. Once that is done, \f$ d \f$ can be found.

Another less obvious note is that the messages encrypted using this method should not be Much Smaller than \f$ n \f$. If they are, then
the cipher value is weak against a Low Exponent Attack, and may be decrypted by brute force.

\subsection messages_rsa Building Messages
The math above shows that RSA can be used for messages which are large numbers. To send a string of text as a message, we must convert
it into such a number. One option would be to determine the maximum number of bits that can be fit in n, take that many bits from the input, and
use them as an integer; however, this can be difficult to work with if that number of bits is not an even number of bytes. This tool uses a 
different algorithm to generate messages.

Assuming that we are working with bytes of data, each byte will be in the range 0-255. If we take two bytes, a and b, and sum
a*256 + b, we have a number that is unique to that string ab. It can also be decomposed to a and b by first taking doing an integer
divison by 256 to get a and then modding it by 256 to get b. This tool uses a generalized version of this idea to encrypt any number
of bytes into a large number. The number of bytes is determined to be the floor of log \f$_256\f$ of \f$ n \f$ + 1. This ensures that,
by using successive powers of 256 to encrypt bytes, we can get a message close to \f$ n \f$ which can be decomposed back into the
original string.

\section compile_rsa Compiling
This tool can be built with the command 
\verbatim 
make
\endverbatim
This will generate a release version of the tool in the release directory. To build a debug version in the debug directory,
use the command 
\verbatim
make BUILD_TYPE=debug
\endverbatim

This tool requires having GMP installed.

\section usage_rsa Usage
This tool can be used to generate public and private key pairs, as well as encrypt and decrypt messages.

\verbatim
tool_rsa -g public private bits
tool_rsa -e/-d input output key
\endverbatim
Mode Options
    - -g : To generate a public, private key pair. 
           Specify output files for the public key and private key, as well as the number of bits n should contain
    - -e : To encrypt
    - -d : To decrypt

Input Options
    - The input for encryption or decryption is a file name

Output Options
    - The output for encryption or decryption is a file name

Key Options
    - The key should be the file name of the key to use.

Keys should generally be larger than 2048 bits for security; 3072 bits if they will be used through the year 2030.
Picking a number of bits less than 8 will fail because n must be at least 256
The key file for encryption should be a public key, and for decryption should the matching private key.
*/

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

//! Enums for this tool
namespace enums {
    //! Mode options
    enum class Mode{None, Encrypt, Decrypt, Generate};
}

using namespace enums;

//! Container for some \f$ n \f$ and either \f$ e \f$ or \f$ d \f$
struct rsa_key
{
    //! The modulus n
    mpz_class n;
    //! Either the encryption or decryption exponent
    mpz_class de;
};

/*! Processes the command line arguments

If the arguments are invalid, a usage prompt is printed with an error message

\param[in] argc Number of arguments
\param[in] argv The arguments
\param[out] op The operation to perform
\param[out] file1 The first file parameter
\param[out] file2 The second file parameter
\param[out] file3 The third file parameter for encryption or decryptino
\param[out] bits The number of bits to use if generating a key
\returns bool - Whether or not the arguments were valid
*/
bool processArgs(int argc, char** argv, Mode& op, string& file1, string& file2, string& file3, uint64_t& bits);

/*! Prints the program usage prompt with an error message

\param[in] name Name of the program
\param[in] msg Error message to print
*/
void help(string name, string msg = "");

/*! Generates an RSA public, private key pair.

    \f$ e \f$ is chosen to be 65537, and then random \f$ p, q \f$ are generated with bits/2 bits
    until \f$ gcd(p, e) = gcd(q, e) = 1 \f$. At that point, \f$ n \f$ and \f$ d \f$ can be calculated.

    \param[in] bits Number of bits in \f$ n \f$
    \param[out] pair<rsa_key, rsa_key>& the public, private pair generated
*/
void generateKey(const uint64_t& bits, pair<rsa_key, rsa_key>& out);

/*! Loads a generated key from an input stream

    The key is assumed to be first either \f$ e \f$ or \f$ d \f$, then whitespace, then \f$ n \f$,
    written in hexadecimal.

    \param[in,out] in The stream to read from
    \param[out] key The key read
*/
void loadKey(istream& in, rsa_key& key);

/*! Saves a generated key to an output stream

    The key is saved in the form of either \f$ e \f$ or \f$ d \f$, then whitespace, then \f$ n \f$,
    written in hexadecimal.

    \param[in,out] in The stream to write to
    \param[in] key The key to write
*/
void saveKey(ostream& out, rsa_key& key);

/*! Encrypts all data in a stream and writes it to an output stream

    \param[in,out] in The stream to read
    \param[in,out] out The stream to write
    \param[in] publick The public key to encrypt with
*/
void encrypt(istream& in, ostream& out, const rsa_key& publick);

/*! Decrypts all data in a stream and writes it to an output stream

    \param[in,out] in The stream to read
    \param[in,out] out The stream to write
    \param[in] privatek The private key to decrypt with
*/
void decrypt(istream& in, ostream& out, const rsa_key& privatek);

/*! Calculates the number of bytes to use to build a single message \f$ m \f$

    \param[in] n The value \f$ n \f$ that the message should be smaller than
    uint64_t - The number of bytes that can be used to build a message \f$ m \f$
*/
uint64_t blockSize(const mpz_class& n);

/*!
    Processes the command line arguments. If they are invalid, the application terminates. 
    Any files that will be used are opened. If file opening fails, the application terminates.

    If generation mode, then public and private keys are generated and written to file.
    If encryption or decryption mode, then the specified file is read and processed.
    
    \param[in] argc Number of command line arguments
    \param[in] argv The command line arguments
    \returns 0 - The program ran successfully
    \returns 1 - The command line arguments were invalid
    \returns 2 - A file could not be opened
    \returns 3 - An error occurred while reading a key file
    \returns 4 - An error occurred while processing an input file
    \returns 5 - An error occurred while generating a key pair
*/
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

/*!
    \throws logic_error : n is smaller than 256
*/
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
    cout << msg << endl << endl;

    cout << "Usage: \n\
tool_rsa -g public private bits\n\
tool_rsa -e/-d input output key\n\
\n\
Mode Options\n\
    -g : To generate a public, private key pair. \n\
            Specify output files for the public key and private key, as well as the number of bits n should contain\n\
    -e : To encrypt\n\
    -d : To decrypt\n\
    \n\
Input Options\n\
    The input for encryption or decryption is a file name\n\
    \n\
Output Options\n\
    The output for encryption or decryption is a file name\n\
    \n\
Key Options\n\
    The key should be the file name of the key to use.\n\
    \n\
Keys should generally be larger than 2048 bits for security; 3072 bits if they will be used through the year 2030.\n\
Picking a number of bits less than 8 will fail because n must be at least 256\n\
The key file for encryption should be a public key, and for decryption should the matching private key." << endl;
}
