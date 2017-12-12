/*! \file 

\page bbs The Blum Blum Shub Cipher

\section background_bbs Background

The Blum Blum Shub pseudo-random number generation algorithm can be used to 
generate a one-time pad for encryption and decryptiong. The idea of a one-time pad is
that one copy is given to the message sender, who uses it to encrypt a message, and one
copy is given to the message recipient, who uses it to decrypt the message. After this,
the pad is destroyed and never used again. Using the Blum Blum Shub algorithm,
one can generate a large number of bits that can be xored with a message to 
encrypt it. The algorithm can be used with the same initial seed to get the 
same pad, which can be used to decrypt the message. 

This tool can be used to find random numbers which can be used as the
algorithm's initial state and to encrypt/decrypt using a one time pad generated
from a specific seed.

Details on the implementation of Blum Blum Shub can be found in the crytography library submodule
which this tool uses.

\section compile_bbs Compiling
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

\section usage_bbs Usage
This tool can be used to encrypt and decrypt messages.

\verbatim
./release/tool_bbscipher command command...
\endverbatim

Commands:
-g n [start]    Generate n prime numbers which are equal to 3 mod 4 (can be used as p, q) optionally starting at 'start'
                Default 'start' is some constant large prime
-e file p q x   Encode 'file' with given p, q, and x
                Outputs to 'file'.enc; .enc will replace the extension if it exists
-d file p q x   Decode 'file' with given p, q, and x
                Outputs to 'file'.dec; .dec will replace the extension if it exists

p and q must be primes equal to 3 mod 4.
x must be coprime to p*q
*/
#include "bbs.h"

#include <gmpxx.h>
#include <iostream>
#include <iomanip>
#include <queue>
#include <unordered_map>
#include <future>
#include <memory>
#include <chrono>
#include <utility>
#include <exception>
#include <functional>
#include <fstream>

//! Convenience macro for working with mpz_class types
#define gmpt(x) x.get_mpz_t()

using namespace std;
using namespace bbs;

//! Command to generate primes
constexpr char GENERATE = 'g';

//! Command to encode
constexpr char ENCODE = 'e';

//! Command to decode
constexpr char DECODE = 'd';

//! Line of dashes
const string LINE = string(50, '-');

//! Default values to use for testing
const string DEFAULTS[3] = {"24672462467892469787",
                            "396736894567834589803",
                            "873245647888478349014"};

//! Container for an operation that the user requested
struct command
{
    //! Command type
    char type;

    //! Number of primes if -g
    int n;

    //! p for encrypt/decrypt
    mpz_class p;

    //! q for encrypt/decrypt
    mpz_class q;

    //! x for encrypt/decrypt
    mpz_class x;

    //! Value to start generating primes at
    mpz_class start;

    //! Name of file to process
    string fileName;
};

//! Group of commands for the same filename
typedef queue<command> commandGroup;

/*! Prints the program usage prompt

\param[in] argv The command line arguments
*/
void usage(char** argv);

/*! Processes the command line arguments.
Any encrypt or decrypt commands for a specific file are placed in a command group together,
to be executed sequentially. Generation commands are placed in their own group.

If the arguments are invalid, an error message is printed.

\param[in] argc Number of arguments
\param[in] argv The arguments
\param[out] fileCmds Maps files to be processed to all commands for processing them
\param[out] generateCmds Commands for generating prime numbers
\returns bool - Whether or not the arguments were valid
*/
bool processArgs(int argc, char** argv, unordered_map<string, commandGroup>& fileCmds, commandGroup& generateCmds);

/*! Runs a group of commands sequentially

\param[in] g The group of commands to run
\return shared_ptr<vector<string>> - Pointer to a vector of messages to output as a result
*/
shared_ptr<vector<string>> runCommandGroup(commandGroup& g);

/*! Runs a single command

\param[in] c The command to do
\param[out] output Vector to place output messages in
\returns bool - Whether the command was successful or not
*/
bool runCommand(const command& c, shared_ptr<vector<string>> output);

/*! Converts a file path to the name of the file without the extension

\param[in] s A file path
\returns string - The name of the file without an extension
*/
string fileBase(const string& s);

/*! Finds the first n primes after the start value

\param[in] n Number of primes to find
\param[in] start Value to start at
\param[out] output Vector to place output messages in
\returns bool - true
*/
bool generatePrimes(uint64_t n, mpz_class start, shared_ptr<vector<string>> output);

/*! Generates a one-time pad and xors a file with it

\param[in] file File path to read
\param[in] p Initial seed value 
\param[in] q Initial seed value
\param[in] x Initial seed value
\param[out] output Vector to place output messages in
\param[in] ext Extension to put on the output file
\returns bool - Whether or not encoding was successful. Fails if p, q, x is an invalid Blum Blum Shub seed
*/
bool encodeFile(string file, const mpz_class& p, const mpz_class& q, const mpz_class& x, shared_ptr<vector<string>> output, string ext);

/*!
    Processes the command line arguments. If they are invalid, the application terminates. 

    Each independent group of commands is started in a separate thread, and all threads
    are run to completion. Commands are considered to be independent if they do not operate
    on the same file. One thread will be used for all the generate primes commands.

    When threads terminate, all their output will be printed to the screen.
    The application will terminate after all threads have finished.

    \param[in] argc Number of command line arguments
    \param[in] argv The command line arguments
    \returns 0 - The program ran successfully
    \returns 1 - The command line arguments were invalid
*/
int main(int argc, char** argv)
{
    unordered_map<string, commandGroup> fileOps;
    commandGroup generates; //Store generate commands as a file just so they're all somewhere

    //Parse commands list
    if(!processArgs(argc, argv, fileOps, generates))
    {
        usage(argv);
        return 1;
    }

    //Start one thread for each file operated on
    vector<pair<bool, future<shared_ptr<vector<string>>>>> threads;

    if(generates.size())
        threads.push_back(make_pair(false, async(launch::async, &runCommandGroup, ref(generates))));
    for(auto& i : fileOps)
    {
        threads.push_back(make_pair(false, async(launch::async, &runCommandGroup, ref(i.second))));
    }

    //Poll threads until all have completed
    bool done;
    do
    {
        done = true;
        for(auto& p : threads)
        {
            if(!p.first)
            {
                //First time thread completes, output all its results
                future<shared_ptr<vector<string>>>& fut = p.second;
                if(fut.wait_for(chrono::milliseconds(100)) == future_status::ready)
                {
                    shared_ptr<vector<string>> result = fut.get();
                    for(const string& s : *result)
                    {
                        cout << s << endl;
                    }
                    p.first = true;
                }
                else
                {
                    done = false;
                }
            }
        }
    }while(!done);
    
    return 0;
}

void usage(char** argv)
{
    cout << "Usage: " << argv[0] << " command command... \n\
\n\
Commands:\n\
-g n [start]    Generate n prime numbers which are equal to 3 mod 4 (can be used as p, q) optionally starting at 'start'\n\
                Default 'start' is some constant large prime\n\
                \n\
-e file p q x   Encode 'file' with given p, q, and x\n\
                Outputs to 'file'.enc; .enc will replace the extension if it exists\n\
                \n\
-d file p q x   Decode 'file' with given p, q, and x\n\
                Outputs to 'file'.dec; .dec will replace the extension if it exists\n\
                \n\
p and q must be primes equal to 3 mod 4.\n\
x must be coprime to p*q" << endl;
}

bool processArgs(int argc, char** argv, unordered_map<string, commandGroup>& fileCmds, commandGroup& generateCmds)
{
    int i=1;
    while(i < argc)
    {
        command newCmd;

        string cmdStr = argv[i++];
        if(cmdStr[0] == '-' && cmdStr.size() > 1)
        {
            char cmdChr = cmdStr[1];
            switch(cmdChr)
            {
                case GENERATE:
                {
                    if(i < argc)
                    {
                        newCmd.type = GENERATE;

                        uint64_t n;
                        try{
                            n = stoull(argv[i++]);
                        }catch(exception& ex){
                            cout << "Unable to parse " << argv[i] << " to uint64" << endl;
                            return false;
                        }

                        newCmd.n = n;

                        if(i < argc && argv[i][0] != '-')
                        {
                            try{
                                newCmd.start = mpz_class(argv[i++]);
                            }catch(exception& ex){
                                cout << "Unable to parse " << argv[i-1] << " as integer" << endl;
                                return false;
                            }
                        }
                        else
                        {
                            newCmd.start = mpz_class(DEFAULTS[0]);
                        }

                        cout << "Generate: " << newCmd.n << " " << newCmd.start << endl;

                        generateCmds.push(newCmd);
                    }
                    else
                    {
                        cout << "No 'n' given for -g command" << endl;
                        return false;
                    }
                }
                break;
                case ENCODE:
                case DECODE:
                {
                    newCmd.type = cmdChr;
                    newCmd.fileName = argv[i];

                    newCmd.p = mpz_class(DEFAULTS[0]);
                    newCmd.q = mpz_class(DEFAULTS[1]);
                    newCmd.x = mpz_class(DEFAULTS[2]);  

                    try{
                        if(++i < argc && argv[i][0] != '-')
                        {
                            newCmd.p = mpz_class(argv[i]);
                            if(++i < argc && argv[i][0] != '-')
                            {
                                newCmd.q = mpz_class(argv[i]);
                                if(++i < argc && argv[i][0] != '-')
                                {
                                    newCmd.x = mpz_class(argv[i]);
                                }
                            }
                        }
                    }catch(exception& ex){
                        cout << "Unable to parse " << argv[i] << " as integer" << endl;
                        return false;
                    }
                    //Group files with the same base name together
                    //so we can sequentially encode and decode
                    fileCmds[fileBase(newCmd.fileName)].push(newCmd);
                    break;
                }
                default:
                    cout << "Unknown command: " << cmdStr << endl;
                    return false;
            }
        }
        else
        {
            return false;
        }
    }

    return generateCmds.size() || fileCmds.size();
}

shared_ptr<vector<string>> runCommandGroup(commandGroup& g)
{
    shared_ptr<vector<string>> results(new vector<string>);
    if(g.front().fileName.size())
    {
        results->push_back(LINE);
        results->push_back("File: " + g.front().fileName);
    }
    while(g.size())
    {
        command& c = g.front();

        results->push_back(LINE);
        
        //Return early if any command fails
        if(!runCommand(c, results))
        {
            return results;
        }

        g.pop();        
    }
    return results;
}

bool runCommand(const command& c, shared_ptr<vector<string>> output)
{
    switch(c.type)
    {
        case GENERATE:
            return generatePrimes(c.n, c.start, output);
        case ENCODE:
            return encodeFile(c.fileName, c.p, c.q, c.x, output, ".enc");
        case DECODE:
            return encodeFile(c.fileName, c.p, c.q, c.x, output, ".dec");
    }
    return true;
}

bool generatePrimes(uint64_t n, mpz_class start, shared_ptr<vector<string>> output)
{
    char* startStr = mpz_get_str(nullptr, 10, gmpt(start));
    output->push_back("Generate " + to_string(n) + " primes, starting with " + string(startStr));
    output->push_back(LINE);
    delete[] startStr;

    for(int i=0; i<n;)
    {
        start = cryptomath::nextPrime(start);
        if(cryptomath::mod<mpz_class>(start, 4) == 3)
        {
            i++;
            startStr = mpz_get_str(nullptr, 10, gmpt(start));
            output->push_back(string(startStr));
            delete[] startStr;
        }
    }
    return true;
}

bool encodeFile(string file, const mpz_class& p, const mpz_class& q, const mpz_class& x, 
                shared_ptr<vector<string>> output, string ext)
{
    blum_blum_shub_engine<uint8_t, mpz_class>* random;
    try{
        random = new blum_blum_shub_engine<uint8_t, mpz_class>(p, q, x);
    }catch(exception& ex){
        output->push_back("Unable to generate bbs engine: " + string(ex.what()));
        return false;
    }

    ifstream fin(file);
    if(!fin)
    {
        output->push_back("Input file " + file + " could not be opened");
        return false;
    }

    string ofile = fileBase(file) + ext;
    ofstream fout(ofile);
    if(!fout)
    {
        output->push_back("Output file " + ofile + " could not be opened");
        return false;
    }

    for(int i=0; i<3; i++)
    {
        mpz_class d0(DEFAULTS[0]);
        mpz_class d1(DEFAULTS[1]);
        mpz_class d2(DEFAULTS[2]);

        if(p == d0 || p == d1 || p == d2 ||
           q == d0 || q == d1 || q == d2 ||
           x == d0 || x == d1 || x == d2)
           {
               output->push_back("WARNING: p, q, or x is one of the default values");
               break;
           }
    }

    while(fin)
    {
        char buff;
        for(int i=0; i<8; i++)
            buff = (buff << 1) | (*random)();
            
        fout << (char)(fin.get() ^ buff);
    }

    fout.close();
    fin.close();

    return true;
}

string fileBase(const string& s)
{
    return s.substr(0, s.rfind("."));
}