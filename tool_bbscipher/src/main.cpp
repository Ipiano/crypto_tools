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

#define gmpt(x) x.get_mpz_t()

using namespace std;
using namespace bbs;

constexpr char GENERATE = 'g';
constexpr char ENCODE = 'e';
constexpr char DECODE = 'd';

const string LINE = string(50, '-');
const string DEFAULTS[3] = {"24672462467892469787",
                            "396736894567834589803",
                            "873245647888478349014"};

struct command
{
    char type;
    int n;
    mpz_class p, q, x, start;
    string fileName;
};

typedef queue<command> commandGroup;

void usage(char** argv);
bool processArgs(int argc, char** argv, unordered_map<string, commandGroup>& fileCmds, commandGroup& generateCmds);
shared_ptr<vector<string>> runCommandGroup(commandGroup& g);
bool runCommand(const command& c, shared_ptr<vector<string>> output);
string fileBase(const string& s);

bool generatePrimes(uint64_t n, mpz_class start, shared_ptr<vector<string>> output);
bool encodeFile(string file, const mpz_class& p, const mpz_class& q, const mpz_class& x, shared_ptr<vector<string>> output, string ext);

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
    cout << "Usage: \n" << argv[0] << " command command...\n" << endl;
    cout << "Commands:" << endl;
    cout << "\t" << setw(20) << "-" + string(1, GENERATE) + " n [start]" << "\t Generate n prime numbers (can be used as p, q) optionally starting at 'start'" << endl;
    cout << "\t" << setw(20) << ""                                       << "\t Default 'start' is some constant large prime" << endl;
    cout << "\t" << setw(20) << "-" + string(1, ENCODE) + " file p q x " << "\t Encode 'file' with given p, q, and x" << endl;
    cout << "\t" << setw(20) << ""                                       << "\t Outputs to 'file'.enc; .enc will replace the extension if it exists" << endl;    
    cout << "\t" << setw(20) << "-" + string(1, DECODE) + " file p q x " << "\t Decode 'file' with given p, q, and x" << endl;
    cout << "\t" << setw(20) << ""                                       << "\t Outputs to 'file'.dec; .dec will replace the extension if it exists" << endl;
    cout << endl;    
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
                    if(++i < argc)
                    {
                        newCmd.type = GENERATE;

                        uint64_t n;
                        try{
                            n = stoull(argv[i]);
                        }catch(exception& ex){
                            cout << "Unable to parse " << argv[i] << " to uint64" << endl;
                            return false;
                        }

                        newCmd.n = n;

                        if(++i < argc && argv[i][0] != '-')
                        {
                            newCmd.start = mpz_class(argv[i]);
                        }
                        else
                        {
                            newCmd.start = mpz_class(DEFAULTS[0]);
                        }

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

    for(int i=0; i<n; i++)
    {
        mpz_nextprime(gmpt(start), gmpt(start));
        startStr = mpz_get_str(nullptr, 10, gmpt(start));
        output->push_back(string(startStr));
        delete[] startStr;
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