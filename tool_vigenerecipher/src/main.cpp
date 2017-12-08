#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include <functional>
#include <memory>
#include <stdexcept>
#include <algorithm>

#include "vigenerecipher.h"
#include "freq_count.h"

using namespace std;
using namespace frequency;

const string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
const vector<double> FREQUENCIES{{.082, .015, .028, .043, .127, .022, .020, .061, .070, .002,
                                  .008, .040, .024, .067, .075, .019, .001, .060, .063, .091,
                                  .028, .010, .023, .001, .020, .001}};

enum class Input{None, File, Term};
enum class Output{None, File, Term};
enum class Mode{None, Encrypt, Decrypt, Crack};

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, uint64_t& key_max, string& input, string& output);
void help(string name, string msg = "");

int main(int argc, char** argv)
{
    string input, output, key;
    uint64_t key_max;
    Input inputMode;
    Output outputMode;
    Mode operation;

    stringstream inText;

    ifstream inFile;
    ofstream outFile;

    istream* inStream = &inText;
    ostream* outStream = &cout;

    if(!processArgs(argc, argv, inputMode, outputMode, operation, key, key_max, input, output))
    {
        return 1;
    }

    if(inputMode == Input::File)
    {
        inFile.open(input, ios::binary);
        if(!inFile)
        {
            help(argv[0], "Unable to open input file " + input);
            return 2;
        }

        inStream = &inFile;
    }
    else
    {
        inText << input;
    }

    if(outputMode == Output::File)
    {
        outFile.open(output, ios::binary | ios::trunc);
        if(!outFile)
        {
            help(argv[0], "Unable to open output file " + output);
            inFile.close();
            return 2;
        }

        outStream = &outFile;
    }

    if(operation != Mode::Crack)
    {
        unique_ptr<vigenere::transformer> vig;
    
        try
        {
            vig.reset(new vigenere::transformer(key, ALPHABET, ALPHABET, false));
        }catch(exception& ex)
        {
            cout << ex.what() << endl;
            return 3;
        }

        function<string(const string&)> op = std::bind((operation == Mode::Encrypt ? &vigenere::transformer::encrypt : &vigenere::transformer::decrypt), vig.get(), placeholders::_1, false);

        while(*inStream)
        {
            string line;
            getline(*inStream, line);

            line = op(line);

            *outStream << line << endl;
        }
    }
    else
    {
        string ciph = "";
        while(*inStream && ciph.size() < 2000)
        {
            string line;
            getline(*inStream, line);

            for(char c_ : line)
            {
                unsigned char c = tolower((unsigned char)c_);
                if(ALPHABET.find(c) != string::npos)
                    ciph += c;
            }
        }

        vector<int> guessLengths;
        int guessMatches = 0;

        for(int i=1; i<=key_max; i++)
        {
            int matches = 0;
            for(int j=0, k=i; k < ciph.size(); j++, k++)
                if(ciph[j] == ciph[k]) matches++;

            if(matches > guessMatches)
            {
                guessLengths.clear();
                guessLengths.push_back(i);
                guessMatches = matches;
            }
            else if(matches == guessMatches)
            {
                guessLengths.push_back(i);
            }
        }

        for(int len : guessLengths)
        {
            string key;
            for(int start = 0; start < len; start++)
            {
                string ciph_;
                for(int i = start; i < ciph.size(); i+=len)
                    ciph_.push_back(ciph[i]);

                vector<pair<char, int>> freqs(255);
                for(int i=0; i<255; i++)
                    freqs[i] = make_pair(i, 0);
        
                function<void(pair<char, int>&)> inc =
                [](pair<char, int>& p)
                {
                    p.second++;
                };
        
                countFrequencies(ciph_, freqs.begin(), inc, false);
                sort(freqs.begin(), freqs.end(), [](const pair<char, int>& l, const pair<char, int>& r){return l.second > r.second;});
           
                vector<int> V(26);
                vector<double> W(26);
                
                for(int i=0; i<26; i++)
                {
                    V[freqs[i].first-'a'] = freqs[i].second;
                    W[freqs[i].first-'a'] = freqs[i].second/(double)ciph_.size();
                }

                double maxDot = 0;
                int maxShift;
                for(int i=0; i<26; i++)
                {
                    double dot = 0;
                    int freq = (26 - i) % 26;
                    for(int j=0; j<26; j++, freq = (freq+1) % 26)
                    {
                        dot += FREQUENCIES[freq]*W[j];
                    }

                    if(dot > maxDot)
                    {
                        maxDot = dot;
                        maxShift = i;
                    }
                }

                key += ALPHABET[maxShift];
            }
            cout << "Potential key: " << key << endl;
        }
    }

    inFile.close();
    outFile.close();

    return 0;
}

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, uint64_t& key_max, string& input, string& output)
{
    inMode = Input::None;
    outMode = Output::None;
    op = Mode::None;
    key_max = 0;

    for(int i=1; i<argc; i++)
    {
        string arg = argv[i];

        if(arg == "-k")
        {
            try
            {
                if(i == argc-1) throw logic_error("");
                i++;
                key = argv[i];
            }catch(exception)
            {
                help(argv[0], "Enter key with -k [key]");                
                return false;
            }
        }
        else if(arg == "-it")
        {
            if(inMode != Input::None)
            {
                help(argv[0], "Choose exactly one input mode [-it, -if]");
                return false;
            }

            inMode = Input::Term;

            if(i >= argc-1)
            {
                help(argv[0], "Enter text with -it {text}");
                return false;
            }

            i++;
            input = argv[i];
        }
        else if(arg == "-if")
        {
            if(inMode != Input::None)
            {
                help(argv[0], "Choose exactly one input mode [-it, -if]");
                return false;
            }

            inMode = Input::File;

            if(i >= argc-1)
            {
                help(argv[0], "Enter file name with -if {file}");
                return false;
            }

            i++;
            input = argv[i];
        }
        else if(arg == "-ot")
        {
            if(outMode != Output::None)
            {
                help(argv[0], "Choose exactly one output mode [-ot, -of]");
                return false;
            }

            outMode = Output::Term;
        }
        else if(arg == "-of")
        {
            if(outMode != Output::None)
            {
                help(argv[0], "Choose exactly one output mode [-ot, -of]");
                return false;
            }

            outMode = Output::File;

            if(i >= argc-1)
            {
                help(argv[0], "Enter file name with -of {file}");
                return false;
            }

            i++;
            output = argv[i];
        }
        else if(arg == "-e")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d, -c]");
                return false;
            }

            op = Mode::Encrypt;
        }
        else if(arg == "-d")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d, -c]");
                return false;
            }

            op = Mode::Decrypt;
        }
        else if(arg == "-c")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d, -c]");
                return false;
            }

            op = Mode::Crack;

            if(i >= argc-1)
            {
                help(argv[0], "Specify the max key length with -c [max length]");
                return false;
            }
            
            try{
                key_max = stoull(argv[++i]);
            }catch(exception& ex){
                help(argv[0], "Specify the max key length with -c [max length]");
                return false;
            }
        }
        else
        {
            help(argv[0], "Unknown option: " + arg);
            return false;
        }
    }

    if(op == Mode::None)
    {
        help(argv[0], "Choose exactly one operation [-e, -d, -c]");
        return false;
    }

    if(inMode == Input::None)
    {
        help(argv[0], "Choose exactly one input mode [-it, -if]");
        return false;
    }

    if(op != Mode::Crack)
    {
        if(outMode == Output::None)
        {
            help(argv[0], "Choose exactly one output mode [-ot, -of]");
            return false;
        }

        if(key == "")
        {
            help(argv[0], "Enter key with -k [key]");                
            return false;        
        }
    }

    return true;
}

void help(string name, string msg)
{
    cout << msg << endl;
}
