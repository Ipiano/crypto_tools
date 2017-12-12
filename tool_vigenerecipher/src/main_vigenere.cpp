/*! \file

\page vigenere Vigenere Cipher Tool

\section background_vigenere Background

The Vigenere cipher was invented during the 16th century, and is often attributed
to Vigenere. The ciper works similarly to a shift cipher, but instead of shifting 
each character by the same amount, a key is used to determine how far to shift each letter.

For example, if the key is '0 4 2 3', then the first letter of the message is shifted
by 0, the second by 4, the third by 2, and the fourth by 3. At this point, the key repeats,
so the fifth character is shifted by 0, the sixth by 4 and so on until the end of the message.

In general, the key is some text which is easy to remember. The text to be encrypted/decrypted and
key are mapped to numbers by their index in the respective alphabet.
For example, if the alphabet is 'abcde', then
    - 'a' maps to 0, 'b' maps to 1... 'e' maps to 4

This encryption method was thought to be secure through the twentieth cenurty, at which point Friedman
developed a generalized method for breaking it and similar ciphers. A common method of cracking the Vigenere
cipher involves comparing the ciphertext to itself, offset by varying amounts, to determine the key length. Once
the key length is determined, then sets of every nth character can be analyzed with a frequency analysis
to determine specific letters of the key.

\section compile_vigenere Compiling
This tool can be built with the command 
\verbatim 
make
\endverbatim
This will generate a release version of the tool in the release directory. To build a debug version in the debug directory,
use the command 
\verbatim
make BUILD_TYPE=debug
\endverbatim

\section usage_vigenere Usage
This tool can be used to encrypt, decrypt, and crack encrypted text using this cipher.

\verbatim
tool_vigenerecipher mode input output [key]
\endverbatim
Mode Options
    - -e : To encrypt
    - -d : To decrypt
    - -c n : To crack an encrypted text. n is the maximum key length to check

Input Options
    - -it text : To input the text 'text'
    - -if file : To input from the file 'file'

Output Options
    - -ot : To output to terminal
    - -of file : To output to the file 'file'

Key Options (Not needed for cracking)
    - -k key : The key to use

The key should contain only the letters a-z.
Any text in the input which is not in the range a-z or A-Z will copied as-is to the output. Any text in the range A-Z will be made
lower-case before it is processed.
*/

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

//! Constants for this tool
namespace constants_vigenere {
    //! Valid characters to encrypt/decrypt
    const string ALPHABET = "abcdefghijklmnopqrstuvwxyz";

    //! Known frequencies of letters in the English alphabet
    const vector<double> FREQUENCIES{{.082, .015, .028, .043, .127, .022, .020, .061, .070, .002,
                                      .008, .040, .024, .067, .075, .019, .001, .060, .063, .091,
                                      .028, .010, .023, .001, .020, .001}};
}
using namespace constants_vigenere;

//! Enums for this tool
namespace enums_vigenere {
    //! Input options
    enum class Input{None, File, Term};

    //! Output options
    enum class Output{None, File, Term};

    //! Mode options
    enum class Mode{None, Encrypt, Decrypt, Crack};
}

using namespace enums_vigenere;

/*! Processes the command line arguments

If the arguments are invalid, a usage prompt is printed with an error message

\param[in] argc Number of arguments
\param[in] argv The arguments
\param[out] inMode Mode of input
\param[out] outMode Mode of output
\param[out] op The operation to perform
\param[out] key The key to use for encryption or decryption
\param[out] key_max Max length to check if cracking the key
\param[out] input String to process if text mode, file name if file mode
\param[out] output File name to output to
\returns bool - Whether or not the arguments were valid
*/
bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, uint64_t& key_max, string& input, string& output);

/*! Prints the program usage prompt with an error message

\param[in] name Name of the program
\param[in] msg Error message to print
*/
void help(string name, string msg = "");

/*!
    Processes the command line arguments. If they are invalid, the application terminates. 
    Any files that will be used are opened. If text is used as the input, it is copied
    into an input stream. 

    If the mode is encryption or decryption, the vigenere transform object is constructed.
    If the key is invalid, the application terminates. Otherwise, each line of the input is processed and printed to
    the output.

    If the mode is cracking encrypted text, up to 2000 characters of input data are read. For each possible key length,
    the cipher is compared to itself shifted over. The shift distances with the most matching letters are then used to generate
    possible keys. Possible keys are found by taking all the characters which are separated by the key distance and comparing
    them to common English frequencies (also shifted) to see at what point the English frequencies match best. This yields the
    potential letter for one spot in the key.

    \param[in] argc Number of command line arguments
    \param[in] argv The command line arguments
    \returns 0 - The program ran successfully
    \returns 1 - The command line arguments were invalid
    \returns 2 - A file could not be opened
    \returns 3 - The key was invalid
*/
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

    //Parse command line arguments
    if(!processArgs(argc, argv, inputMode, outputMode, operation, key, key_max, input, output))
    {
        return 1;
    }

    //If input file, open the file
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
    //Otherwise, copy input text into stream
    else
    {
        inText << input;
    }

    //If outputting to file, open that file
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

    //If encryptino, or decryption
    //construct the transform and process all lines
    //in the input
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
    //Key cracking
    else
    {
        //Read up to 2000 lines of encrypted text
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

        //For all possible key lengths, compare the
        //text to itself shifted and count the number of
        //places they match
        for(int i=1; i<=key_max; i++)
        {
            int matches = 0;
            for(int j=0, k=i; k < ciph.size(); j++, k++)
                if(ciph[j] == ciph[k]) matches++;

            //If new best number of matches, reset the best guesses list
            if(matches > guessMatches)
            {
                guessLengths.clear();
                guessLengths.push_back(i);
                guessMatches = matches;
            }
            //If same as best matches, add to best guesses list
            else if(matches == guessMatches)
            {
                guessLengths.push_back(i);
            }
        }

        //Generate a possible key for each guess length
        for(int len : guessLengths)
        {
            string key;
            //Key is generated one character at a time
            for(int start = 0; start < len; start++)
            {
                string ciph_;
                //Acquire every nth letter of the cipher, where
                //n is the letter of the key
                for(int i = start; i < ciph.size(); i+=len)
                    ciph_.push_back(ciph[i]);

                //Frequency analysis on the letters
                vector<pair<char, int>> freqs(255);
                for(int i=0; i<255; i++)
                    freqs[i] = make_pair(i, 0);
        
                function<void(pair<char, int>&)> inc =
                [](pair<char, int>& p)
                {
                    p.second++;
                };
        
                countFrequencies(ciph_, freqs.begin(), inc, false);

                //Sort letters by most frequent
                sort(freqs.begin(), freqs.end(), [](const pair<char, int>& l, const pair<char, int>& r){return l.second > r.second;});
           
                //Compute frequency percentages
                vector<double> W(26);
                
                for(int i=0; i<26; i++)
                {
                    W[freqs[i].first-'a'] = freqs[i].second/(double)ciph_.size();
                }

                //Test frequency percentages against known English frequency percentages (shifted)
                //to find the shift where they match best
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

                //Whatever shift of the alphabet fit best is likely 
                //the letter for this place in the key
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
    cout << msg << endl << endl;

    cout << "Usage: " << name << " mode input output [key]" << endl << endl;

cout << "\
Mode Options\n\
    -e : To encrypt\n\
    -d : To decrypt\n\
    -c n : To crack an encrypted text. n is the maximum key length to check\n\
\n\
Input Options\n\
    -it text : To input the text \'text\'\n\
    -if file : To input from the file \'file\'\n\
\n\
Output Options\n\
    -ot : To output to terminal\n\
    -of file : To output to the file \'file\'\n\
\n\
Key Options (Not needed for cracking)\n\
    -k key : The key to use\n\
\n\
The key should contain only the letters a-z.\n\
Any text in the input which is not in the range a-z or A-Z will copied as-is to the output.\n\
Any text in the range A-Z will be made lower-case before it is processed." << endl;
}
