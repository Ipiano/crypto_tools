/*! \file

\page affine Affine Cipher Tool

\section background_affine Background

Affine ciphers are a form of substitution cipher which takes the
plaintext to a ciphertext using the transform \f$ c = \alpha m + \beta \f$ (mod \f$ n \f$) where
    - \f$ c \f$ is the ciphertext
    - \f$ m \f$ is a character of the message
    - \f$ n \f$ is the size of the character set to use
    - \f$ \alpha \f$ is some value which is coprime with \f$ n \f$
    - \f$ \beta \f$ is any value (mod \f$ n \f$)
Text is decrypted with the transform \f$ m = (c - \beta)\alpha^{-1} \f$ (mod \f$ n \f$) where \f$ \alpha^{-1} \f$ is
the multiplicative inverse of \f$ \alpha \f$ mod \f$ n \f$

Characters are mapped to values mod \f$ n \f$ by their index in the alphabet. For example, if the alphabet is 'abcde', then
    - \f$ n = \f$ 5
    - 'a' maps to 0, 'b' maps to 1... 'e' maps to 4
    - All values except for 0 and multiples of 5 are valid for \f$ \alpha \f$ because 5 is prime

While this cipher is harder to crack than a simple shift cipher, it is still fairly trivial. If it is known what some plaintext
values map to in the ciphertext, then a linear system of two variables can be solve mod \f$ n \f$ to yield \f$ \alpha, \beta \f$.
If no mappings are known, a frequency analysis can be used to guess some.

This tool can be used to encrypt and decrypt text with the affine cipher, as well as attempt to crack a ciphertext or print
all possible decryptions for it. If the user is attempting to crack a ciphertext and knows some of the original text, they
can enter that information with the -k command line argument. If enough information is given to solve the key a, b then
only the cracked message will be displayed. If multiple solutions are possible, they are all displayed.

\section compile_affine Compiling
This tool can be built with the command 
\verbatim 
make
\endverbatim
This will generate a release version of the tool in the release directory. To build a debug version in the debug directory,
use the command 
\verbatim
make BUILD_TYPE=debug
\endverbatim

\section usage_affine Usage
This tool can be used to encrypt, decrypt, and crack encrypted text using this cipher.

\verbatim
tool_affinecipher -e/-d input output -a a -b b
tool_affinecipher -ca/-cb input [-k m c]
\endverbatim
Mode Options
    - -e : To encrypt
    - -d : To decrypt
    - -ca : To crack by testing all possible a, b key combinations
    - -cb : To crack by attempting solve the linear system

Input Options
    - -it text : To input the text 'text'
    - -if file : To input from the file 'file'

Output Options
    - -ot : To output to terminal
    - -of file : To output to the file 'file'

Cracking Hints
    - -k m c : Indicates to the cracking algorithm that character m should encrypt to character c
               Argument can be used multiple times, and is not required at all

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
#include <iomanip>
#include <set>

#include "freq_count.h"
#include "affinecipher.h"

using namespace std;
using namespace frequency;

//! Constants for this tool
namespace constants_affine {
    //! Alphabet of characters to use
    const string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    //! Order of frequencies of the English alphabet
    const string FREQUENCIES = "etaoinsrhdlucmfywgpbvkxqjz";
}
using namespace constants_affine;

//! Enums for this tool
namespace enums_affine {
    //! Input options
    enum class Input{None, File, Term};

    //! Output options
    enum class Output{None, File, Term};

    //! Mode options
    enum class Mode{None, Encrypt, Decrypt, Crack_All, Crack_Best};
}
using namespace enums_affine;

/*! Processes the command line arguments

If the arguments are invalid, a usage prompt is printed with an error message

\param[in] argc Number of arguments
\param[in] argv The arguments
\param[out] inMode Mode of input
\param[out] outMode Mode of output
\param[out] op The operation to perform
\param[out] a The value first part of the key
\param[out] b The value second part of the key
\param[out] input String to process if text mode, file name if file mode
\param[out] output File name to output to
\param[out] known List of known plain -> cipher pairs
\returns bool - Whether or not the arguments were valid
*/
bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, 
                 int64_t& a, int64_t& b, string& input, string& output,
                 vector<pair<char, char>>& known);

/*! Prints the program usage prompt with an error message

\param[in] name Name of the program
\param[in] msg Error message to print
*/
void help(string name, string msg = "");

/*! Solves the linear system of two variables mod 26
to get a, b.  If no solution is found, 0 is returned as a

\param[in] p1 First x, y pair
\param[in] p2 Second x, y pair
\returns pair<int, int> - [a, b]. [0, 0] if no solution
*/
pair<int, int> linsolve(pair<char, char> p1, pair<char, char> p2);

/*! Checks if a solution a, b can be used to decrypt a ciphertext
and match all known before-after pairs that occur in it

This function returns as soon as two knowns have matched because that
should indicate that a,b is guaranteed the correct key

\param[in] a First part of key
\param[in] b Second part of key
\param[in] ciph Ciphertext being cracked
\param[in] known List of known plain -> cipher pairs
\returns pair<int, string> - [number of matched knowns, decrypted text]
*/
pair<int, string> checkSoln(int a, int b, string ciph, vector<pair<char, char>>& known);

/*!
    Processes the command line arguments. If they are invalid, the application terminates. 
    Any files that will be used are opened. If text is used as the input, it is copied
    into an input stream. 

    If the mode is encryption or decryption, the affine transform object is constructed.
    If the key is invalid, the application terminates. Otherwise, each line of the input is processed and printed to
    the output.

    If the mode is cracking encrypted text, one line of characters of input data are read. If -ca was specified, this line
    is decrypted with all possible a,b keys and printed (along with a, b).
    If -cb was specified, the solver tries to solve the linear systems three times
        - The first time, it attempts to use only user-entered known values
        - The second time, it runs a frequency analysis on the entire input text, and attempts to solve using one known from the user
            and one assumed from this analysis
        - The third time, it tries to solve using all combinations of assumed knowns from the analysis
    If at any point the solver finds an a,b key that matches at least two knowns (whether they are user-entered or assumed), processing stops.
    If a solution matches only one known, but no others because they are not present in the string, the solution is printed, but processing continues

    \param[in] argc Number of command line arguments
    \param[in] argv The command line arguments
    \returns 0 - The program ran successfully
    \returns 1 - The command line arguments were invalid
    \returns 2 - A file could not be opened
    \returns 3 - The key was invalid
*/
int main(int argc, char** argv)
{
    string input, output;
    int64_t a, b;
    vector<pair<char, char>> known;
    Input inputMode;
    Output outputMode;
    Mode operation;

    stringstream inText;

    ifstream inFile;
    ofstream outFile;

    istream* inStream = &inText;
    ostream* outStream = &cout;

    if(!processArgs(argc, argv, inputMode, outputMode, operation, a, b, input, output, known))
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

    if(operation == Mode::Encrypt || operation == Mode::Decrypt)
    {
        unique_ptr<affine::transformer> aff;
        
        try
        {
            aff.reset(new affine::transformer(a, b, ALPHABET, false));
        }catch(exception& ex)
        {
            cout << ex.what() << endl;
            return 3;
        }

        function<string(const string&)> op = std::bind((operation == Mode::Encrypt ? &affine::transformer::encrypt : &affine::transformer::decrypt), aff.get(), placeholders::_1);

        while(*inStream)
        {
            string line;
            getline(*inStream, line);

            line = op(line);

            *outStream << line << endl;
        }
    }
    else if(operation == Mode::Crack_All)
    {
        string ciph;
        getline(*inStream, ciph);

        cout << "Possible translations for first line of text" << endl;
        cout << setw(3) << "a" << setw(3) << "b" << " | " << ciph << endl;
        cout << string(7, '-') << "|" << string(ciph.size() + 1, '-') << endl;

        bool done = false;
        //Test all possible keys; easier and more reliable than solving the
        //linear system
        for(int i=0; i<26 && !done; i++)
        {
            //a must be 1 mod 26
            if(cryptomath::gcd<int>(i, 26) == 1)
            {
                for(int j=0; j<26 && !done; j++)
                {
                    pair<int, string> check = checkSoln(i, j, ciph, known);

                    if(check.first != -1)
                    {
                        cout << setw(3) << i << setw(3) << j << " | " << check.second << endl;
                    }
                    if(check.first == 2)
                    {
                        done = true;
                    }
                }
            }
        }
    }
    else
    {
        string ciph;
        getline(*inStream, ciph);

        set<pair<int, int>> tested;

        cout << "Possible translations for first line of text" << endl;
        cout << setw(3) << "a" << setw(3) << "b" << " | " << ciph << endl;
        cout << string(7, '-') << "|" << string(ciph.size() + 1, '-') << endl;

        //Attempt to solve using only given known values
        bool done = false;
        for(int i = 0; i < known.size() && !done; i++)
        {
            for(int j = i + 1; j < known.size() && !done; j++)
            {
                pair<char, char> knowni = make_pair(ALPHABET.find(known[i].first), ALPHABET.find(known[i].second));
                pair<char, char> knownj = make_pair(ALPHABET.find(known[j].first), ALPHABET.find(known[j].second));
                
                pair<int, int> soln = linsolve(knowni, knownj);
                if(soln.first && tested.insert(soln).second)
                {
                    string msg = affine::transformer(soln.first, soln.second, ALPHABET, false).decrypt(ciph);
                    
                    cout << setw(3) << soln.first << setw(3) << soln.second << " | " << msg << endl;                    
                    done = true;
                }
            }
        }

        //If given knowns, not enough run a requency analysis to get possible matches
        //Use 
        if(!done)
        {
            vector<pair<char, int>> freqs(255);
            for(int i=0; i<255; i++)
                freqs[i] = make_pair(i, 0);

            function<void(pair<char, int>&)> inc =
            [](pair<char, int>& p)
            {
                if(p.first >= 'a' && p.second <= 'z')
                    p.second++;
            };

            countFrequencies(ciph, freqs.begin(), inc, false);
            countFrequencies(*inStream, freqs.begin(), inc, false);      
            sort(freqs.begin(), freqs.end(), [](const pair<char, int>& l, const pair<char, int>& r){return l.second > r.second;});

            //Try linear solve with each known and one frequency
            for(int i=0; i<26 && !done; i++)
            {
                for(int j=0; j<known.size() && !done; j++)
                {
                    //Ensure frequency doesn't conflict with known
                    if(freqs[i].first != known[j].first && freqs[i].second != known[j].second)
                    {
                        //Try a linear solve
                        pair<char, char> possible = make_pair(ALPHABET.find(FREQUENCIES[i]), ALPHABET.find(freqs[i].first));
                        pair<char, char> knownj = make_pair(ALPHABET.find(known[j].first), ALPHABET.find(known[j].second));
                        pair<int, int> soln = linsolve(knownj, possible);
                        if(soln.first && tested.insert(soln).second)
                        {
                            //Check if solution is possible
                            pair<int, string> check = checkSoln(soln.first, soln.second, ciph, known);
                            
                            if(check.first != -1)
                            {
                                cout << setw(3) << soln.first << setw(3) << soln.second << " | " << check.second << endl;
                            }
                            if(check.first == 2)
                            {
                                done = true;
                            }
                        }
                    }
                }
            }

            //If still not solved, try solving with frequencies only
            if(!done)
            {
                for(int i=0; i<26 && !done; i++)
                {
                    for(int j=i+1; j<26 && !done; j++)
                    {
                        //Try a linear solve
                        pair<char, char> possible1 = make_pair(ALPHABET.find(FREQUENCIES[i]), ALPHABET.find(freqs[i].first));
                        pair<char, char> possible2 = make_pair(ALPHABET.find(FREQUENCIES[j]), ALPHABET.find(freqs[j].first));                        
                        pair<int, int> soln = linsolve(possible1, possible2);
                        if(soln.first && tested.insert(soln).second)
                        {
                            //Check if solution is possible
                            pair<int, string> check = checkSoln(soln.first, soln.second, ciph, known);
                            
                            if(check.first != -1)
                            {
                                cout << setw(3) << soln.first << setw(3) << soln.second << " | " << check.second << endl;
                            }
                            if(check.first == 2)
                            {
                                done = true;
                            }
                        }
                        
                    }
                }
            }
        }
    }

    inFile.close();
    outFile.close();

    return 0;
}

pair<int, int> linsolve(pair<char, char> p1, pair<char, char> p2)
{
    int x1 = p1.first, y1 = p1.second;
    int x2 = p2.first, y2 = p2.second;

    int inv = cryptomath::inverseMod<int>(cryptomath::mod<int>(x2 - x1, 26), 26);
    if(inv == 0)
        return make_pair(0, 0);
    
    int alpha = cryptomath::mod<int>((y2 - y1)*inv, 26);
    int beta = cryptomath::mod<int>(y1 - x1*alpha, 26);

    if(cryptomath::gcd<int>(alpha, 26) == 1)
        return make_pair(alpha, beta);

    return make_pair(0, 0);        
}

pair<int, string> checkSoln(int a, int b, string ciph, vector<pair<char, char>>& known)
{
    string msg = affine::transformer(a, b, ALPHABET, false).decrypt(ciph);
    int matches = 0;

    //Test all known pairs
    for(const pair<char, char>& p : known)
    {
        //Index of from in cipher
        int64_t index = msg.find(p.first);
        if(index != string::npos)
        {
            //Check if match in message
            if(ciph[index] == p.second)
            {
                matches++;
                //If 2 matches, done; we cracked it
                if(matches == 2) break;
            }
            else
            {
                //If no match, definitely wrong answer
                matches = -1;
                break;
            }
        }
    }

    return make_pair(matches, msg);
}

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op,
                 int64_t& a, int64_t& b, string& input, string& output,
                 vector<pair<char, char>>& known)
{
    bool a_ = false, b_ = false;

    inMode = Input::None;
    outMode = Output::None;
    op = Mode::None;

    for(int i=1; i<argc; i++)
    {
        string arg = argv[i];

        if(arg == "-a")
        {
            try
            {
                if(a_ || i == argc-1) throw logic_error("");
                i++;
                a = stoll(argv[i]);
                a_ = true;
            }catch(exception)
            {
                help(argv[0], "Enter a with -a [int]");                
                return false;
            }
        }
        else if(arg == "-b")
        {
            try
            {
                if(b_ || i == argc-1) throw logic_error("");
                i++;
                b = stoll(argv[i]);
                b_ = true;
            }catch(exception)
            {
                help(argv[0], "Enter b with -b [int]");                
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
                help(argv[0], "Choose exactly one operation [-e, -d, -ca, -cb]");
                return false;
            }

            op = Mode::Encrypt;
        }
        else if(arg == "-d")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d, -ca, -cb]");
                return false;
            }

            op = Mode::Decrypt;
        }
        else if(arg == "-ca")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d, -ca, -cb]");
                return false;
            }   

            op = Mode::Crack_All;
        }
        else if(arg == "-cb")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d, -ca, -cb]");
                return false;
            }   

            op = Mode::Crack_Best;
        }
        else if(arg == "-k")
        {
            if(i < argc-2)
            {
                char from, to;
                from = argv[++i][0];
                to = argv[++i][0];

                known.emplace_back(from, to);
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
        help(argv[0], "Choose exactly one operation [-e, -d, -ca, -cb]");
        return false;
    }

    if(inMode == Input::None)
    {
        help(argv[0], "Choose exactly one input mode [-it, -if]");
        return false;
    }

    if(op == Mode::Encrypt || op == Mode::Decrypt)
    {
        if(!a_)
        {
            help(argv[0], "Enter a with -a [int]");                
            return false;        
        }

        if(!b_)
        {
            help(argv[0], "Enter b with -b [int]");                
            return false;        
        }

        if(outMode == Output::None)
        {
            help(argv[0], "Choose exactly one output mode [-ot, -of]");
            return false;
        }
    }

    return true;
}

void help(string name, string msg)
{
    cout << msg << endl << endl;

    cout << "Usage:" << endl << "tool_affinecipher -e/-d input output -a a -b b\n\
tool_affinecipher -ca/-cb input [-k m c]\n\
\n\
Mode Options\n\
    -e : To encrypt\n\
    -d : To decrypt\n\
    -ca : To crack by testing all possible a, b key combinations\n\
    -cb : To crack by attempting solve the linear system\n\
    \n\
Input Options\n\
    -it text : To input the text 'text'\n\
    -if file : To input from the file 'file'\n\
    \n\
Output Options\n\
    -ot : To output to terminal\n\
    -of file : To output to the file 'file'\n\
    \n\
Cracking Hints\n\
    -k m c : Indicates to the cracking algorithm that character m should encrypt to character c\n\
             Argument can be used multiple times, and is not required at all\n\
                \n\
Any text in the input which is not in the range a-z or A-Z will copied as-is to the output. Any text in the range A-Z will be made\n\
lower-case before it is processed." << endl;
}
