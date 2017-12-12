/*! \file

\page adfgx ADFGX Cipher Tool

\section background_adfgx Background

The ADFGX cipher is a code which was developed by the Germans
during World War 1.
The cipher has four steps to encrypt a text
    - Using the matrix below, substitute a pair of letters from [adfgx] for each letter of the text
    - Write the substituted text under the key in column, going from left to right
    - Re-order the columns so the letters of the key are in alphabetical order
    - Write the columns (from top top bottom) from the left to the right
Decryption using the cipher follows the same pattern, but in reverse. To keep things secure during the war,
the initial substituion matrix was changed regularaly, along with the key.

Substitution matrix
\verbatim
    A  D  F  G  X
   --------------
A | p  g  c  e  n
D | b  q  o  z  r
F | s  l  a  f  t
G | m  d  v  i  w
X | k  u  y  x  h
\endverbatim

During the war, this cipher was thought to be very difficult to crack, but it was broken by the
French cryptanalyst Georges Painvin. After a couple of ciphertexts were recovered within a short period
of each other, he made the assumption that they had the same substitution matrix and key. With this assumption,
he tried writing out the text as if he were decrypting using various key lengths. If the beginnings of the
original messages were similar, then when the key length was correct, they would have a large number of matches
at the tops of the columns. After the key length was identified, the columns were ordered different ways,
and for each way the problem became a simple frequency analysis away from decryption.

\section compile_adfgx Compiling
This tool can be built with the command 
\verbatim 
make
\endverbatim
This will generate a release version of the tool in the release directory. To build a debug version in the debug directory,
use the command 
\verbatim
make BUILD_TYPE=debug
\endverbatim

\section usage_adfgx Usage
This tool can be used to encrypt and decrypt text using this cipher.

\verbatim
tool_adfgx mode input output key
\endverbatim
Mode Options
    - -e : To encrypt
    - -d : To decrypt

Input Options
    - -it text : To input the text 'text'
    - -if file : To input from the file 'file'

Output Options
    - -ot : To output to terminal
    - -of file : To output to the file 'file'

Key Options
    - -k key : Indicates a string that should be used as the key

The key should have no duplicated characters
*/
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include <functional>
#include <memory>
#include <stdexcept>

#include "adfgxcipher.h"

using namespace std;

//! Enums for this tool
namespace enums {
    //! Input modes
    enum class Input{None, File, Term};

    //! Output modes
    enum class Output{None, File, Term};

    //! Operation modes
    enum class Mode{None, Encrypt, Decrypt};
}

using namespace enums;

/*! Processes the command line arguments

If the arguments are invalid, a usage prompt is printed with an error message

\param[in] argc Number of arguments
\param[in] argv The arguments
\param[out] inMode Mode of input
\param[out] outMode Mode of output
\param[out] op The operation to perform
\param[out] key The key to use for encryption or decryption
\param[out] input String to process if text mode, file name if file mode
\param[out] output File name to output to
\returns bool - Whether or not the arguments were valid
*/
bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, string& input, string& output);

/*! Prints the program usage prompt with an error message

\param[in] name Name of the program
\param[in] msg Error message to print
*/
void help(string name, string msg = "");

/*!
    Processes the command line arguments. If they are invalid, the application terminates. 
    Any files that will be used are opened. If text is used as the input, it is copied
    into an input stream. 

    If the mode is encryption or decryption, the adfgx transform object is constructed.
    If the key is invalid, the application terminates. Otherwise, each line of the input is processed and printed to
    the output.

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
    string key;
    Input inputMode;
    Output outputMode;
    Mode operation;

    stringstream inText;

    ifstream inFile;
    ofstream outFile;

    istream* inStream = &inText;
    ostream* outStream = &cout;

    if(!processArgs(argc, argv, inputMode, outputMode, operation, key, input, output))
    {
        return 1;
    }

    unique_ptr<adfgx::transformer> ciph;

    try
    {
        ciph.reset(new adfgx::transformer(key));
    }catch(exception& ex)
    {
        cout << ex.what() << endl;
        return 3;
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

    function<string(const string&)> op = std::bind((operation == Mode::Encrypt ? &adfgx::transformer::encrypt : &adfgx::transformer::decrypt), ciph.get(), placeholders::_1);

    while(*inStream)
    {
        string line;
        getline(*inStream, line);

        line = op(line);

        *outStream << line << endl;
    }

    inFile.close();
    outFile.close();

    return 0;
}

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, string& input, string& output)
{
    key = "";
    inMode = Input::None;
    outMode = Output::None;
    op = Mode::None;

    for(int i=1; i<argc; i++)
    {
        string arg = argv[i];

        if(arg == "-k")
        {
            if(key != "" || i >= argc-1)
            {
                help(argv[0], "Enter key with -k [key]");
                return false;
            }
            
            i++;
            key = argv[i];
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
                help(argv[0], "Choose exactly one operation [-e, -d]");
                return false;
            }

            op = Mode::Encrypt;
        }
        else if(arg == "-d")
        {
            if(op != Mode::None)
            {
                help(argv[0], "Choose exactly one operation [-e, -d]");
                return false;
            }

            op = Mode::Decrypt;
        }
        else
        {
            help(argv[0], "Unknown option: " + arg);
            return false;
        }
    }

    if(op == Mode::None)
    {
        help(argv[0], "Choose exactly one operation [-e, -d]");
        return false;
    }

    if(inMode == Input::None)
    {
        help(argv[0], "Choose exactly one input mode [-it, -if]");
        return false;
    }

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

    return true;
}

void help(string name, string msg)
{
    cout << msg << endl << endl;

    cout << "Usage: tool_adfgx mode input output key\n\
\n\
Mode Options\n\
    - -e : To encrypt\n\
    - -d : To decrypt\n\
    \n\
Input Options\n\
    - -it text : To input the text 'text'\n\
    - -if file : To input from the file 'file'\n\
    \n\
Output Options\n\
    - -ot : To output to terminal\n\
    - -of file : To output to the file 'file'\n\
    \n\
Key Options\n\
    - -k key : Indicates a string that should be used as the key\n\
    \n\
The key should have no duplicated characters" << endl;
        
}
