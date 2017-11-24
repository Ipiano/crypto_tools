#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <functional>

#include "des4.h"

using namespace std;
using namespace des4;

enum class Input{None, File, Term};
enum class Output{None, File, Term};
enum class Mode{None, Encrypt, Decrypt};

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, string& input, string& output);
void help(string name, string msg = "");

int main(int argc, char** argv)
{
    string key, input, output;
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

    if(key.find_first_not_of("01") != string::npos || key.size() != 9)
    {
        help(argv[0], "Key must contain exactly 9 characters from the set [\'0\', \'1\']");
        return 3;
    }

    uint16_t key_val = 0;
    for(int i=0; i<9; i++)
        key_val |= ((key[i] - '0') << 8 - i);

    inText << input;

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

    function<uint16_t(uint16_t, const uint16_t&, const uint16_t&)> op = (operation == Mode::Encrypt ? encrypt : decrypt);

    uint8_t blocks[3];
    while(*inStream)
    {
        blocks[0] = blocks[1] = blocks[2] = 0;
        inStream->read((char*)blocks, 3);

        uint16_t block1 = (blocks[0] << 4) | (blocks[1] >> 4);
        uint16_t block2 = (blocks[1] << 8) | blocks[2];

        block1 = op(block1, key_val, 4);
        block2 = op(block2, key_val, 4);

        blocks[0] = (block1 & 0xFF0) >> 4;
        blocks[1] = ((block1 & 0xF) << 4) | ((block2 & 0xF00) >> 8);
        blocks[2] = (block2 & 0xFF);
        
        outStream->write((char*)blocks, 3);
    }

    inFile.close();
    outFile.close();

    return 0;
}

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, string& key, string& input, string& output)
{
    inMode = Input::None;
    outMode = Output::None;
    op = Mode::None;

    for(int i=1; i<argc; i++)
    {
        string arg = argv[i];

        if(arg == "-k")
        {
            if(i >= argc-1)
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

    return true;
}

void help(string name, string msg)
{
    cout << msg << endl;
}