#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include <functional>
#include <memory>
#include <stdexcept>

#include "affinecipher.h"

using namespace std;

enum class Input{None, File, Term};
enum class Output{None, File, Term};
enum class Mode{None, Encrypt, Decrypt};

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, int64_t& a, int64_t& b, string& input, string& output);
void help(string name, string msg = "");

int main(int argc, char** argv)
{
    string input, output;
    int64_t a, b;
    Input inputMode;
    Output outputMode;
    Mode operation;

    stringstream inText;

    ifstream inFile;
    ofstream outFile;

    istream* inStream = &inText;
    ostream* outStream = &cout;

    if(!processArgs(argc, argv, inputMode, outputMode, operation, a, b, input, output))
    {
        return 1;
    }

    unique_ptr<affine::transformer> aff;

    try
    {
        aff.reset(new affine::transformer(a, b));
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

    function<string(const string&)> op = std::bind((operation == Mode::Encrypt ? &affine::transformer::encrypt : &affine::transformer::decrypt), aff.get(), placeholders::_1);

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

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, int64_t& a, int64_t& b, string& input, string& output)
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

    return true;
}

void help(string name, string msg)
{
    cout << msg << endl;
}
