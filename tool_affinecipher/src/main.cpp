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

const string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
const string FREQUENCIES = "etaoinsrhdlucmfywgpbvkxqjz";

enum class Input{None, File, Term};
enum class Output{None, File, Term};
enum class Mode{None, Encrypt, Decrypt, Crack_All, Crack_Best};

bool processArgs(int argc, char** argv, Input& inMode, Output& outMode, Mode& op, 
                 int64_t& a, int64_t& b, string& input, string& output,
                 vector<pair<char, char>>& known);
void help(string name, string msg = "");
pair<int, int> linsolve(pair<char, char> p1, pair<char, char> p2);
pair<int, string> checkSoln(int a, int b, string ciph, vector<pair<char, char>>& known);

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
    cout << msg << endl;
}
