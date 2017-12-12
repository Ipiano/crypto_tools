/*! \file 

\page frequency Frequency Analysis Tool

Frequency analysis is the basis for attack on many classic cryptosystems. This tool
can be used to read a set of files and list the frequencies of each character in those files.

\section compile_freq Compiling
This tool can be built with the command 
\verbatim 
make
\endverbatim
This will generate a release version of the tool in the release directory. To build a debug version in the debug directory,
use the command 
\verbatim
make BUILD_TYPE=debug
\endverbatim

\section usage_freq Usage
\verbatim
tool_frequencyanalysis file1 file2 file3...
\endverbatim
*/
#include "freq_count.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cctype>
#include <algorithm>
#include <vector>

using namespace std;
using namespace frequency;

//! Container for letter frequency and relative percentage
struct frequency_count
{
    //! The character this count is for
    char letter;
    //! The number of occurrences of this character
    uint64_t count;
    //! The percent of the text that was this character
    double percent;
};

/*!
    If fewer than two arguments are found, the process terminates.
    
    A global occurrence list is set up, and the frequency count is 
    run on each file of the input that can be read.

    Each character is printed out with its number of occurances and 
    what percentage of the text read was it.

    All alphabetic letters are considered lower-case

    \param[in] argc Number of command line arguments
    \param[in] argv Command line arguments
    \returns 0 The program ran successfully
    \returns 1 No files were given
*/
int main(int argc, char** argv)
{
    if(argc < 2)
    {
        cout << "Usage: " << argv[0] << " file1 file2 file3..." << endl;
        return 1;
    }

    vector<frequency_count> frequencies(255);
    char i = 0;
    for(frequency_count& f : frequencies)
    {
        f.letter = i++;
        f.count = 0;
        f.percent = 0;
    }

    for(uint32_t i=1; i<argc; i++)
    {
        ifstream fin(argv[i]);
        if(fin)
        {
            cout << "Processing " << argv[i] << "..." << endl;
            countFrequencies<vector<frequency_count>::iterator, frequency_count>
                (fin, frequencies.begin(), [](frequency_count& f){ f.count++; });
        }
        else
        {
            cerr << "Unable to process " << argv[i] << endl;
        }
    }

    string line = string(50, '-');
    cout << endl << line << endl;

    uint64_t total = 0;
    for(const frequency_count& f : frequencies)
        total += f.count;

    for(frequency_count& f : frequencies)
        f.percent = f.count/(double)total * 100;

    sort(frequencies.begin(), frequencies.end(), [](const frequency_count& l, const frequency_count& r){ return l.percent > r.percent; });

    cout << total << " total characters read" << endl << line << endl << endl;

    for(const frequency_count& f : frequencies)
    {
        if(f.count)
        {
            cout << "\t " << setw(1) << (f.letter > ' ' ? (char)f.letter : ' ') << "  (" << setw(4) << (int)f.letter << ")" << "\t" << setw(10) << f.count;
            cout << "\t" << setprecision(5) << f.percent << "%" << endl;
        }
            
    }

    return 0;
}