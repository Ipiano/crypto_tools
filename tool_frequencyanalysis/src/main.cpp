#include "freq_count.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cctype>

using namespace std;
using namespace frequency;

int main(int argc, char** argv)
{
    if(argc < 2)
    {
        cout << "Usage: " << argv[0] << " file1 file2 file3..." << endl;
        return 1;
    }

    uint64_t frequencies[255] = {0};

    for(uint32_t i=1; i<argc; i++)
    {
        ifstream fin(argv[i]);
        if(fin)
        {
            cout << "Processing " << argv[i] << "..." << endl;
            countFrequencies(fin, frequencies);
        }
        else
        {
            cerr << "Unable to process " << argv[i] << endl;
        }
    }

    string line = string(50, '-');
    cout << endl << line << endl;

    uint64_t total;
    for(uint32_t i=0; i<255; i++)
        total += frequencies[i];

    cout << total << " total characters read" << endl << line << endl << endl;

    for(uint32_t i=0; i < 255; i++)
    {
        if(frequencies[i])
        {
            cout << "\t" << (char)i << " (" << setw(3) << i << ")" << "\t" << setw(10) << frequencies[i];
            cout << "\t" << setprecision(5) << frequencies[i]/(double)total*100 << "%" << endl;
        }
            
    }

    return 0;
}