#include "freq_count.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cctype>
#include <algorithm>
#include <vector>

using namespace std;
using namespace frequency;

struct frequency_count
{
    char letter;
    uint64_t count;
    double percent;
};

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
            cout << "\t" << (char)f.letter << " (" << setw(4) << (int)f.letter << ")" << "\t" << setw(10) << f.count;
            cout << "\t" << setprecision(5) << f.percent << "%" << endl;
        }
            
    }

    return 0;
}