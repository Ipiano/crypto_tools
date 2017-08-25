#include "cryptooltest.h"
#include "algotest.h"
#include "gmpmodtest.h"

#include <iostream>

using namespace std;

int main()
{
    cout << "This tool does a frequency analysis" << endl;

    testcryptoolfunction();
    testgmpfunction();
    testalgorithmfunction(3);
}