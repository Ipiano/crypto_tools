#include "bbs.h"

#include <gmpxx.h>
#include <iostream>

using namespace std;
using namespace bbs;

int main()
{
    mpz_class p("24672462467892469787");
    mpz_class q("396736894567834589803");

    blum_blum_shub_engine<uint32_t> engine(p, q, mpz_class("873245647888478349013"));
    uniform_int_distribution<uint32_t> distro;

    for(int i=0; i<1000; i++)
        cout << distro(engine) << endl;

    return 0;
}
