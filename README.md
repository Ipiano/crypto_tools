# Cryptography Tools

Written by Andrew Stelter

For Dr. Christer Karlsson

As a partial requirement of Cryptography (CSC 512), Fall 2017 at the South Dakota School of Mines and Technology

## Description:
This set of tools utilizes the general
cryptography library at https://github.com/Ipiano/module_crypto which was created as part
of the same project.

The book for the course was  "Introduction to Cryptography with Coding Theory (2nd Edition) 2nd Edition" by
Wade Trappe and Lawrence C. Washington. This book was the main reference used for writing the library.

DISCLAIMER: These tools are not written to follow any specific cryptographic standards. They exist
to demonstrate an understanding of the concepts and theory which the subject is founded on.

### Vigenere Cipher Tool
The vigenere cipher tool can be used to encrypt and decrypt text, as well as 
attack encrypted text in an attempt to determine the key used to encrypt it

### ADFGX Cipher Tool
The ADFGX cipher tool can be used to encrypt and decrypt text using the German
ADFGX cipher and a default substitution matrix

### Affine Cipher Tool
The affine cipher tool can be used to encrypt and decrypt text, as well as 
attack encrypted text in an attempt to determine the a, b used to encrypt it

### Frequency Analysis Tool
The frequency analysis tool can be used to find the frequency of characters
in one or more texts.

### Blum Blum Shub Cipher Tool
The Blum Blum Shub Cipher tool can be used to encrypt and decrypt text using a one-time pad.
The one-time pad of bits is generated using the Blum Blum Shub pseudo-random number generation
algorithm.

### Simplified DES Tool
The book used for the course described a simplified version of the DES which uses 4-rounds and operates on
blocks of 12 bits. The des4 tool can be used to encrypt and decrypt text using this method, as well as attack
the same algorithm which is encrypting text using 3 or 4 rounds.

### Full DES Tool
The des64 tool is the full 64-bit DES. It can be used to encrypt or decrypt text in ECB mode.

### RSA Tool
The RSA tool can be used to generate RSA public and private key pairs, as well as use those
pairs to encrypt and decrypt texts.

## Building the Tools
Each tool can be built with the command 
```
make
```
This will generate a release version of the tool in [tool directory]/release. To build a debug version in [tool directory]/debug,
use the command 
```
make BUILD_TYPE=debug
```

### Dependencies
Both the RSA tool and the Blum Blum Shub cipher tool require the GNU Multi-Precision Library (GMP).

This entire repository requires the cryptography module found at https://github.com/Ipiano/module_crypto as a submodule.
If you did not pull this tools repository with the --recurse-submodules flag, you will need to update the submodule with
```
git submodule init
git submodule update
```

### Documentation
Project documentation can be generated in the /doc directrory by running Doxygen from the root directory.
implementation and background details for the different tools are found in a couple of sections of the project documentation. The Implementation
details can be found on a per-file bases in the 'Files' section of the documentation. Details about the theory of the tools and
building/usage, look under the 'Related Pages' section.
