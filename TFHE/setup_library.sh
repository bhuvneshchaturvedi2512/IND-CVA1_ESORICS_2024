#!/bin/bash
git clone https://github.com/tfhe/tfhe.git
cd tfhe
mkdir build
cd build
cmake ../src -Wno-dev
make
make install
cd ../..
