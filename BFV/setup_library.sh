#!/bin/bash
git clone https://github.com/microsoft/SEAL.git
cp keygenerator.cpp SEAL/native/src/seal
cd SEAL
cmake -S . -B build
cmake --build build
cmake --install build
cd ..
