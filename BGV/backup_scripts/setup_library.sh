#!/bin/bash
git clone https://github.com/microsoft/SEAL.git
cp rlwe.cpp SEAL/native/src/seal/util
cp encryptor.h SEAL/native/src/seal
cp keygenerator.cpp SEAL/native/src/seal
cd SEAL
cmake -S . -B build
cmake --build build
cmake --install build
cd ..
