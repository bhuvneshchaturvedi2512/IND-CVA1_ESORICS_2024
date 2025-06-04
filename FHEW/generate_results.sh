#!/bin/bash
cp results_FHEW.cpp FHEW
cd FHEW
g++ -w -ansi -Wall -O3 -o results_FHEW results_FHEW.cpp -L. -lfhew -lfftw3 -std=c++11
./results_FHEW
mv Number_of_decryptions.csv ..
mv generated_key.txt ..
mv secret_key.txt ..
cd ..
python verify.py
