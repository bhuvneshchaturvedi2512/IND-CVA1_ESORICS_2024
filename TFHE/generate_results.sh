#!/bin/bash
gcc -w results_TFHE.c -o results_TFHE -ltfhe-spqlios-fma
./results_TFHE
python verify.py
