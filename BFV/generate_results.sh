#!/bin/bash
cmake . -Wno-dev
make
./results_BFV
python verify.py
rm CMakeCache.txt
rm cmake_install.cmake
rm Makefile
rm -rf CMakeFiles
