#!/bin/bash

if [[ ! -d "build" ]] then
    mkdir -p build &&
    cd build &&
    cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ .. &&
    cd ..
fi

cd build &&
make -j $(nproc) &&
cd test &&
ctest &&
cd ../../