#!/usr/bin/env bash
set -e
cmake -S . -B build -DBUILD_TESTS=ON -DCMAKE_CXX_STANDARD=${CXX_STANDARD:-11}
cmake --build build --target test_all test_totp
cd build
ctest --output-on-failure
