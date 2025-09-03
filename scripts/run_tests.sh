#!/usr/bin/env bash
set -e
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
cd build
ctest --output-on-failure
