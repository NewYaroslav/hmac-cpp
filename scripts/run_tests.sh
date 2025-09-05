#!/usr/bin/env bash
set -e
# Configure and run tests
cmake -S . -B build -DHMACCPP_BUILD_TESTS=ON
cmake --build build --target test_all test_totp
cd build
ctest --output-on-failure
