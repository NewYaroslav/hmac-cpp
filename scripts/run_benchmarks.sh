#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DHMACCPP_BUILD_EXAMPLES=ON
cmake --build build-bench --config Release
hyperfine "./build-bench/example"
