#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench --config Release
hyperfine "./build-bench/example"
