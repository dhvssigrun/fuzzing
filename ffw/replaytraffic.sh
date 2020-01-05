#!/bin/bash
set -e
cd "$(dirname "$0")" 

for i in corpus/*; do
./ffw.py --replay --file $i 
echo "replayed testcase" $i
done

