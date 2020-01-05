#!/bin/bash
set -e
for i in crashes_mqtt/*; do
echo "executing testcase $i"
./ffw.py --replay --file $i
done
