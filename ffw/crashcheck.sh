#!/bin/bash
#set -e
cd "$(dirname "$0")" 

for i in `ls -atl crashes/ | grep '^-' | awk '{print $9}'`; do
./ffw.py --replay --file crashes/$i
echo "replayed testcase" $i
sleep 1
done

