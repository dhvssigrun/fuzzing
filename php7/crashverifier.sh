#!/bin/bash


export USE_ZEND_ALLOC=0 
for FILE in $(find . -iname '*sig*'); do cat $FILE | /home/kali/fuzzing/victims/php-src-php-5.6.40/sapi/cli/php-afl-asan -r 'eval(file_get_contents("php://stdin"));' 2>&1 | grep -i 'sanitizer' -A 10 && echo $FILE; done
