Command line used to find this crash:

afl-fuzz -i /home/kali/fuzzing/sessions/php7/in -o /home/kali/fuzzing/sessions/php7/out -x /home/kali/fuzzing/sessions/php/dictionary/dictionary.txt -m none -S slave1 -- /home/kali/fuzzing/victims/php-src-php-5.6.40/sapi/cli/php-afl-asan -r eval(file_get_contents("php://stdin"));

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
