#!/usr/bin/python

import sys
import os.path
import os

# import parent dir as python search path
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import framework

PROJDIR = os.getcwd() + "/"
BASEDIR = os.path.realpath(PROJDIR + "/../")


config = {
    # name of the software we fuzz
    "name": "test client",

    # which version of the software are we fuzzing (optional)
    "version": "",

    # additional comment about this project (optional)
    "comment": "client unit test",

    # Path to target
    "target_bin": PROJDIR + "bin/clienttest",

    # target arguments
    # separate arguments by space
    # keywords: ""%(port)i" is the port the server will be started on
    "target_args": "%(port)i",

    # how many fuzzing instances should we start
    "processes": 1,

    # "tcp" or "udp" protocol?
    "ipproto": "tcp",

    # STOP.
    # no need to change after this line, usually

    # hongg stuff
    "honggpath": "/usr/local/bin/honggfuzz",
    "honggcov": None,
    "honggmode_option": None,  # will be overwritten based on honggcov

    # should we abort if aslr is enabled?
    "ignore_aslr_status": True,

    # have a special app protocol implemented? use it here
    "proto": None,

    # the maximum network message number we will look at
    # (send, replay, test etc.)
    "maxmsg": None,

    # the maximum network message number we will fuzz
    "maxfuzzmsg": None,

    # analyze the response of the server?
    "response_analysis": True,

    # input/output for fuzzer is generated here (so he can mutate it)
    # also ASAN log files
    "temp_dir": PROJDIR + "temp_dir",

    # fuzzing results are stored in out/
    "outcome_dir": PROJDIR + "out",

    # which fuzzer should be used
    # currently basically only radamsa
    "fuzzer": "Radamsa",

    # Directory of input files
    "input_dir": PROJDIR + "in",

    # Directory of verified files
    "verified_dir": PROJDIR + "verified",

    # if you have multiple ffw fuzzers active,
    # change this between them
    # Use something between 20'0000 and 30'000 or bad stuff may happen
    "target_port": 20000,

    # dont change this
    "basedir": BASEDIR,
    "projdir": PROJDIR,

    # restart server every X fuzzing iterations
    "restart_server_every": 200,
}


def main():
    framework.realMain(config)


if __name__ == '__main__':
    sys.exit(main())
