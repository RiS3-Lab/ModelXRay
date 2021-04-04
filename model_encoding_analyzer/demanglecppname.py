#!/usr/bin/env python
import os
import sys
import argparse
import subprocess

def demangle(names):
    args = ['c++filt']
    args.extend(names)
    pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, _ = pipe.communicate()
    demangled = stdout.split("\n")

    # Each line ends with a newline, so the final entry of the split output
    # will always be ''.
    assert len(demangled) == len(names)+1
    return demangled[:-1]

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('funcnames', help='c++ method names to be demangled, separated by comma')
        args = parser.parse_args()
        namelist = args.funcnames.split(',')
        print demangle(namelist)

    except KeyboardInterrupt:
        sys.exit(0)
