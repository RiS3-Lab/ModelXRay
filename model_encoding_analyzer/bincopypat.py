#!/usr/bin/env python
import argparse

def truncate(infile, outfile, pat):
    data = open(infile, 'rb').read()
    outf = open(outfile, 'wb')
    length = len(data) - len(pat)
    loc = -1
    for i in xrange(length):
        found = True 
        for j in range(len(pat)):
            if data[i + j] != pat[j]:
                found = False
                break
        if found == True:
            loc = i
            break
    outf.write(data[:loc])
    outf.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--infile', help='binfile to be truncated')
    parser.add_argument('-p', '--pattern', help='pattern as delimiter')
    parser.add_argument('-o', '--output', help='output file')
    args = parser.parse_args()
    binf = args.infile
    pat = args.pattern
    out = args.output

    truncate(binf, out, pat)

