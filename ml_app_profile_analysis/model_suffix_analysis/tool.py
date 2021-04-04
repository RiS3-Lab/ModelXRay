#!/usr/bin/env python
import sys
import operator
fn = sys.argv[1]
a = open(fn).readlines()
b = {} 
for line in a:
    fields = line.split()[4]
    ends = fields.split('.')[-1]
    if ends not in b:
        b[ends] = 1
    else:
        tmp = b[ends]
        b[ends] = tmp + 1

sorted_x = sorted(b.items(), key=operator.itemgetter(1))
print sorted_x 
