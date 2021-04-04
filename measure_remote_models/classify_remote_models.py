#!/usr/bin/env python

import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='report_analyzer')
    parser.add_argument('reports',
            help = 'filelist of remote models reports separated by comma')
    args = parser.parse_args()
    remote_reports = args.reports.split(',')
    classes = {}

    for f in remote_reports:
        lines = open(f).readlines()
        for l in lines:
            fields = l.strip().split()
            if len(fields) > 2:
                category = fields[1][:-1] # get rid of ending ','
                if category in classes:
                    classes[category] += 1
                else:
                    classes[category] = 1
    print(classes)
