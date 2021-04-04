#!/usr/bin/env python
import argparse
import os

"""
input: 
1. general reports
2. filtered package names
Steps: 
    1. extract all app package name that has confirmed ml library
    2. check whether the app package is in the package list that has confirmed models.
"""

def extract_pkg_with_confirmed_ml_lib(report_file): 
    lines = open(report_file).readlines()
    lib_names = ['tensorflow','caffe','sensetime','uls','mxnet','mace','ncnn']
    pkg_list = []
    for l in lines:
        fields = l.split()
        for lib in lib_names:
            if lib in l:
                if len(fields) < 4:
                    print("skip:%s"%(l))
                    continue
                if fields[3] not in pkg_list:
                    pkg_list.append(fields[3])
                break # break if already found one
    return pkg_list

def check_pkg_list(found_pkg, given_pkg):
    suspect_pkg = []
    for pkg in found_pkg:
        if pkg not in given_pkg:
            suspect_pkg.append(pkg)
    return suspect_pkg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='report_analyzer')
    parser.add_argument('-r', '--report-path', default = '360.entropy_report',
            help = 'raw report path(unfiltered)')
    parser.add_argument('-p', '--package-path', default = '360.entropy_report.filtered.packages',
            help = 'filtered package list')
    args = parser.parse_args()
    report_file = args.report_path
    given_package_lines = open(args.package_path).readlines()
    given_package = []
    for l in given_package_lines:
        given_package.append(l.strip())


    package_list = extract_pkg_with_confirmed_ml_lib(report_file)
    suspect_package = check_pkg_list(package_list, given_package)
    for p in suspect_package:
        print(p)
