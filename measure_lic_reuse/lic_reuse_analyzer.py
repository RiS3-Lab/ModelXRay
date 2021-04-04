#!/usr/bin/env  python

import argparse
import os
import subprocess
import logging
import time

def main(args):
    path = args.licpath
    licf = open(path, 'r')
    lic_dic = {}

    lines = licf.readlines()
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or len(fields[0]) != 8:
            continue
        md5 = fields[0]
        lic_path = fields[1] 
        apk_name = lic_path.split('/')[6]
        lic_name = lic_path.split('/')[-1]
        if md5 not in lic_dic:
            apps = []
            apps.append((apk_name, lic_name,))
            lic_dic[md5] = apps
        else:
            lic_dic[md5].append((apk_name, lic_name, ))

    output_path = os.path.basename(path)+'.reuse_analysis'
    susp_path = os.path.basename(path)+'.reuse_analysis.suspected'

    result_fd = open(output_path,'w')
    susp_fd = open(susp_path,'w')

    susp_count = 0
    for md5 in lic_dic:
        if len(lic_dic[md5]) == 1:
            continue
        result_fd.write('%s:\n'%md5)
        for record in lic_dic[md5]:
            line = ("\t%s %s\n" % (record[0], record[1]))
            result_fd.write(line)
        result_fd.write('\n')

        cur_head = lic_dic[md5][0][0][:9]
        suspected = False
        for record in lic_dic[md5][1:]:
            head = record[0][:9] 
            if head != cur_head:
                suspected = True
                susp_count += 1
                break

        if (suspected is True):
            susp_fd.write('%s:\n'%md5)
            for record in lic_dic[md5]:
                line = ("\t%s %s\n" % (record[0], record[1]))
                susp_fd.write(line)
            susp_fd.write('\n')

    print("Identified %d suspected license reuse cases among different apps" % susp_count)

    susp_fd.write("\nIdentified %d suspected license reuse cases among different apps\n" % susp_count)
    result_fd.close()
    susp_fd.close()
    licf.close()
    return

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='lic_reuse_analyzer')
    parser.add_argument('licpath',
            help = 'license file path')
    args = parser.parse_args()
    main(args)
