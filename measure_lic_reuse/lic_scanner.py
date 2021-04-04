#!/usr/bin/env  python

# analyze  app license.
# Input: Android APK Decomposed Dir
# Output: md5, appname, license name


import argparse
import os
import subprocess
import logging
import time

def get_time_tag():
    ts = time.gmtime()
    return time.strftime("%Y-%m-%d-%H-%M-%S", ts)

def run_w(shell_cmd):
    """
    run shell cmds with result returned
    """
    logging.debug("executing shell cmd : " + shell_cmd)
    try:
        res = os.popen(shell_cmd).read().strip()
    except:
        logging.error("error in executing : " + shell_cmd)
        res = "" 
    return res

def main(args, output=".txt"):
    path = args.apkpath
    time_str = get_time_tag()
    prefix = '__'.join(os.path.abspath(path).split('/')[2:])
    output_path = prefix + output
    output_h = open(output_path, 'w+')
    output_h.write("Analyzing %s\n%s\n\n" %(os.path.abspath(path), time_str))
    output_h.write("MD5\t\tLicense Path and Name\n")
    for subdir, dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(subdir, file)
            if filepath.endswith('.lic'):
                md5_cmd = "md5sum %s"%(filepath)
                res_md5 = run_w(md5_cmd)
                md5 = res_md5.split()[0][:8]
                report_line = "%s %s\n"%(md5, filepath)
                output_h.write(report_line)

    output_h.close()
    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='lic_scanner')
    parser.add_argument('apkpath',
            help = 'path to apk file or directory')
    args = parser.parse_args()

    logging.basicConfig(filename='analyzer.log', level=logging.DEBUG)

    main(args)
