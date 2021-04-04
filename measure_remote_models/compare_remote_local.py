#!/usr/bin/env python

import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='online_ai_analyzer')
    parser.add_argument('remotepath',
            help = 'path to file contain remote models app info')
    parser.add_argument('localpath',
            help = 'path to file contain local models app info')
    args = parser.parse_args()
    # extract apps that use remote model
    remote_app_file = args.remotepath
    remote_apps = []
    lines = open(remote_app_file).readlines()
    for line in lines:
        fields = line.strip().split()
        if len(fields) > 2:
            app = fields[0]
            if app not in remote_apps:
                remote_apps.append(app)

    # extract local apps
    local_app_file = args.localpath
    local_apps = []
    lines = open(local_app_file).readlines()
    for line in lines:
        fields = line.strip().split()
        if len(fields) >= 1:
            app = fields[3]
            if app not in local_apps:
                local_apps.append(app)

    c = 0
    commen_apps = [] 
    for app in remote_apps:
        if app in local_apps:
            commen_apps.append(app)
            c = c + 1
    a = len(remote_apps)
    b = len(local_apps)
    #print(commen_apps)
    print("analyze %s and %s " %(remote_app_file, local_app_file))
    print("remote apps: %d, local_apps: %d, commen apps: %d" % (a, b, c))
