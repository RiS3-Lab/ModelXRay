#!/usr/bin/env  python

# analyze whether Android app use cloud ai.
# Input: Android APK file
# Output: AI Vendor, AI Service, EvidenceType


import argparse
import os
import subprocess
import logging
import time

def ls_dir(dir):
    filenames = [] 
    for subdir, dirs, files in os.walk(dir):
        for file in files:
            filepath = os.path.join(subdir, file)
            filenames.append(filepath)
    return filenames

def get_libs_info(decpath):
    lib_path = decpath + '/' + 'lib'
    lib_files = ls_dir(lib_path)
    libs = ""
    for f in lib_files:
        libs += os.path.basename(f) + ' '
    return libs

def run_w(shell_cmd):
    """
    run shell cmds with result returned
    """
    #logging.debug("executing shell cmd : " + shell_cmd)
    try:
        res = os.popen(shell_cmd).read().strip()
    except:
        logging.error("error in executing : " + shell_cmd)
        res = "" 
    return res

# ag "firebase/ml/vision/cloud" smali*/ -l
def get_Google_AI(decpath):
    shell_cmd = "ag %s -i -l --silent -m2 %s" %("firebase/ml/vision/cloud", decpath)
    match = run_w(shell_cmd)
    return match.split('\n')[0]

# ag "com.amplifyframework.predictions" smali*/ -l
def get_Amazon_AI(decpath):
    shell_cmd = "ag %s -i -l --silent -m2 %s" %("com.amplifyframework.predictions", decpath)
    match = run_w(shell_cmd)
    return match.split('\n')[0]

# ag "alexaDeepLink" smali*/ -l
def get_Alexa_AI(decpath):
    shell_cmd = "ag %s -i -l --silent -m2 %s" %("alexaDeepLink", decpath)
    match = run_w(shell_cmd)
    return match.split('\n')[0]

# ag "alexaDeepLink" smali*/ -l
# compile group: 'com.azure', name: 'azure-ai-textanalytics', version: '5.1.0-beta.1'
def get_Azure_AI(decpath):
    shell_cmd = "ag %s -i -l --silent -m2 %s" %("azure-ai", decpath)
    match = run_w(shell_cmd)
    return match.split('\n')[0]

def is_Baidu_NLP(libs):
    if 'BaiduSpeechSDK' in libs or 'vad' in libs:
        return True
    else:
        return False

def is_Baidu_synthesizer(libs):
    if 'BDSpeechDecoder' in libs:
        return True
    else:
        return False
 
def is_Baidu_OCR(libs):
    if 'ocr-sdk' in libs:
        return True
    else:
        return False

def run_wo(shell_cmd):
    print("run_wo cmd: %s" % shell_cmd)
    res = subprocess.call(shell_cmd, shell=True)
    if res != 0:
        logging.error("error in executing cmd :" + shell_cmd)
    return

def decompose(args, apkpath, decompose_path):
    decpath = os.path.abspath(decompose_path)
    if args.lib_only is True:
        shell_cmd = "apktool d %s -o %s --no-res --no-src" % (apkpath, decpath)
    else:
        shell_cmd = "apktool d %s -o %s --no-res" % (apkpath, decpath)
    run_wo(shell_cmd)
    return

# Input:
#       @apk, path to apk file 
def online_AI_analyzer(args, apkpath, blacklist):
    print("analyzing %s ..." % apkpath)
    apkname = os.path.basename(apkpath)[:-4]

    if apkname in blacklist:
        print("skipping %s ..." % apkname)
        return ""

    decomposed_path = '/home/ethan/work/ML-Prot/decomposed_apps/' + apkname
    if not os.path.isdir(decomposed_path):
        try:
            decompose(args, apkpath, decomposed_path)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            print("decompose exception happened!")
    libs = get_libs_info(decomposed_path)
    print("libs:")
    print (libs)

    record = ""

    if args.lib_only: 
        # this option is for analyze chinese apps
        # as chinese apps don't need to check smali code, save time
        if (is_Baidu_NLP(libs)):
            record = record + "Baidu:NLP,"
        elif (is_Baidu_synthesizer(libs)):
            record = record + "Baidu:Synthesizer,"
        elif (is_Baidu_OCR(libs)):
            record = record + "Baidu:OCR,"
        else:
            # no need to report libs info when no lib matching
            libs = ""

        if record != "":
            report_line = "%s %s %s"%(apkname, record, libs) 
        else:
            report_line = ""
    else:
        # check Baidu AI service
        if (is_Baidu_NLP(libs)):
            record = record + "Baidu:NLP,"
        elif (is_Baidu_synthesizer(libs)):
            record = record + "Baidu:Synthesizer,"
        elif (is_Baidu_OCR(libs)):
            record = record + "Baidu:OCR,"
        else:
            # no need to report libs info when no lib matching
            libs = ""

        g_line = get_Google_AI(decomposed_path)
        if g_line != "":
            record = record + "Google:AI," 

        a_line = get_Amazon_AI(decomposed_path)
        if a_line != "":
            record = record + "Amazon:AI," 

        x_line = get_Alexa_AI(decomposed_path)
        if x_line != "":
            record = record + "Alexa:AI," 

"""
        // https://mvnrepository.com/artifact/com.azure/azure-ai-textanalytics
        compile group: 'com.azure', name: 'azure-ai-textanalytics', version: '5.1.0-beta.1'
"""
        # microsoft Azure 
        m_line = get_Azure_AI(decomposed_path)
        if m_line != "":
            record = record + "Azure:AI," 

        if record != "":
            report_line = "%s %s %s %s %s %s"%(apkname, record, g_line, a_line, x_line, libs)
        else:
            report_line = ""

    print("report_line:" + report_line)
    if report_line == "": # remove decomposed dir
        shell_cmd = "rm -fr %s" % decomposed_path
        run_wo(shell_cmd)
        shell_cmd = "echo \"%s\" >> non_ml_apklist.txt" % apkname
        run_wo(shell_cmd)

    return report_line 

def get_time_tag():
    ts = time.gmtime()
    return time.strftime("%Y-%m-%d-%H-%M-%S", ts)

def main(args, blacklist, output=".txt"):
    path = args.apkpath
    time_str = get_time_tag()
    prefix = '__'.join(os.path.abspath(path).split('/')[2:])
    output_path = prefix + output
    output_h = open(output_path, 'w+')
    output_h.write("Analyzing %s\n%s\n\n" %(os.path.abspath(path), time_str))
    if os.path.isfile(path):
        report_line = online_AI_analyzer(args, path, blacklist)
        if (report_line != ""):
            output_h.write(report_line+'\n')
    elif os.path.isdir(path): # is path
        for subdir, dirs, files in os.walk(path):
            for file in files:
                filepath = os.path.join(subdir, file)
                if filepath.endswith('apk'):
                    report_line = online_AI_analyzer(args, filepath, blacklist)
                    if (report_line != ""):
                        output_h.write(report_line+'\n')
    else:
        print("Wrong path: %s!"%path)

    output_h.close()

    return

def setup_blacklist(apklist):
    fh = open(apklist, 'r')
    non_ml_apklist = fh.readlines()
    blacklist = []
    for line in non_ml_apklist:
        blacklist.append(line.strip())
    fh.close()
    return blacklist

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='online_ai_analyzer')
    parser.add_argument('apkpath',
            help = 'path to apk file or directory')
    parser.add_argument('-l', '--lib-only', action='store_true',
            help = 'decode library only, no smali code analysis')
    args = parser.parse_args()

    logging.basicConfig(filename='analyzer.log', level=logging.DEBUG)

    apklist = "non_ml_apklist.txt"
    blacklist = setup_blacklist(apklist)
    main(args, blacklist)
