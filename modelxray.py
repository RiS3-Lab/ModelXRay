#!/usr/bin/env python
import logging
import argparse
import ConfigParser
import os
import sys
import subprocess
import json
import time
from multiprocessing import Manager,Process
import progressbar

class ModelXRay:
    """
    modelxray is a static Android APK analysis tool that extract all 
    the useful information about the machine learning model used in the App.
    """
    def __init__(self, apkpath, config, args):
        if args.test_only is True:
            return

        self._apkpath = apkpath
        self._config = config
        self._args = args 
        self._outdir = config.get("config", "output_dir")
        if self._args.decomposed_package is False:
            self._decdir = config.get("config", "decomposed_dir")
        self._pmodels = self._outdir + "/" + "models"
        self._preports = self._outdir + "/" + "reports"
        self._entropy_report = []
        self._is_ml_app = False 
        self._skip = False
        self._guess_fw = None
        try:
            self._magic_func_list = config.get("function_pattern","magic_str").split(',')
            self._max_func_num = int(config.get("config","max_func_num"))
        except:
            self._magic_func_list = ['init','load','model','decrypt','start','create']
            self._max_func_num = 50
        # get free function pattern
        try:
            self._free_func_list = config.get("free_pattern","magic_str").split(',')
            self._free_filter_list = config.get("free_pattern","filter_str").split(',')
        except:
            self._free_func_list = ['free']
            self._free_filter_list = ['free_exception','free_dependent_exception']

        logging.debug("apkpath:" + self._apkpath)
        logging.debug("outdir :" + self._outdir)
        if self._args.decomposed_package is False:
            logging.debug("decdir :" + self._decdir)
        logging.debug("reportsdir :" + self._preports)
        logging.debug("modelsdir :" + self._pmodels)

        if args.decomposed_package is False:
            if args.package_name is True:
                self._pkgname = self.get_package_name()
            else:
                self._pkgname = self.get_path_base()
            self._decpath = os.path.abspath(apkpath)
        else:
            # assume apkpath doesn't end with '/' even with '-d', if so, get rid of it
            if apkpath.endswith('/'):
                self._pkgname = os.path.basename(apkpath[:-1])
            else:
                self._pkgname = os.path.basename(apkpath)

        self._respath = self._outdir + '/' + self._pkgname + '/' 
        self.setup_output_path()
        self.setup_report()
        self.setup_entropy_report()
        pass

    def get_path_base(self):
        base = os.path.basename(self._apkpath)
        if base.endswith('.apk'):
            return base[:-4]
        else:
            return base

    def setup_output_path(self):
        # output dir
        try:
            os.stat(self._outdir)
        except:
            os.mkdir(self._outdir)
    
        # decompose dir 
        if self._args.decomposed_package is False:
            try:
                os.stat(self._decdir)
            except:
                os.mkdir(self._decdir)

        # reports dir 
        try:
            os.stat(self._preports)
        except:
            os.mkdir(self._preports)

        # models dir 
        try:
            os.stat(self._pmodels)
        except:
            os.mkdir(self._pmodels)

    def setup_entropy_report(self):
        self._entropy_report_path = self._outdir + '/' + 'entropy_report' 
        if not os.path.exists(self._entropy_report_path):
            shell_cmd = "echo 'entropy\tmd5\tsize\tpkgname\tfilename\tml_framework:library\t(entropy range(0,8), [>7.5] means random):' > %s" % self._entropy_report_path
            self.run_wo(shell_cmd)

    def setup_report(self):
        repdir = self._outdir + '/' + self._pkgname
        try:
            os.stat(repdir)
        except:
            os.mkdir(repdir)
        reppath = repdir+'/'+'report.md'
        self._report = reppath
        if not os.path.exists(reppath):
            self._rh = open(reppath,'w')
        else:
            if self._args.regenerate_report is True:
                logging.warning("overwriting existing report.md!")
                self._skip = False
                self._rh = open(reppath,'w')
            else:
                self._skip = True
                return

        self._rh.write("# Machine Learning Model Analysis Report for %s \n" % self._pkgname)
        self._rh.write("\n source apk: %s \n" % self._apkpath)
        pass

    def run_w(self, shell_cmd):
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

    def run_wo(self, shell_cmd):
        """
        run shell cmds without result returned
        """
        logging.debug("executing shell cmd : " + shell_cmd)
        res = subprocess.call(shell_cmd, shell=True)
        if res != 0:
            logging.error("error in executing cmd :" + shell_cmd)
        pass

    def get_package_name(self):
        if self._args.decomposed_package is True:
            # TODO extract package name from AndroidManifest.xml
            shell_cmd = 'cat %s/AndroidManifest.xml |grep -Po \'package=\"\K[^\"]*\'' % self._apkpath
        else:
            # extract from apk file
            shell_cmd = 'aapt d xmltree %s AndroidManifest.xml|grep package=|sed \'s/.*package=\"\([0-9a-zA-Z\.]*\)\".*/\\1/\''% self._apkpath

        res = self.run_w(shell_cmd).strip()
        if len(res) == 0:
            logging.info("can't get the correct package name")
            res = os.path.basename(self._apkpath).strip()
            if len(res) == 0:
                logging.error("can't get apkpath")
                return "unknown_apkpath"
        return res

    def decompose(self, pkgname):
        decpath = os.path.abspath(self._decdir+pkgname)
        apkpath = os.path.abspath(self._apkpath)
        self._decpath = decpath
        if os.path.exists(decpath):
            logging.warning(decpath + " already exists!")
        else:
            shell_cmd = "apktool d %s -o %s" % (apkpath, decpath)
            if self._args.fast_run is True:
                shell_cmd += ' --no-res --no-src'
            self.run_wo(shell_cmd)
        pass

    def remove_decomposed_files(self):
        if self._args.decomposed_package is True:
            # only remove respath, but keep decomposed_path if running from decomposed_package 
            respath = self._respath 
            if not os.path.exists(respath):
                logging.warning(decpath + " not exists!")
            else:
                shell_cmd = "rm  -r %s" % (respath)
                self.run_wo(shell_cmd)
        else:
            decpath = self._decpath 
            respath = self._respath 
            if not os.path.exists(decpath) or not os.path.exists(respath):
                logging.warning(decpath + " not exists!")
            else:
                shell_cmd = "rm  -r %s" % (decpath)
                self.run_wo(shell_cmd)
                shell_cmd = "rm  -r %s" % (respath)
                self.run_wo(shell_cmd)
        pass

    def ls_dir(self, dir):
        filenames = []
        for subdir, dirs, files in os.walk(dir):
            for file in files:
                filepath = os.path.join(subdir, file)
                filenames.append(filepath)
        return filenames

    def suffix_analyzer(self, filelist):
        suffix = self._config.get("model_pattern","suffix").split(',')
        suffix = [sf.strip() for sf in suffix]
        res = []
        for f in filelist:
            for suf in suffix:
                if f.endswith('.'+suf.strip()):
                    res.append(f)
        return res

    def keywords_analyzer(self, filelist, config_section):
        keywords = self._config.get(config_section,"keywords").split(',')
        keywords = [x.strip() for x in keywords]
        logging.debug("keywords:" + (','.join(keywords)))
        res = []
        for f in filelist:
            for kw in keywords:
                if f.lower().find(kw.strip()) != -1:
                    res.append(f)

        # filter out unrelevant files that has little chance to be model file
        ex_suffix = self._config.get("model_pattern","ex_suffix").split(',')
        ex_suffix = [x.strip() for x in ex_suffix]
        logging.debug("ex_suffix:" + ','.join(ex_suffix))
        ex_res = []
        for f in res:
            for es in ex_suffix:
                if f.endswith('.'+es.strip()):
                    ex_res.append(f)

        final_res = []
        for x in res:
            if x in ex_res:
                continue
            else:
                final_res.append(x)
        return final_res

    def extract_model_path(self):
        # get all the filename assets/
        if self._args.decomposed_package is True:
            decpath = self._apkpath
        else:
            decpath = os.path.abspath(self._decdir+self._pkgname)
        assets_path = decpath + '/' + 'assets'
        self._passets = assets_path
        assets_files = self.ls_dir(assets_path)
        relpath = [os.path.relpath(path, assets_path) for path in assets_files] 

        # merge potential model files using suffix and keywords analysis
        res_suf = self.suffix_analyzer(relpath)
        res_kw = self.keywords_analyzer(relpath, "model_pattern")
        res = list(set().union(res_suf, res_kw))

        # store model path
        self._models = res

        # report suspected model files
        self._rh.write("\n### Suspected model files under assets/:\n")
        self._rh.write("entropy\t\tsize\tfilename \t(entropy(0,8), [ent >7.5] means random):\n")
        #self._rh.write('\n'.join(res) + '\n')
        for f in res:
            ff = assets_path + '/' + f.strip()
            size_cmd = "ls -sh %s"%(ff)
            ent_cmd = "ent -t %s"%(ff)
            md5_cmd = "md5sum %s"%(ff)
            res_size = self.run_w(size_cmd)
            res_ent = self.run_w(ent_cmd)
            res_md5 = self.run_w(md5_cmd)
            try:
                size = res_size.split()[0]
                ent = res_ent.split('\n')[1].split(',')[2]
                md5 = res_md5.split()[0][:8]
            except:
                size = ""
                ent = ""
                md5 = ""
            self._rh.write(ent + '\t' + size + '\t' + f + '\t' + '\n')

            # write entropy report for quick reference
            self._entropy_report.append(ent + '\t' + md5 + '\t'+ size + '\t' + self._pkgname + '\t' + f + '\t')

        # save model files
        model_files = [os.path.basename(f) for f in res]
        logging.info("model files:" + ','.join(model_files))
        self._model_files = model_files 

    def append_entropy_report(self, guess_fw):
        if len(self._entropy_report) != 0:
            for e in self._entropy_report:
                e += '\t'.join(guess_fw)
                shell_cmd = "echo %s >> %s"%(e, self._entropy_report_path)
                self.run_wo(shell_cmd)


    def setup_lib_symbol(self, filelists):
        symdir = self._outdir + '/' + self._pkgname + '/' + 'lib_symbol_files/'
        self._symdir = symdir
        symfilelist = []
        try:
            os.stat(symdir)
        except:
            os.mkdir(symdir)

        for f in filelists:
            basename = os.path.basename(f)
            symfile = symdir + basename + ".symbols"
            symfilelist.append(symfile)
            if not os.path.exists(symfile):
                shell_command = "nm -D --defined-only %s > %s" %(f, symfile)
                self.run_wo(shell_command)
        return symfilelist

    def setup_lib_strings(self, filelists):
        strdir = self._outdir + '/' + self._pkgname + '/' + 'lib_str_files/'
        self._strdir = strdir
        strfilelist = []
        try:
            os.stat(strdir)
        except:
            os.mkdir(strdir)

        for f in filelists:
            basename = os.path.basename(f)
            strfile = strdir + basename + ".str"
            strfilelist.append(strfile)
            if not os.path.exists(strfile):
                shell_command = "strings %s > %s" %(f, strfile)
                self.run_wo(shell_command)
        return strfilelist
    def filter_meta_inf(self, line):
        if "original/META-INF" in line:
            return False
        else:
            return True 
    def search_dir(self, key, path):
        res_str = []
        shell_cmd = "ag %s -i --silent -m2 %s" %(key, path)
        match = self.run_w(shell_cmd)
        if match != "":
            ml = match.split('\n')
            ml = [m[len(path)-1:] for m in ml]
            if len(ml) > 10:
                ml=ml[:6]
                res_str.append("\t--WARNING  ! Too many matches, show 6 lines only!--")
                res_str.append("\t--SHELL_CMD! %s"%shell_cmd)
            # filter our x/original/META-INF/
            new_ml = filter(self.filter_meta_inf, ml) 
            res_str += new_ml
        return res_str

    def extract_filename_from_search_result(self, res):
        flist = []
        for line in res:
            fname = line.split(':')[0].strip()
            if fname.startswith('--WARNING') or fname.startswith('--SHELL_CMD'):
                continue
            if fname.endswith('.str'):
                fname = fname[:-len('.str')]
            if fname.endswith('.symbols'):
                fname = fname[:-len('.symbols')]
            if fname not in flist:
                flist.append(fname)
        return flist

    def guess_ml_framework_by_magic_str(self, lib_files):
        # report suspected libraries and frameworks 
        guess_fw = []
        fw_libs = []
        self._rh.write("\n\n### Suspected machine learning library files under lib/:\n")

        # generate symbol files for libraries
        symlist = self.setup_lib_symbol(lib_files)
        self._symlist = symlist

        # generate str files for libraries
        strfilelist = self.setup_lib_strings(lib_files)

        if (len(symlist) == 0 or len(strfilelist) == 0):
            logging.warning("symlist or strfilelist is empty!")
            return guess_fw

        symf = symlist[0]
        strf = strfilelist[0]
        symfpath,symftail = os.path.split(symf)
        strfpath,strftail = os.path.split(strf)

        # get framework list from config
        frameworklist = self._config.get("config","framework").split(',')
        logging.debug("framework list:" + (','.join(frameworklist)))

        # do keywords matching for each framework
        for fw in frameworklist:
            flag = False
            libs = []
            self._rh.write("\n\n\t* symbol matching for framework [%s]:\n" % fw)
            # get keywords for each framework
            magic_str_list = self._config.get(fw.strip(),"magic_str").split(',')
            magic_str_list = [x.strip() for x in magic_str_list]
            logging.debug("magic str list:" + (','.join(magic_str_list)))
            for m in magic_str_list:
                res1 = self.search_dir(m, symfpath)
                res2 = self.search_dir(m, strfpath)
                res = res1 + res2
                if len(res) != 0:
                    self._rh.write("\n\t- magic word %s:\n\n"%m)
                    self._rh.write('\t' + '\n\t'.join(res))
                    # set flag
                    flag = True
                    libs += self.extract_filename_from_search_result(res)
            if flag:
                libs = list(set(libs))
                fw += ':'+','.join(libs)
                guess_fw.append(fw)

        self._rh.write("\n\n### Guess Machine Learning Framework:\n")
        self._rh.write('\n'.join(guess_fw))
        self._rh.write('\n\n')

        if len(guess_fw) == 0:
            logging.info("Probably not a machine learning app, for no framework keywords matched!")
        else:
            logging.info("Might be a machine learning app, for framework keywords matched!")
            self._is_ml_app = True 

        self._guess_fw = guess_fw 

        return guess_fw
    def lib_str_match(self, lib_files): # TODO: Not Used For Now
        # report suspected libraries base whether model file show up in library strings 
        self._rh.write("\n\n### Suspected for model files show up library strings under lib/:\n")

        # generate str files for libraries
        strfilelist = self.setup_lib_strings(lib_files)
        if len(strfilelist) == 0:
            logging.warning("strfilelist is empty! skipping lib str match analysis!")
            return

        for mf in self._model_files:
            self._rh.write("\"%s\":\n" % mf)
            sf = strfilelist[0]
            head,tail = os.path.split(sf)
            self.search_dir(mf, head)
        pass

    def general_str_match(self):
        # report files that contains model file, do grep over decomposed dir
        self._rh.write("\n\n### General scan over decomposed dir for model files\n")
        for mf in self._model_files:
            res = self.search_dir(mf, self._decpath)
            if len(res) != 0:
                self._rh.write("\n\n\t===\"%s\"===:\n" % mf)
                self._rh.write('\n'.join(res))
        pass

    def lib_analysis(self):
        """
        extract interesting library files
            1. if library file name has ml lib keywords, dump report it
            2. if library file name don't have ml lib keywords, however, library symbols has, report it.
            3. for reported lib,

        """
        # get all the filename under lib/
        if self._args.decomposed_package is False:
            decpath = os.path.abspath(self._decdir+self._pkgname)
        else:
            decpath = self._decpath
        lib_path = decpath + '/' + 'lib'
        lib_files = self.ls_dir(lib_path)

        # get relative path
        relpath = [os.path.relpath(path, lib_path) for path in lib_files] 

        res_kw = self.keywords_analyzer(relpath, "lib_pattern")

        # report suspected libraries 
        self._rh.write("\n\n### Suspected library files by name-matching under lib/:\n")
        self._rh.write('\n'.join(res_kw) + '\n')

        # do lib symbol analysis
        guess_fw = self.guess_ml_framework_by_magic_str(lib_files)

        # generate entropy report after get framework info
        self.append_entropy_report(guess_fw)

        pass

    def check_magic_function(self, func_name):
        """
        check whether function name matches any predefined magic_str in config:function_pattern
        """
        # get function pattern
        magic_str_list = self._magic_func_list
        func_name_lower = func_name.lower()
        for ms in magic_str_list:
            if func_name_lower.find(ms.strip()) != -1:
                return True
        return False
    def check_free_function(self, func_name):
        free_str_list = self._free_func_list
        free_filter_list = self._free_filter_list
        fn = func_name.lower()
        for fr in free_str_list:
            if fn.find(fr.strip()) != -1: # found it
                for ft in free_filter_list: # check filter list
                    if fn.find(ft.strip()) != -1:
                        return False # filter out
                    else:
                        continue
                return True
            else:
                continue
        return False

    def generate_instrumentation_script(self, json_path, script_name):
        # add frida cmd
        app_name = self.get_package_name()

        script_path = self._respath + '/' + script_name
        js_script_path = script_path + '.js'
        script_top = self._config.get("script", "top")
        script_bottom = self._config.get("script", "bottom")
        # shell script template
        shell_tml_top = self._config.get("script", "shell_top")
        shell_tml_mid = self._config.get("script", "shell_mid")

        # generating javascript from template
        shell_cmd = "cat %s > %s" % (script_top, js_script_path)
        self.run_wo(shell_cmd)
        shell_cmd = "cat %s >> %s" % (json_path, js_script_path)
        self.run_wo(shell_cmd)
        # insert appname
        shell_cmd = "echo ';\nvar appname=\"%s\" ' >> %s" % (app_name, js_script_path)
        self.run_wo(shell_cmd)
        shell_cmd = "cat %s >> %s" % (script_bottom, js_script_path)
        self.run_wo(shell_cmd)

        # as a bonus, generate shell script
        shell_script_path = script_path + '.sh'

        # copy shell template top
        shell_cmd = "cat %s > %s" % (shell_tml_top, shell_script_path)
        self.run_wo(shell_cmd)
        # add workingpath
        shell_cmd = "echo 'WorkingPath=/sdcard/mallocbuffer/%s' >> %s" % (app_name, shell_script_path)
        self.run_wo(shell_cmd)
        # add shell template mid
        shell_cmd = "cat %s >> %s" % (shell_tml_mid, shell_script_path)
        self.run_wo(shell_cmd)
        # add frida cmd
        shell_cmd = "echo 'frida -U -f %s -l %s --no-pause' >> %s" % (app_name, script_name+'.js',shell_script_path)
        self.run_wo(shell_cmd)
        pass

    def get_lib_free_functions(self, lib):
        symdir = self._symdir
        libsympath = symdir + lib + ".symbols"
        free_functions = []
        try:
            logging.debug("libsympath:"+libsympath)
            lines = open(libsympath, 'r').readlines()
            for line in lines:
                fields = line.split()
                # add free function 
                if self.check_free_function(fields[2]) is True:
                    free_functions.append(fields[2])
        except IOError as e:
                print "I/O error({0}): {1}".format(e.errno, e.strerror)
        except:
            logging.error("error in generating lib free json files")
            print "Unexpected error:", sys.exc_info()[0]
            #raise
        return free_functions
    def generate_instrument_free_json(self):
        """
        our goal is to find all ml libraries, and their dependency libs
        for both the dependency libs and themselves, we instrument free
        functions
        depdic = {mllib1: [mllib1, a, b], mllib2: [mllib2, c, d]}
        """

        # first, get dependency analysis for all libraries
        all_libs = []
        symlist = self._symlist
        for symf in symlist:
            symfpath,symftail = os.path.split(symf)
            lib = symftail[:-8] # extract liba.so from liba.so.symbols
            all_libs.append(lib)

        logging.debug("all libs:")
        logging.debug(all_libs)

        all_libs_depdic = self.analyze_lib_dependency(all_libs)

        # second, fetch all the machine learning libraries
        ml_libs = self._libdepdic.keys()

        ## third, combine all_libs_depdic and ml_libs, get our free_depdic
        #free_depdic = {}
        #for lib in ml_libs:
        #    if lib in all_libs_depdic:
        #        free_depdic[lib] = all_libs_depdic[lib]
        #        if lib not in all_libs_depdic[lib]:
        #            free_depdic[lib].append(lib)

        free_depdic = all_libs_depdic

        # get dictionary for instrumenting free functions
        libfreedic = {}

        for lib in free_depdic:
            deplibs = free_depdic[lib]
            # extract raw libname, libocr.so --> ocr
            rawlib = lib[3:-3]
            if len(deplibs) == 1 and deplibs[0] == lib: # no external dependency
                res = self.get_lib_free_functions(lib)
                if res != None:
                    libfreedic[rawlib] = res
                else:
                    logging.info(" can't generate json for lib:" + lib)
                    libfreedic.pop(lib)
            elif len(deplibs) > 1:
                # deplibs are more than one lib
                freedic = {}
                for deplib in deplibs:
                    rawdeplib = deplib[3:-3]
                    res = self.get_lib_free_functions(deplib)
                    if res != None:
                        freedic[rawdeplib] = res
                    else:
                        logging.info(" can't generate json for lib:" + deplib)
                        # skip this library, not every lib has free functions
                if len(freedic) >= 1:
                    libfreedic[rawlib] = freedic
            else:
                logging.error("unexpeced lib dependencies, lib:"+lib)
                logging.error(deplibs)

        return libfreedic

    def generate_lib_json(self, lib, fws):
        symdir = self._symdir
        libsympath = symdir + lib + ".symbols"
        magic_json_list = []
        match_all_list = []
        match_fw_list = []
        res = None
        try:
            logging.debug("libsympath:"+libsympath)
            lines = open(libsympath, 'r').readlines()
            for line in lines:
                fields = line.split()

                # selecting symbols for function definition
                if (len(fields) >= 3) and fields[1] == 'T': 
                    match_all_list.append(fields[2])

                    if self.check_magic_function(fields[2]) is True:
                        magic_json_list.append(fields[2])


                    # if function name contains framework name, add it
                    for fw in fws:
                        if fields[2].lower().find(fw) != -1:
                            match_fw_list.append(fields[2])
                            # matched, break current for loop
                            break

            # truncate function list to avoid overflowing info
            if len(magic_json_list) > self._max_func_num:
                magic_json_list = magic_json_list[:self._max_func_num]

            if len(match_all_list) > self._max_func_num:
                match_all_list = match_all_list[:self._max_func_num]

            if len(match_fw_list) > self._max_func_num:
                match_fw_list = match_fw_list[:self._max_func_num]

            res = (magic_json_list, match_all_list, match_fw_list)
        except IOError as e:
                print "I/O error({0}): {1}".format(e.errno, e.strerror)
        except:
            logging.error("error in generating lib json files")
            print "Unexpected error:", sys.exc_info()[0]
            #raise

        return res

    def generate_libdepdic_json(self, fws):
        """
        given a list of library names and a list of framework names
        generate corresponding instrumentation json file.
        """
        # get lib_sym_dir
        libmagicdic = {}
        liballdic = {}
        libfwdic = {}
        for lib in self._libdepdic:
            deplibs = self._libdepdic[lib]
            # extract raw libname, libocr.so --> ocr
            rawlib = lib[3:-3]
            if len(deplibs) == 1 and deplibs[0] == lib: # no external dependency
                res = self.generate_lib_json(lib, fws)
                if res != None:
                    libmagicdic[rawlib] = res[0]
                    liballdic[rawlib] = res[1]
                    libfwdic[rawlib] = res[2]
                else:
                    logging.info(" can't generate json for lib:" + lib)
                    # skip this library, not every lib has free functions
            elif len(deplibs) == 1 and deplibs[0] != lib: 
                # deplib is not lib, which means lib is not ml lib, only need to instrument deplib
                # when detect system is loading lib
                rawdeplib = deplibs[0][3:-3]
                res = self.generate_lib_json(deplibs[0], fws)
                if res != None:
                    libmagicdic[rawlib] = {rawdeplib:res[0]}
                    liballdic[rawlib] = {rawdeplib:res[1]}
                    libfwdic[rawlib] = {rawdeplib:res[2]}
                else:
                    logging.info(" can't generate json for lib:" + deplibs[0])
                    # skip this library, not every lib has free functions
            elif len(deplibs) > 1:
                # deplibs are more than one lib
                mdic = {}
                adic = {}
                fdic = {}
                for deplib in deplibs:
                    rawdeplib = deplib[3:-3]
                    res = self.generate_lib_json(deplib, fws)
                    if res != None:
                        mdic[rawdeplib] = res[0]
                        adic[rawdeplib] = res[1]
                        fdic[rawdeplib] = res[2]
                    else:
                        logging.info(" can't generate json for lib:" + deplib)
                libmagicdic[rawlib] = mdic
                liballdic[rawlib] = adic
                libfwdic[rawlib] = fdic

        # for free instrumentation, it applies to all libraries
        libfreedic = self.generate_instrument_free_json()

        # write results to json file
        logging.debug("json dumping ... libs: " + ','.join(self._libs) + " fw:" + ','.join(fws))

        magic_json_path = self._respath + '/libdicmagic.json';
        all_json_path = self._respath + '/libdicall.json';
        fw_json_path = self._respath + '/libdicfw.json';
        free_json_path = self._respath + '/libdicfree.json';
        with open(magic_json_path, 'w') as outfile:
            json.dump(libmagicdic, outfile)
            
        with open(all_json_path, 'w') as outfile:
            json.dump(liballdic, outfile)

        with open(fw_json_path, 'w') as outfile:
            json.dump(libfwdic, outfile)

        with open(free_json_path, 'w') as outfile:
            json.dump(libfreedic, outfile)

        # generate the script with json file
        self.generate_instrumentation_script(magic_json_path, "intercept_magic_func")
        self.generate_instrumentation_script(all_json_path, "intercept_all_func")
        self.generate_instrumentation_script(fw_json_path, "intercept_fw_func")
        self.generate_instrumentation_script(free_json_path, "intercept_free_func")

        pass

    def analyze_lib_dependency(self, libs):
        """
        analyze library's dependency relationship,
        if a dep/ b, b will load a.
        don't assump cascaded dependency like
        a dep/ b, b dep/ c
        """
        
        libdepdic = {x:[x] for x in libs}
        for lib in libs:
            shell_cmd = "ag %s -l %s" % (lib, self._strdir)
            res = self.run_w(shell_cmd).strip()
            deps = res.split('\n')
            if len(deps) > 0:
                for dep in deps:
                    base = os.path.basename(dep)[:-4]
                    # generate dependency dictionary
                    if base != lib: # non-self dependency, base will load lib, base 
                        if base in libdepdic:
                            libdepdic[base].append(lib)
                        else:
                            libdepdic[base] = [lib]
                        if lib in libdepdic:
                            libdepdic.pop(lib) # lib will be loaded by base

        logging.debug("libdepdic:")
        logging.debug(libdepdic)

        return libdepdic


    def generate_lib_dependency_report(self, libs):
        self._rh.write("\n\n### Machine Learning Library Dependency/:\n")
        # deduplicate libs
        libs = list(set().union(libs))

        self._libdepdic = self.analyze_lib_dependency(libs)
        self._libs = libs

        for lib in self._libdepdic:
            deps = self._libdepdic[lib]
            self._rh.write("\n[%s]:\n" % (lib))
            self._rh.write("\t%s\n" % (lib)) # self dependency
            for dep in deps:
                self._rh.write("\t%s\n" % (dep))
            self._rh.write("\n")
        pass

    def generate_script(self):
        if self._is_ml_app is False or len(self._guess_fw) == 0:
            return # don't generate script for no ml library found

        # get framework shared library
        libs = []
        fws = []
        for fw in self._guess_fw:
            fields = fw.split(':')
            fw_name = fields[0]
            fw_libs = fields[1].split(',')
            libs += fw_libs
            fws.append(fw_name)

        self.generate_lib_dependency_report(libs)
        self.generate_libdepdic_json(fws)

        pass

    def setup_analyzer(self):
        # add frida cmd
        app_name = self.get_package_name()

        analyzer_src_path = self._config.get("script","analyzer_path")
        analyzer_list = self._config.get("script","analyzer_list").split(',')
        analyzer_path = self._respath + "/model_analyzer/"

        # create analyzer path
        try:
            os.stat(analyzer_path)
        except:
            os.mkdir(analyzer_path)

        for a in analyzer_list:
            # copy analyzer script
            shell_cmd = "cp %s/%s %s" %(analyzer_src_path, a, analyzer_path)
            self.run_wo(shell_cmd)

        # create pull_and_analysis.sh script
        pullbigbuffer_path = analyzer_path + 'pull_and_analysis.sh'
        shell_cmd = "echo '#!/bin/sh' > %s" %(pullbigbuffer_path)
        self.run_wo(shell_cmd)
        shell_cmd = "echo 'rm pb.result' >> %s" %(pullbigbuffer_path)
        self.run_wo(shell_cmd)
        shell_cmd = "echo 'adb pull /sdcard/mallocbuffer/%s' >> %s" %(app_name, pullbigbuffer_path)
        self.run_wo(shell_cmd)
        shell_cmd = "echo './header.sh %s pb' >> %s" %(app_name, pullbigbuffer_path)
        self.run_wo(shell_cmd)
        shell_cmd = "echo 'ag conv pb.result' >> %s" %(pullbigbuffer_path)
        self.run_wo(shell_cmd)
        shell_cmd = "echo 'ag TFL pb.result' >> %s" %(pullbigbuffer_path)
        self.run_wo(shell_cmd)

        pass
    def copy_report(self):
        if len(self._models) == 0 and self._is_ml_app is False:
            return # don't copy for not model found

        link = self._preports + '/' + self._pkgname + '.report'
        target = os.path.abspath(self._report)
        logging.info("target path:" + target)
        shell_cmd = "ln -sf %s %s" %(target, link)
        if os.path.exists(link) is True:
            if self._skip is True:
                return# don't copy
        self.run_wo(shell_cmd)
        pass

    def copy_models(self):
        for m in self._models:
            target = os.path.abspath(self._passets + '/' + m)
            link = self._pmodels + '/' + self._pkgname +'_'+ os.path.basename(m) 
            shell_cmd = "ln -sf %s %s" %(target, link)
            if os.path.exists(link) is True:
                return# don't copy
            self.run_wo(shell_cmd)
        pass

    def test(self):
        logging.debug(" Run Test!")
        time.sleep(1)

    def analyze(self):
        if self._skip is True:
            logging.warning("skipping analysis for report.md is there! see: %s" % self._report)
            return

        if self._args.decomposed_package is False:
            self.decompose(self._pkgname)
        self.extract_model_path()
        self.lib_analysis()

        # generate java script that is needed by dynamic instrumentation
        if self._args.json_script is True:
            self.generate_script()
            self.setup_analyzer()

        if self._args.fast_run is not True:
            self.general_str_match()

        self._rh.close()

        # copy report to reports dir if not exists
        self.copy_report()
        # copy models to models dir if not exists
        self.copy_models()
        
        # Test whether a machine learning app, if not, we might rm decomposed app
        if self._is_ml_app is False and len(self._models) == 0:
            if self._args.space_efficient is True:
                self.remove_decomposed_files()
        pass

def worker(jobs, args, config, ns):
    # only do jobs that jobid % wid == 0
    logging.debug("new worker created!")
    length = len(jobs)
    for i in xrange(length):
        logging.info('modelxray is analyzeing file ' + jobs[i])
        model_profiler = ModelXRay(jobs[i], config, args)
        if args.test_only is True:
            model_profiler.test()
        else:
            model_profiler.analyze()

        # update progress bar
        ns.value = ns.value + 1

        global bar 
        #bar.update(progress)
        bar.update(ns.value)

# test whether it's a decomposed directory
def is_decomposed_dir(path):
    dirs = os.listdir(path)
    if "AndroidManifest.xml" in dirs:
        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='modelxray')
    parser.add_argument('apkpath',
            help = 'path to apk file or directory')
    parser.add_argument('-c', '--config-file', default = 'modelxray.config',
            help = 'the path of %(prog)s config file')
    parser.add_argument('-r', '--regenerate-report', action='store_true',
            help = 'regenerate report even if report is there')
    parser.add_argument('-l', '--log-file', action='store_true',
            help = 'store log in modelxray.log(default to stdout)')
    parser.add_argument('-v', '--verbose', action='store_true',
            help = 'verbose logging info')
    parser.add_argument('-f', '--fast-run', action='store_true',
            help = 'run fast by only analyzing library and assets, not smali code')
    parser.add_argument('-s', '--space-efficient', action='store_true',
            help = 'save space by not storing non-machine learning decomposed apps')
    parser.add_argument('-t', '--test-only', action='store_true',
            help = 'donot do anything, just test work splitting for multiprocessing')
    parser.add_argument('-j', '--json-script', action='store_true',
            help = 'automatically generate json for dynamic instrumentation java script')
    parser.add_argument('-p', '--package-name', action='store_true',
            help = 'use package name as output directory name, default use apk path name')
    parser.add_argument('-d', '--decomposed-package', action='store_true',
            help = 'start analysis from already decomposed packages')
    args = parser.parse_args()

    if args.log_file is True:
        if args.verbose is True:
            logging.basicConfig(filename='modelxray.log', level=logging.DEBUG)
        else:
            logging.basicConfig(filename='modelxray.log', level=logging.INFO)
    else:
        if args.verbose is True:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    config = ConfigParser.RawConfigParser()
    if (os.path.exists(args.config_file)):
        config.read(args.config_file)
    else:
        logging.error("config file not exists")
        exit(1)


    jobs = []
    if os.path.isfile(args.apkpath):
        logging.info('modelxray is analyzeing file ' + args.apkpath)
        model_profiler = ModelXRay(args.apkpath, config, args)
        model_profiler.analyze()
    elif os.path.isdir(args.apkpath):
        logging.info('modelxray is analyzeing dir ' + args.apkpath)
        if args.decomposed_package is True:
            if is_decomposed_dir(args.apkpath):
                # Single decomposed dir
                model_profiler = ModelXRay(args.apkpath, config, args)
                model_profiler.analyze()
            else:
                dirs = os.listdir(args.apkpath)
                for d in dirs:
                    dp = args.apkpath + '/' + d
                    # skip unrevelant dirs
                    if is_decomposed_dir(dp):
                        jobs.append(dp)

        else:
            for subdir, dirs, files in os.walk(args.apkpath):
                for file in files:
                    filepath = os.path.join(subdir, file)
                    if filepath.endswith('apk'):
                        jobs.append(filepath)

        # get worker number
        try:
            ncpu = int(config.get("config","ncpu"))
            logging.debug("ncpu: %d" % ncpu)
        except:
            ncpu = 4

        with progressbar.ProgressBar(max_value=len(jobs)) as bar:
            # create workers 
            workers = []
            mgr = Manager()
            ns = mgr.Namespace()
            ns.value = 0
            jobs_num = len(jobs)
            worker_load = jobs_num / ncpu
            worker_left = jobs_num % ncpu
            if worker_load > 0:
                for i in range(ncpu):
                    subjobs = jobs[i * worker_load : (i+1)*worker_load]
                    workers.append(Process(target = worker, args = (subjobs, args, config, ns))) 
                if worker_left > 0:
                    subjobs = jobs[ncpu*worker_load:jobs_num]
                    workers.append(Process(target = worker, args = (subjobs, args, config, ns))) 

            else:
                workers.append(Process(target = worker, args = (jobs, args, config, ns))) 

            worker_num = len(workers)
            for i in range(worker_num):
                workers[i].start()

            for i in range(worker_num):
                workers[i].join()

    pass
