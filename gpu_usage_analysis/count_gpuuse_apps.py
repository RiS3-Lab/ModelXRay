#!/usr/bin/env python

def get_ml_gpu_apps(ml_apps, ml_libs, libfile):
    lines = open(libfile, 'r').readlines()
    #print(lines[0])
    target_apps = []
    gpu_libs = []
    for l in lines:
        fields = l.split('/')
        app = fields[0]
        lib = fields[2][:-5]
        #print("app:%s, lib:%s"%(app,lib))
        if lib in ml_libs and app in ml_apps and app not in target_apps:
            target_apps.append(app)
        if lib in ml_libs and lib not in gpu_libs:
            gpu_libs.append(lib)
    #print "[get_ml_gpu_apps]" 
    #print target_apps
    print "GPU Libs %d"%len(gpu_libs)
    return target_apps

def get_ml_apps(packages):
    lines = open(packages, 'r').readlines()
    target_apps = []
    #print(lines[0])
    for l in lines:
        target_apps.append(l.strip())
    #print "[get_ml_apps]" 
    #print target_apps
    return target_apps

def get_ml_libs(libcsv):
    lines = open(libcsv, 'r').readlines()
    #print(lines[0])
    target_libs = []
    for l in lines:
        fields = l.split(',')
        target_libs.append(fields[0])
    #print "[get_ml_libs]" 
    #print target_libs
    return target_libs

def run(packages, libcsv, gpuusefile):
    ml_apps = get_ml_apps(packages)
    ml_libs = get_ml_libs(libcsv)
    ml_gpu_apps = get_ml_gpu_apps(ml_apps, ml_libs, gpuusefile)
    return ml_gpu_apps
    

if __name__ == "__main__":
    packages = "360.entropy_report.filtered.packages"
    libcsv = "360.entropy_report.libinfo.csv"
    gpuusefile = "360.gpuusage"
    ml_gpu_apps = run(packages, libcsv, gpuusefile)
    print "360 ML GPU Apps :%d"%len(ml_gpu_apps)
    print ml_gpu_apps

    packages = "gplay.entropy_report.filtered.packages"
    libcsv = "gplay.entropy_report.libinfo.csv"
    gpuusefile = "gplay.gpuusage"
    ml_gpu_apps = run(packages, libcsv, gpuusefile)
    print "GPlay ML GPU Apps :%d"%len(ml_gpu_apps)
    print ml_gpu_apps

    packages = "tencent.entropy_report.filtered.packages"
    libcsv = "tencent.entropy_report.libinfo.csv"
    gpuusefile = "tencent.gpuusage"
    ml_gpu_apps = run(packages, libcsv, gpuusefile)
    print "Tecent ML GPU Apps :%d"%len(ml_gpu_apps)
    print ml_gpu_apps
