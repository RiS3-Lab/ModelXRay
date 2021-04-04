#!/usr/bin/env python
import argparse
fwmap = {'tensorflow':1,'caffe':2,'sensetime':3,'ncnn':4,'other':5,'mxnet':6,'uls':7,'mace':8,'tflite':9}

def printres(th, res):
    th.append('sum')
    print "%15s"%(" "),
    for i in th:
        print i,
    print ""
    for use in res:
        print "%15s"%(use),
        fwres = res[use]
        sum = 0 
        for key in th[:-1]:
            val = fwres[key]
            #print "(%s,%d)"%(fw,fwres[fw]),
            #print "%d\t"%(fwres[fw]),
            #sum = sum + fwres[fw]
            print "%d\t"%(val),
            sum = sum + val
        print "%d\t"%(sum),
        print "" 

def process_filelist(filelist):
    fdlist = []
    for f in filelist:
        fd = open(f,'r').readlines()
        fdlist.append(fd)

    fcmap = {'ocr':15,'speech':26,'idcard':37,'bankcard':48,'recog':59,'liveness':70,'track':81,'handdetect':92,'handwriting':103,'iris':114}
    restable = {}
    for key in fcmap:
        res = {}
        for fw in fwmap:
            sum = 0
            for fd in fdlist:
                fields = fd[fcmap[key]+fwmap[fw] - 1].split(':')
                #print(fields)
                sum = sum + int(fields[1])
            res[fw] = sum
        restable[key] = res
    thead = fwmap.keys()
    return (thead,restable)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='modelxray')
    parser.add_argument('filelist',
            help = 'list of files to be processed, like a,b,c')
    args = parser.parse_args()

    filelist = args.filelist.split(',')
    (th,res) = process_filelist(filelist)
    printres(th, res)
