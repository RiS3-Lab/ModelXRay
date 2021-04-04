#!/usr/bin/env python

def count_unique_models(fname):
    unique_models = []
    lines = open(fname,'r').readlines()
    for line in lines:
        # get hashes
        mid = line.split()[1]
        if mid == 'md5':
            continue
        if mid not in unique_models:
            unique_models.append(mid)
    print(unique_models[0])
    return len(unique_models)

if __name__ == '__main__':
    us = count_unique_models("us.models")
    chn = count_unique_models("chn.models")
    us_enc = count_unique_models("us.models.enc")
    chn_enc = count_unique_models("chn.models.enc")
    print ("us unique models: %d" % us)
    print ("china unique models: %d" % chn)
    print ("us unique encrypted models: %d" % us_enc)
    print ("china unique encrypted models: %d" % chn_enc)
    print ("us model protection rate: %f" % (us_enc*1.0/us))
    print ("china model protection rate: %f" % (chn_enc*1.0/chn))

