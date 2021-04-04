#!/bin/sh

for f in $(ls ruimin_*)
do
     echo $f
     newf=${f#ruimin__nfs__}
     mv $f $newf
done
