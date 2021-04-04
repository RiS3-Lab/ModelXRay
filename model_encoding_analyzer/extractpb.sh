#!/bin/sh
bn=$(basename $1)
if [ "$#" -eq 2 ]
then
dd if=$1 of=$bn.truncated.pb bs=1 skip=$2
elif [ "$#" -eq 3 ]
then
dd if=$1 of=$bn.truncated.pb bs=1 skip=$2 count=$3
else
echo " param error! "
fi
