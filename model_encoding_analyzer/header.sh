#!/bin/sh
res=$2.result
for f in $1/*.$2;
do 
	echo "Processing $f .."; 
	echo "Processing $f .." >> $res; 
    echo "size: " $(ls -lh $f |cut -d' ' -f5) >> $res; 
    echo "entroy: " $(ent -t $f |grep 1, |sed  's/[0-9]*,[0-9]*,\([0-9\.]*\).*/\1/') >> $res
	echo "=== hexdump 96 lines: ===" >> $res
    hexdump -e '8/1 "%02X ""\n"'  -n 96 $f >> $res;
	echo "===   end of hexdump  ===" >> $res
    echo "" >> $res
    echo "=== strings 100 lines: ===" >> $res
	strings $f |head  -n 200>> $res;
    echo "===  end of strings   ===" >> $res
    echo "" >> $res
    if strings $f | grep -q conv1
    then
        echo $f "contains conv1"
        ./hexdumper.sh $f
        ./hexdumperraw.sh $f
    elif strings $f | grep -q conv2
    then
        echo $f "contains conv2"
        ./hexdumper.sh $f
        ./hexdumperraw.sh $f
    elif strings $f | grep -q TFL3 
    then
        echo $f "contains TFL3"
        ./hexdumper.sh $f
        ./hexdumperraw.sh $f
    elif strings $f | grep -q TFL2 
    then
        echo $f
        ./hexdumper.sh $f
        ./hexdumperraw.sh $f
    fi
done
