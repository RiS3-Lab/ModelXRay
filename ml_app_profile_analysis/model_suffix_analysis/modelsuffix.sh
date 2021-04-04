#!/bin/sh
fn=modelsuffix.txt

rm $fn
for f in reports/*.filtered
do
    echo "Results for $f" >> $fn
    ./tool.py $f >> $fn
    echo "" >> $fn
done
