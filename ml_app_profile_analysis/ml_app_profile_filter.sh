#!/bin/sh

function process_report {
   local f=$1
   ./reportanalyzer.py -f $f  # without encryption filter
   ./reportanalyzer.py -fe $f # with encryption filter
   ./reportanalyzer.py -p $f.filtered > $f.filtered.packages
   ./reportanalyzer.py -p $f.encrypted.filtered > $f.encrypted.filtered.packages
   ./reportanalyzer.py -p $f> $f.packages
   ./reportanalyzer.py -l $f.filtered > $f.libinfo.csv
}

<< 'COMMENT'
for report in reports/*.entropy_report
do
    process_report $report
done
COMMENT

#process_report ../evaluation/eval_false_negative/output_dir/entropy_report
process_report ../evaluation/output_dir/entropy_report
