#!/bin/sh
./offline_model_update_analyze.py -r 360.entropy_report  -p 360.entropy_report.filtered.packages | wc -l
./offline_model_update_analyze.py -r tencent.entropy_report  -p tencent.entropy_report.filtered.packages | wc -l
./offline_model_update_analyze.py -r us.entropy_report  -p us.entropy_report.filtered.packages |wc -l
