#!/bin/sh
./fw_purpose_stat.sh    /your/path/to/modelxray/360_output/reports > 360.result
./fw_purpose_stat.sh    /your/path/to/modelxray/gplay_output/reports > gplay.result
./fw_purpose_stat.sh    /your/path/to/modelxray/tencent_output_dir/reports > tencent.result

./fw_purpose_stat.py 360.result,gplay.result,tencent.result > fw_purpose.tbl
