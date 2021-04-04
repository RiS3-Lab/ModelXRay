#!/bin/sh
# This script is automatically generated for running frida tool.
# Use it with caution:
#   `frida -U -f app_name -l intercept_script.js --no-pause`
#
# Note: 
#   the default app_name might be wrong! If so, Replace app_name 
#   with the real app_name. If you don't know, run 
#      `ps grep app_keyword` 
#   on adb shell to check it.

# create folder for dumping malloc buffers
BufferPath=/sdcard/mallocbuffer/
IsDir=`adb shell ls $BufferPath &> /dev/null ; echo "$?"`
if [ $IsDir == 0 ] ; then 
    echo "Exist!"
else
    echo "Folder Don't Exist! Creating Folder!"
    adb shell mkdir $BufferPath
fi

