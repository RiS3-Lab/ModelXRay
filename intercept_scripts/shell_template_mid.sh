#WorkingPath=/sdcard/com.xx.yy
IsDir=`adb shell ls $WorkingPath &> /dev/null ; echo "$?"`
if [ $IsDir == 0 ] ; then 
    echo "App Buffer Folder Exist!"
else
    echo "App Buffer Folder Don't Exist! Creating Folder"
    adb shell mkdir $WorkingPath
fi
