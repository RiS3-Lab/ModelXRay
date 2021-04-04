#!/bin/sh
#path=reports/
path=$1
fws="tensorflow caffe sensetime ncnn other mxnet uls mace"
echo  "statistics for $(realpath $path)"
echo  "fws: $fws"
echo ""
for use in OCR ocr speech idcard bankcard 
do
    echo $use
    # handle most framework 
    #for fw in tensorflow caffe sensetime ncnn other
    for fw in $fws 
    do
        echo $fw  ": " "$(ag -f -s -l  $use $(ag -f -l "$fw:" $path) |wc -l)"
    done
    # handle tflite separately
    echo "tflite" ":" "$(ag -f -s -l  $use $(ag -f -l 'tflite' $path) |wc -l)"
    echo ""
done

for use in recog liveness track
do
    echo $use
    # handle most framework 
    #for fw in tensorflow caffe sensetime ncnn other
    for fw in $fws 
    do
        echo $fw  ": " "$(ag -l  $use $(ag -f -l -s face $(ag -f -l "$fw:" $path)) |wc -l)"
    done
    # handle tflite separately
    echo "tflite" ":" "$(ag -l  $use $(ag -f -l -s face $(ag -f -l "tflite" $path)) |wc -l)"
    echo ""
done

for use in handdetect handwriting iris
do
    echo $use
    # handle most framework 
    #for fw in tensorflow caffe sensetime ncnn other
    for fw in $fws 
    do
        fl=$(ag -f -l "$fw:" $path)
        if [ -z "$fl" ] 
        then
             echo $fw ": 0"
        else
            echo $fw  ": " "$(grep -l  $use $fl |wc -l)"
        fi
        #echo $fw  ": " "$(grep -l  $use $(ag -f -l "$fw:" $path) |wc -l)"
    done
    # handle tflite separately
    echo "tflite" ":" "$(grep -l  $use $(ag -f -l "tflite" $path) |wc -l)"
    echo ""
done
