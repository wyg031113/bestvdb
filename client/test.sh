#!/bin/bash

while true
do
    vdb_client -b $1
    i=0
    while [ $i -lt 100 ]
    do
        vdb_client -q $1
        if [  $? -ne 1 ] 
        then
            echo "Verify failed"
            exit 0
        fi
    done
done
