#!/bin/bash

while true
do
    vdb_client -b 2
    i=0
    while [ $i -lt 100 ]
    do
        vdb_client -q 2
        if [  $? -ne 1 ] 
        then
            echo "Verify failed"
            exit 0
        fi
    done
done
