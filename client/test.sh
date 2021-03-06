#!/bin/bash

j=1
while true
do
    vdb_client -b $1
    i=1
    while [ $i -lt 100 ]
    do
        echo test:$i/$j
        vdb_client -q $1
        if [  $? -ne 1 ] 
        then
            echo "Verify failed"
            exit 0
        fi
        let i=i+1
        let idx=i%40
        let id=idx+1
        sql="update plain_tb_test set zip='223$j$i' where id = $id"
        echo $sql
        vdb_client -t 1 -x $idx -u "$sql"
        sleep 3 
    done
    let j=j+1
done
