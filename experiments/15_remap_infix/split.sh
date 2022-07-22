#!/usr/bin/env bash

src=sym
tgt=math

echo "creating train, valid, test..."
for l in $src $tgt; do
    awk '{if (NR%23 == 0)  print $0; }' ../data/data_n/data_01/$l.remap > ./data/valid.$l
    awk '{if (NR%23 == 1)  print $0; }' ../data/data_n/data_01/$l.remap > ./data/test.$l
    awk '{if (NR%23 != 0 && NR%23 !=1)  print $0; }' ../data/data_n/data_01/$l.remap > ./data/train.$l

done
