#!/usr/bin/env bash

src=vex
tgt=math

echo "creating train, valid, test..."
for l in $src $tgt; do
    awk '{if (NR%23 == 0)  print $0; }' ../data/$l > ./data/valid.$l
    awk '{if (NR%23 == 1)  print $0; }' ../data/$l > ./data/test.$l
    awk '{if (NR%23 != 0 && NR%23 !=1)  print $0; }' ../data/$l > ./data/train.$l

done
