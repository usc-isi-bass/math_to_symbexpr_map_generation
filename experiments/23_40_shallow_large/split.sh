#!/usr/bin/env bash

src=sym
tgt=math

echo "creating train, valid, test..."
for l in $src $tgt; do
    awk '{if (NR%23 == 0)  print $0; }' ../../large_data/data_infix/$l.large > ./data/valid.$l
    awk '{if (NR%23 == 1)  print $0; }' ../../large_data/data_infix/$l.large > ./data/test.$l
    awk '{if (NR%23 != 0 && NR%23 !=1)  print $0; }' ../../large_data/data_infix/$l.large > ./data/train.$l

done
