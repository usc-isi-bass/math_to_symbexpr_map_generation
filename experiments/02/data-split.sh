#!/usr/bin/env bash

src=sym
tgt=math
lang=sym-math

echo "creating train, valid, test..."
for l in $src $tgt; do
    awk '{if (NR%23 == 0)  print $0; }' orig/$l > train/valid.$l
    awk '{if (NR%23 != 0)  print $0; }' orig/$l > train/train.$l

    cat orig/$l > train/test.$l
done
