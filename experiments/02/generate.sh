#!/usr/bin/env bash

fairseq-generate data-bin/ \
    --path checkpoints/checkpoint_best.pt \
    --beam 5 --remove-bpe
	
