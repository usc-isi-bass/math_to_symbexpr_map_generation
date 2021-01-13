#!/usr/bin/env bash

fairseq-preprocess --source-lang sym --target-lang math \
	--trainpref train/train --validpref train/valid --testpref train/test \
	--destdir data-bin --workers 20

