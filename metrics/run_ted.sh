in="/dev/stdin"
tmp=$(mktemp)
tmp2=$(mktemp)
out="/dev/stdout"
# ref path should be passed as positional argument 1

# extract predictions from fairseq output
grep ^D $in | awk -F "\t" '{print $3}' > $tmp

# parens balance
python heuristic_balance.py -i $tmp -o $tmp2

# run tree edit distance
python TED_eval.py --ref $1 --hyp $tmp2 > $out
