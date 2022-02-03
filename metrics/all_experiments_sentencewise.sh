for d in $(ls ../experiments | grep '^[0-9][0-9]_')
do bash run_sentencewise.sh ../experiments/$d/data/valid.math < ../experiments/$d/evaluate_on_valid.out > ../experiments/$d/sentencewise.out
echo $d
done
