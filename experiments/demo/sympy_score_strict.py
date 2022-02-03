from sympy import symbols, simplify
from sympy.core.sympify import SympifyError
import argparse

parser = argparse.ArgumentParser(description='score mathematical equivalence using sympy')
parser.add_argument('--ref', type=str, help="path to reference (gold/ground truth) translations)")
parser.add_argument('--hyp', type=str, help="path to generated translations (results only - fairseq markup should be stripped out")

args = parser.parse_args()

with open(args.ref) as ref, open(args.hyp) as hyp:
    count_total = 0
    count_correct = 0
    for ref_line, hyp_line in zip(ref, hyp):
        try:
            ref_simp = simplify(ref_line)
        except SympifyError:
            print("failed to simplify refernce translation. skipping this line.")
            continue
        count_total += 1
        try:
            hyp_simp = simplify(hyp_line)
        except SympifyError:
            print("failed to simplify generated translation, likely due to unbalanced (). Counting as wrong.")
            continue
        if ref_simp == hyp_simp:
            count_correct += 1

    # print out counts
    print(count_correct, "/", count_total, "lines are equivalent.")
    print(round(count_correct/count_total * 100, 3), "% accuracy.")

