from apted.helpers import Tree
from apted import APTED
import numpy as np
import argparse

parser = argparse.ArgumentParser(description='score tree edit distance and produce summary statistics')
parser.add_argument('--ref', type=str, help="path to reference (gold/ground truth) translations)")
parser.add_argument('--hyp', type=str, help="path to generated translations (results only - fairseq markup should be stripped out")

args = parser.parse_args()

with open(args.ref) as ref, open(args.hyp) as hyp:
    scores = []
    for ref_line, hyp_line in zip(ref, hyp):
        try:
            scores.append(APTED(Tree.from_math(hyp_line.strip()), Tree.from_math(ref_line.strip())).compute_edit_distance())
        except:
            print("failed calculate TED. skipping this line.")
            continue
        if len(scores) % 100 == 0:
            print("checked line ", len(scores))

    # print out counts
    print("Average TED:", round(np.mean(scores), 2))
    print("Median TED:", round(np.median(scores), 2))
    print("Min. TED:", min(scores))
    print("Max. TED:", max(scores))

    # save scores
    np.save(args.hyp.split(".")[0] + "-TED_scores.npy", scores)
    
