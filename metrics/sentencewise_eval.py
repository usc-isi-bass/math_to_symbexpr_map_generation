from apted.helpers import Tree
from apted import APTED
# TODO there is probably a better way to do this? 
from nltk.translate.bleu_score import sentence_bleu
import pandas as pd
import argparse

parser = argparse.ArgumentParser(description='score tree edit distance and produce summary statistics')
parser.add_argument('--ref', type=str, help="path to reference (gold/ground truth) translations)")
parser.add_argument('--hyp', type=str, help="path to generated translations (results only - fairseq markup should be stripped out")

args = parser.parse_args()

with open(args.ref) as ref, open(args.hyp) as hyp:
    scores = []
    for ref_line, hyp_line in zip(ref, hyp):
        try:
            ted = APTED(Tree.from_math(hyp_line.strip()), Tree.from_math(ref_line.strip())).compute_edit_distance()
            bleu = sentence_bleu([ref_line.strip().split()], hyp_line.strip().split())
            scores.append([ted, bleu])
        except:
            print("failed to calculate TED or BLEU. skipping this line.")
            continue
        if len(scores) % 100 == 0:
            print("checked line ", len(scores))

    df = pd.DataFrame(scores, columns=['ted', 'bleu'])
    # save scores
    fname = args.ref.split("data")[0] + "ted-vs-bleu.csv"
    print(fname)
    df.to_csv(fname, header=True, index=False)
        
    # print out counts
    print("Average TED:", round(df['ted'].mean(), 2))
    print("Median TED:", round(df['ted'].median(), 2))
    print("Min. TED:", df['ted'].min())
    print("Max. TED:", df['ted'].max())
    print("Average BLEU:", round(df['bleu'].mean(), 2))
    print("Median BLEU:", round(df['bleu'].median(), 2))
    print("Min. BLEU:", df['bleu'].min())
    print("Max. BLEU:", df['bleu'].max())
