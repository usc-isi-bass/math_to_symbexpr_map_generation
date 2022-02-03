import argparse

parser = argparse.ArgumentParser(description='score mathematical equivalence using sympy')
parser.add_argument('--input', '-i', type=str, help="path to input file.")
parser.add_argument('--output', '-o', default='./balanced.txt', type=str, help="desired output location")

args = parser.parse_args()

with open(args.i) as infile, open(args.o) as outfile:
    for line in infile:
        # TODO check balance and try to rebalance heuristically
