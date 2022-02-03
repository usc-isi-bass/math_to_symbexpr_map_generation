from sympy import symbols, simplify
from sympy.core.sympify import SympifyError
import argparse

parser = argparse.ArgumentParser(description='convert symbolic math notation to bracket tree notation')
parser.add_argument('input', type=str, help="path to input file to convert")
parser.add_argument('output', type=str, required=False, default="./bracketedtrees.txt", help="desired output location (optional)")

args = parser.parse_args()

with open(args.input) as in_file, open(args.output) as out_file:
    
