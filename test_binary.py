#!/usr/bin/env python3
import argparse
import claripy
import logging

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from expression.ubitree import *
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
from code_generation.bin_code_generation import CFile

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False


def main(bin_file_name):
    print("Symbolic Expression:")
    see = SymbolicExpressionExtractor(bin_file_name)
    extracted_symexpr = see.extract(target_func, var_names, var_ctypes, 'int')
    ast = extracted_symexpr.symex_expr
    print(ast)
    ast_z3 = claripy.backends.z3.convert(ast)
    print(ast_z3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get symexprs from a binary.')
    parser.add_argument('filename', metavar='FILENAME', type=str, nargs=1,
                        help='path to a binary with expressions')

    args = parser.parse_args()
    main(args.filename[0])
