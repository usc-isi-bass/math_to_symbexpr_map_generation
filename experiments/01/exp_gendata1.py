#!/usr/bin/env python3

import angr
import claripy
import logging
from collections import OrderedDict, deque

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.ubitree import *
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
from code_generation.bin_code_generation import CFile

def gen_symexpr(expr):
    ccg = CCodeGenerator(expr)
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    
    c_file_name = 'gen_exp.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see  = SymbolicExpressionExtractor(bin_file_name)
    sym_expr = see.extract(target_func, var_names)
    return sym_expr

def gen_loop(math_fs, sym_fs, ops, num_var):
    # Create a generator. Refer to expression/ubitree.py for parameters
    generator = UbiTreeGenerator(max_ops=ops, num_leaves=ops*5, max_int=10)

    for i in range(ops * 2):
        # Convert the stack into expression.components
        prefix_stack = generator.generate_ubitree_stack(num_var, [1,0])
        expr = prefix_stack_to_expression(prefix_stack)
        sym_expr = gen_symexpr(expr)

        expr_seq = expression_to_seq(expr)
        sym_seq = sym_expr.symex_to_seq()
        #print("+====== Natural ======+")
        print(expr)
        """
        print("--------")
        print(sym_expr.symex_expr)
        print("+====== seq-2-seq ======+")
        print(expr_seq)
        print("--------")
        print(sym_seq)
        print("")
        """

        math_fs.write(' '.join([elem for elem in expr_seq]))
        math_fs.write("\n")

        sym_fs.write(' '.join([elem for elem in sym_seq]))
        sym_fs.write("\n")


def main():

    math_file = "experiments/01/orig/math"
    sym_file = "experiments/01/orig/sym"

    math_fs = open(math_file, "a")
    sym_fs = open(sym_file, "a")

    for i in range(20):
        gen_loop(math_fs, sym_fs, i+1, 10*i+20)


if __name__ == '__main__':
    main()

