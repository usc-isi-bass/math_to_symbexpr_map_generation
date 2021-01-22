#!/usr/bin/env python3
import angr
import claripy
import logging
from collections import OrderedDict, deque

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.components import *
from expression.ubitree import expression_to_prefix, expression_to_seq
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
from code_generation.bin_code_generation import CFile

def main():
    v1 = Var('a')
    v2 = Var('b')
    v3 = Var('c')
    expr = MulOp(v2, AddOp(v1, v3))

    sym_expr = do_expr(expr)

    print("Natural Expression:")
    print(expr)
    print("--------")
    print("Symbolic Expression:")
    print(sym_expr.symex_expr)
    print("\n+====== naive ======+")
    print("math:")
    print(expression_to_seq(expr))
    print("--------")
    print("sym:")
    print(sym_expr.symex_to_seq())
    print("\n+====== prefix ======+")
    print("math:")
    print(expression_to_prefix(expr))
    print("--------")
    print("sym:")
    print(sym_expr.symex_to_prefix())


def do_expr(expr):
    ccg = CCodeGenerator(expr)
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()

    see  = SymbolicExpressionExtractor(bin_file_name)
    extracted_symexpr = see.extract(target_func, var_names)
    return extracted_symexpr



if __name__ == "__main__":
    main()

