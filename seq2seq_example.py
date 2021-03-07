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
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor, sym_prefix_to_infix
from code_generation.bin_code_generation import CFile


def main():
    expr = MulOp(Var('a', "int"), TanFunc(AddOp(Var('b', "int"), Var('c', "double"))))

    sym_expr = do_expr(expr, "float")

    print("Natural Expression:")
    print(expr)
    print("--------")
    print("Symbolic Expression (naive printing):")
    print(sym_expr.symex_expr)
    print("\n+====== prefix ======+")
    print("math:")
    print(expression_to_prefix(expr))
    print("--------")
    print("sym:")
    print(sym_expr.symex_to_prefix())
    print("\n+====== infix ======+")
    print("math:")
    print(expression_to_seq(expr))
    print("--------")
    print("sym:")
    print(sym_prefix_to_infix(sym_expr.symex_to_prefix()))


def do_expr(expr, ret_type):
    ccg = CCodeGenerator(expr, ret_type=ret_type)
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()

    see  = SymbolicExpressionExtractor(bin_file_name)
    extracted_symexpr = see.extract(target_func, var_names, var_ctypes, ret_type, False)
    return extracted_symexpr



if __name__ == "__main__":
    main()

