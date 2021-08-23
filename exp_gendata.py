#!/usr/bin/env python3

import angr
import claripy
import logging

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.ubitree import *
from expression.ubitree import expression_to_prefix, expression_to_infix
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor, sym_prefix_to_infix
from code_generation.bin_code_generation import CFile


def gen_symexpr(expr, ret_type):
    ccg = CCodeGenerator(expr, ret_type)
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    
    c_file_name = 'gen_exp.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see  = SymbolicExpressionExtractor(bin_file_name)
    sym_expr = see.extract(target_func, var_names, var_ctypes, ret_type, False)
    return sym_expr

def gen_rand_for_type(c_type):
    """
    if c_type == "int":
        print("Integer Only:")
    else:
        print("=============")
        print("Mix types:")
    """
    # Create a generator. Refer to expression/ubitree.py for parameters
    i = 2
    if c_type == "int":
        generator = UbiTreeGenerator(max_ops=i, num_leaves=i*5, max_int=10, int_only=True, use_bit_op=False, use_mathlib=True)
    else:
        generator = UbiTreeGenerator(max_ops=i, num_leaves=i*5, max_int=10, int_only=False, use_bit_op=False, use_mathlib=True)
    prefix_stack = generator.generate_ubitree_stack(10*i,[1,0])

    # Convert the stack into expression.components
    if c_type == "int":
        expr = prefix_stack_to_expression(prefix_stack, True)
    else:
        expr = prefix_stack_to_expression(prefix_stack)
    sym_expr = gen_symexpr(expr, c_type)
    print("Natural:")
    print(expr)
    #print(sym_expr.symex_expr)
    
    print("======= prefix =======")
    print("math:")
    print(expression_to_prefix(expr))
    print("--------")
    print("sym:")
    print(sym_expr.symex_to_prefix())
    print()

    print("======= infix =======")
    print("math:")
    print(expression_to_infix(expr))
    print("sym:")
    print(sym_prefix_to_infix(sym_expr.symex_to_prefix()))

    print()
    print()

def main():
    #gen_rand_for_type("int")
    for i in range(10):
        gen_rand_for_type("int")
        exit(0)



if __name__ == '__main__':
    main()

