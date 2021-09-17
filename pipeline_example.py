#!/usr/bin/env python3
import angr
import claripy
import logging
logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from expression.ubitree import *
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
from code_generation.bin_code_generation import CFile

def main():
    # Create an integer-only generator
    generator = UbiTreeGenerator(max_ops=3, num_leaves=5, max_int=30, int_only=True)
    prefix_stack = generator.generate_ubitree_stack(1)
    expr = prefix_stack_to_expression(prefix_stack)

    print("Natural Expression:")
    print(expr)

    print("")
    print("----")
    do_expr(expr)


def do_expr(expr):
    ccg = CCodeGenerator(expr)
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    var_ctypes = generated_c_code.expr_var_ctypes

    print("Generated C code:")
    print(code)
    print("")
    print("----")
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()


    print("Symbolic Expression:")
    see  = SymbolicExpressionExtractor(bin_file_name)
    extracted_symexpr = see.extract(target_func, var_names, var_ctypes, 'int')
    ast = extracted_symexpr.symex_expr
    print(ast)
    ast_z3 = claripy.backends.z3.convert(ast)
    print(ast_z3)

    print("Simplified:")
    in_sym = extracted_symexpr.symex_to_infix()
    print("".join(in_sym))

if __name__ == '__main__':
    main()
