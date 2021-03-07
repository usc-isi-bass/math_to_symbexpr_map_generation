from nose.tools import *
import os

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor, sym_prefix_to_infix
from code_generation.bin_code_generation import CFile

import logging
logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

def _do_expr(expr, ret_type):
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
    os.remove(c_file_name)
    os.remove(bin_file_name)
    return extracted_symexpr

def test_sequence():
    expr = MulOp(Var('a', "int"), TanFunc(AddOp(Var('b', "int"), Var('c', "double"))))

    sym_expr = _do_expr(expr, "float")

    pre_sym = sym_expr.symex_to_prefix()
    in_sym = sym_prefix_to_infix(sym_expr.symex_to_prefix())
    prefix = ['*', 'tan', '+', 'b', 'c', 'a']
    infix = ['(', 'tan', '(', '(', 'b', '+', 'c', ')', ')', '*', 'a', ')']
    assert_equal(pre_sym, prefix)
    assert_equal(in_sym, infix)
