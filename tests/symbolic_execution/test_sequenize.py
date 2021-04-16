from nose.tools import *
import os
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'test_binaries')

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
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

    in_sym = sym_expr.symex_to_infix()
    infix = ['tan', '(', 'b', '+', 'c', ')', '*', 'a']
    assert_equal(in_sym, infix)

def test_short_circuit_calls_05():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f05'
    var_ctypes = ['float', 'int']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1, arg2 = 'argf1','argi2'
    symexpr = see.extract(func_name, [arg1, arg2], var_ctypes, "float", short_circuit_calls={0x4007d7:(('float', 'int'), 'float')})
    infix = ['f_inner4', '(', 'argf1', ',', 'argi2', ')']
    in_sym = symexpr.symex_to_infix()
    assert_equal(in_sym, infix)
