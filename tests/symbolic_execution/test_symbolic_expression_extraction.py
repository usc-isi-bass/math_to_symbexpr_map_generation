from nose.tools import *
import claripy
import os
import hashlib
import tempfile
import subprocess
import uuid
import logging
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from code_generation.bin_code_generation import CFile
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

# angr has errors in its logging :(
logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

def s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)

def test_extract_01():
    c = Const(1)
    eval_int_expr(c)

def test_extract_02():
    v = Var('a')
    eval_int_expr(v, 1)

def test_extract_03():
    v = Var('a')
    c = Const(1)
    expr = AddOp(v, c)
    eval_int_expr(v, 2)

def test_extract_04():
    v1 = Var('a')
    v2 = Var('b')
    expr = AddOp(v1, v2)
    eval_int_expr(expr, 1, 2)

def test_extract_05():
    v1 = Var('a')
    v2 = Var('b')
    v3 = Var('c')
    expr = MulOp(AddOp(v1, v2), v3)
    eval_int_expr(expr, 1, 2, 3)

def test_extract_06():
    v1 = Var('a')
    v2 = Var('b')
    c1 = Const('5')
    expr = MulOp(SubOp(v1, v2), c1)
    eval_int_expr(expr, 1, 2, -5)

def test_mix_type():
    v1 = Var('a', "long")
    v2 = Var('b', "int")
    v3 = Var('c', "double")
    v4 = Var('d', "float")
    expr = DivOp(AddOp(v2, MulOp(v1, v3)), v4)

    ccg = CCodeGenerator(expr, ret_type="float")
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see = SymbolicExpressionExtractor(bin_file_name)
    symexpr = see.extract(target_func, var_names, var_ctypes, "float")

    output = "fpToIEEEBV(fpDiv(RM.RM_NearestTiesEven, fpAdd(RM.RM_NearestTiesEven, fpMul(RM.RM_NearestTiesEven, fpToFP(RM.RM_NearestTiesEven, a, DOUBLE), FPS(c, DOUBLE)), fpToFP(RM.RM_NearestTiesEven, b[31:0], DOUBLE)), fpToFP(RM.RM_NearestTiesEven, fpToFP(fpToIEEEBV(FPS(d, DOUBLE))[31:0], FLOAT), DOUBLE))))[127:32] .. fpToIEEEBV(fpToFP(RM.RM_NearestTiesEven, fpDiv(RM.RM_NearestTiesEven, fpAdd(RM.RM_NearestTiesEven, fpMul(RM.RM_NearestTiesEven, fpToFP(RM.RM_NearestTiesEven, a, DOUBLE), FPS(c, DOUBLE)), fpToFP(RM.RM_NearestTiesEven, b[31:0], DOUBLE)), fpToFP(RM.RM_NearestTiesEven, fpToFP(fpToIEEEBV(FPS(d, DOUBLE))[31:0], FLOAT), DOUBLE)), FLOAT))>"

    assert(output in str(symexpr.symex_expr))

def test_math_func_01():
    v1 = Var('a', "float")
    expr = SinFunc(v1)

    ccg = CCodeGenerator(expr, ret_type="float")
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see = SymbolicExpressionExtractor(bin_file_name)
    symexpr = see.extract(target_func, var_names, var_ctypes, "float")

    assert_true(any(ast.op == 'SinFunc' for ast in symexpr.symex_expr.children_asts()))

def test_math_func_02():
    v1 = Var('a', "float")
    v2 = Var('b', "float")
    expr = PowFunc(v1, CosFunc(v2))

    ccg = CCodeGenerator(expr, ret_type="float")
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see = SymbolicExpressionExtractor(bin_file_name)
    symexpr = see.extract(target_func, var_names, var_ctypes, "float")

    assert_true(any(ast.op == 'CosFunc' for ast in symexpr.symex_expr.children_asts()))
    assert_true(any(ast.op == 'PowFunc' for ast in symexpr.symex_expr.children_asts()))

def test_math_func_03():
    v1 = Var('a', "float")
    v2 = Var('b', "float")
    expr = AddOp(v1, LogFunc(v2))

    ccg = CCodeGenerator(expr, ret_type="float")
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see = SymbolicExpressionExtractor(bin_file_name)
    symexpr = see.extract(target_func, var_names, var_ctypes, "float")

    assert_true(any(ast.op == 'LogFunc' for ast in symexpr.symex_expr.children_asts()))

def eval_int_expr(expr, *args):
    ccg = CCodeGenerator(expr)

    generated_c_code = ccg.generate_code()
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    c_code = generated_c_code.code


    c_file_name = tmp_c_file_name()
    c_file = CFile(c_file_name, c_code)
    elf_file_name = c_file.compile()

    # Get the output of the expression for the given args
    output = run_elf_file(elf_file_name, *args).strip().decode('ascii')

    var_ctypes = list("int" for i in range(len(var_names)))
    see  = SymbolicExpressionExtractor(elf_file_name)
    extracted_symexpr = see.extract(target_func, var_names, var_ctypes, "int")
    symvars = extracted_symexpr.symvars
    ast = extracted_symexpr.symex_expr

    # Evaluate the symex expression, constraining the symbolic vars to the args
    solver = claripy.Solver()
    ast_eval = solver.eval(ast, 1, extra_constraints=[symvar == arg for symvar, arg in zip(symvars, args)])[0]

    # If the extracted symbolic expression is equal to the given expression, they should be equal
    assert_equal(str(s32(ast_eval)), str(int(output)))


    # Test non-simplified extract
    extracted_symexpr = see.extract(target_func, var_names, var_ctypes, "int", False)
    symvars = extracted_symexpr.symvars
    ast = extracted_symexpr.symex_expr

    solver = claripy.Solver()
    ast_eval = solver.eval(ast, 1, extra_constraints=[symvar == arg for symvar, arg in zip(symvars, args)])[0]

    assert_equal(str(s32(ast_eval)), str(int(output)))
    assert(not ("fff") in str(ast))



def eval_c_code(c_code, *args):
    c_file_name = tmp_c_file_name()
    c_file = CFile(c_file_name, c_code)
    elf_file_name = c_file.compile()

    output = run_elf_file(elf_file_name, *args)

    # Clean up
    os.remove(c_file_name)
    os.remove(elf_file_name)

    return output
    

def tmp_c_file_name():
    return os.path.join(tempfile.gettempdir(), '{}_{}.c'.format('test_code_generation', uuid.uuid4().hex))

def run_elf_file(elf_file_name, *args):
    p = subprocess.Popen([elf_file_name] + list(str(arg) for arg in args), stdout=subprocess.PIPE)
    p.wait()
    assert p.returncode == 0
    outs = p.stdout.read()

    return outs
