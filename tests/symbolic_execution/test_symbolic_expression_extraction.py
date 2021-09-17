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

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'test_binaries')

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

def test_short_circuit_calls_01():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f01'
    var_ctypes = ['float', 'float']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    extracted_symexpr = see.extract(func_name, ['x', 'y'], var_ctypes, "float", short_circuit_calls={0x400826:(None, ('float',), 'float')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true(any(t.startswith('f_inner') for t in symex_expr_ops), msg='We replaced the function call to f_inner with an operation named f_inner but this is not in the AST: {}'.format(symex_expr_ops))

def test_short_circuit_calls_02():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f02'
    var_ctypes = ['float', 'float']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    extracted_symexpr = see.extract(func_name, ['x', 'y'], var_ctypes, "float", short_circuit_calls={0x40085e:(None, ('float',), 'float')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true('SinFunc' in symex_expr_ops, msg='We only replaced the function call to f_inner with an operation  named f_inner however, now the "SinFunc" token also disappeared: {}'.format(symex_expr_ops))

def test_short_circuit_calls_03():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f03'
    var_ctypes = ['int', 'int']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1, arg2 = 'arg1','arg2'
    extracted_symexpr = see.extract(func_name, [arg1, arg2], var_ctypes, "int", short_circuit_calls={0x40088a:(None, ('int', 'int'), 'int')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true(any(t.startswith('f_inner2') for t in symex_expr_ops), msg='We replaced the function call to f_inner2 with an operation named f_inner2 but this is not in the AST: {}'.format(symex_expr_ops))

    # Testing that the order of arg1 and arg2 in the operation matches the order passed to the function

    f_inner2_ast = None
    for ast in symex_expr.children_asts():
        if ast.op.startswith('f_inner2'):
            f_inner2_ast = ast
    f_inner2_ast_arg1 = f_inner2_ast.args[0]
    f_inner2_ast_arg2 = f_inner2_ast.args[1]
    assert_true(arg1 in f_inner2_ast_arg1.variables and arg2 not in f_inner2_ast_arg1.variables, msg="We expect only {} to be in the first argument variables of f_inner2, but: {}".format(arg1, f_inner2_ast_arg1.variables))
    assert_true(arg2 in f_inner2_ast_arg2.variables and arg1 not in f_inner2_ast_arg2.variables, msg="We expect only {} to be in the second argument variables of f_inner2, but: {}".format(arg2, f_inner2_ast_arg2.variables))

def test_short_circuit_calls_04():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f04'
    var_ctypes = ['int', 'float']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1, arg2 = 'argi1','argf2'
    extracted_symexpr = see.extract(func_name, [arg1, arg2], var_ctypes, "int", short_circuit_calls={0x4008b1:(None, ('int', 'float'), 'int')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true(any(t.startswith('f_inner3') for t in symex_expr_ops), msg='We replaced the function call to f_inner3 with an operation named f_inner3 but this is not in the AST: {}'.format(symex_expr_ops))

    # Testing that the order of arg1 and arg2 in the operation matches the order passed to the function

    f_inner3_ast = None
    for ast in symex_expr.children_asts():
        if ast.op.startswith('f_inner3'):
            f_inner3_ast = ast
    f_inner3_ast_arg1 = f_inner3_ast.args[0]
    f_inner3_ast_arg2 = f_inner3_ast.args[1]
    assert_true(arg1 in f_inner3_ast_arg1.variables and arg2 not in f_inner3_ast_arg1.variables, msg="We expect only {} to be in the first argument variables of f_inner3, but: {}".format(arg1, f_inner3_ast_arg1.variables))
    assert_true(arg2 in f_inner3_ast_arg2.variables and arg1 not in f_inner3_ast_arg2.variables, msg="We expect only {} to be in the second argument variables of f_inner3, but: {}".format(arg2, f_inner3_ast_arg2.variables))

def test_short_circuit_calls_05():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f05'
    var_ctypes = ['float', 'int']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1, arg2 = 'argf1','argi2'
    extracted_symexpr = see.extract(func_name, [arg1, arg2], var_ctypes, "float", short_circuit_calls={0x4008d8:(None, ('float', 'int'), 'float')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true(any(t.startswith('f_inner4') for t in symex_expr_ops), msg='We replaced the function call to f_inner4 with an operation named f_inner4 but this is not in the AST: {}'.format(symex_expr_ops))

    # Testing that the order of arg1 and arg2 in the operation matches the order passed to the function

    f_inner4_ast = None
    for ast in symex_expr.children_asts():
        if ast.op.startswith('f_inner4'):
            f_inner4_ast = ast
    f_inner4_ast_arg1 = f_inner4_ast.args[0]
    f_inner4_ast_arg2 = f_inner4_ast.args[1]
    assert_true(arg1 in f_inner4_ast_arg1.variables and arg2 not in f_inner4_ast_arg1.variables, msg="We expect only {} to be in the first argument variables of f_inner4, but: {}".format(arg1, f_inner4_ast_arg1.variables))
    assert_true(arg2 in f_inner4_ast_arg2.variables and arg1 not in f_inner4_ast_arg2.variables, msg="We expect only {} to be in the second argument variables of f_inner4, but: {}".format(arg2, f_inner4_ast_arg2.variables))

def test_short_circuit_calls_06():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f06'
    var_ctypes = ['float']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1 = 'argf1'
    extracted_symexpr = see.extract(func_name, [arg1], var_ctypes, "int", short_circuit_calls={0x4008f6:(None, [], 'int')})
    symex_expr = extracted_symexpr.symex_expr
    assert_true(any(t.startswith('f_inner5') for t in symex_expr.variables), msg='We replaced the function call to f_inner5 with a variable named f_inner5 but this is not in the AST: {}'.format(symex_expr))

def test_short_circuit_calls_07():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f05'
    var_ctypes = ['float', 'int']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1, arg2 = 'argf1','argi2'
    extracted_symexpr = see.extract(func_name, [arg1, arg2], var_ctypes, "float", short_circuit_calls={0x4008d8:('chosen_func_name', ('float', 'int'), 'float')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true(any(t.startswith('chosen_func_name') for t in symex_expr_ops), msg='We replaced the function call to f_inner4 with an operation named chosen_func_name but this is not in the AST: {}'.format(symex_expr_ops))

    # Testing that the order of arg1 and arg2 in the operation matches the order passed to the function

    f_inner4_ast = None
    for ast in symex_expr.children_asts():
        if ast.op.startswith('chosen_func_name'):
            f_inner4_ast = ast
    f_inner4_ast_arg1 = f_inner4_ast.args[0]
    f_inner4_ast_arg2 = f_inner4_ast.args[1]
    assert_true(arg1 in f_inner4_ast_arg1.variables and arg2 not in f_inner4_ast_arg1.variables, msg="We expect only {} to be in the first argument variables of f_inner4, but: {}".format(arg1, f_inner4_ast_arg1.variables))
    assert_true(arg2 in f_inner4_ast_arg2.variables and arg1 not in f_inner4_ast_arg2.variables, msg="We expect only {} to be in the second argument variables of f_inner4, but: {}".format(arg2, f_inner4_ast_arg2.variables))

def test_short_circuit_calls_08():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f06'
    var_ctypes = ['float']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1 = 'argf1'
    extracted_symexpr = see.extract(func_name, [arg1], var_ctypes, "int", short_circuit_calls={0x4008f6:('chosen_func_name', [], 'int')})
    symex_expr = extracted_symexpr.symex_expr
    assert_true(any(t.startswith('chosen_func_name') for t in symex_expr.variables), msg='We replaced the function call to f_inner5 with a variable named chosen_func_name but this is not in the AST: {}'.format(symex_expr))

def test_short_circuit_calls_09():
    elf_name = 'nested_func_call'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f07'
    var_ctypes = ['float']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1 = 'argf1'
    extracted_symexpr = see.extract(func_name, [arg1], var_ctypes, "float", short_circuit_calls={0x400936:(None, ['float'], 'float')})
    symex_expr = extracted_symexpr.symex_expr
    symex_expr_ops = [ast.op for ast in symex_expr.children_asts()]
    assert_true(any(t.startswith('indirect') for t in symex_expr_ops), msg='We did not give a specified name for an indirectly called function. We expected to see a symbolic function named "indirect", but this is not in the AST: {}'.format(symex_expr))


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

if __name__ == "__main__":
    test_short_circuit_calls_01()
    test_short_circuit_calls_02()
    test_short_circuit_calls_03()
    test_short_circuit_calls_04()
    test_short_circuit_calls_05()
    test_short_circuit_calls_06()
    test_short_circuit_calls_07()
    test_short_circuit_calls_08()
    test_short_circuit_calls_09()
