from nose.tools import *
import claripy
import os
import hashlib
import tempfile
import subprocess
import uuid
import logging

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from code_generation.bin_code_generation import CFile
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

# angr has errors in its logging :(
logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

def test_extract_01():
    c = Const(1)
    eval_expr(c)

def test_extract_02():
    v = Var('a')
    eval_expr(v, 1)

def test_extract_03():
    v = Var('a')
    c = Const(1)
    expr = AddOp(v, c)
    eval_expr(v, 2)

def test_extract_04():
    v1 = Var('a')
    v2 = Var('b')
    expr = AddOp(v1, v2)
    eval_expr(expr, 1, 2)

def test_extract_05():
    v1 = Var('a')
    v2 = Var('b')
    v3 = Var('c')
    expr = MulOp(AddOp(v1, v2), v3)
    eval_expr(expr, 1, 2, 3)

def eval_expr(expr, *args):
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


    see  = SymbolicExpressionExtractor(elf_file_name)
    extracted_symexpr = see.extract(target_func, var_names)
    symvars = extracted_symexpr.symvars
    ast = extracted_symexpr.symex_expr

    # Evaluate the symex expression, constraining the symbolic vars to the args
    solver = claripy.Solver()
    ast_eval = solver.eval(ast, 1, extra_constraints=[symvar == arg for symvar, arg in zip(symvars, args)])[0]

    # If the extracted symbolic expression is equal to the given expression, they should be equal
    assert_equal(str(ast_eval), output)



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

def main():
    test_extract()

if __name__ == "__main__":
    main()
