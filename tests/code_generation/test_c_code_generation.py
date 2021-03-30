from nose.tools import *
import os
import subprocess
import sys
import tempfile
import uuid

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from code_generation.bin_code_generation import CFile


def test_generate_code_01():
    c = Const(1)
    out = eval_expr(c, "int")
    assert_equal(out, '1')

def test_generate_code_02():
    v = Var('a')
    out = eval_expr(v, "int", '1')
    assert_equal(out, '1')

    out = eval_expr(v, "int", '2')
    assert_equal(out, '2')

def test_generate_code_03():
    c = Const(1)
    v = Var('a')
    expr = AddOp(c, v)
    out = eval_expr(expr, "int", '1')
    assert_equal(out, '2')

    out = eval_expr(expr, "int", '2')
    assert_equal(out, '3')

def test_generate_code_04():
    c = Const(5)
    v1 = Var('a')
    v2 = Var('b')
    expr = AddOp(c, MulOp(v1, v2))
    out = eval_expr(expr, "int", '2', '2')
    assert_equal(out, '9')

    out = eval_expr(expr, "int", '2', '3')
    assert_equal(out, '11')

def test_generate_code_05():
    c = Const(5)
    v1 = Var('a')
    v2 = Var('b')
    expr = AddOp(v1, PowFunc(c, v2))
    out = eval_expr(expr, "int", '2', '2')
    assert_equal(out, '27')

    out = eval_expr(expr, "int", '4', '3')
    assert_equal(out, '129')

def test_generate_code_mod_func():
    c = Const(5)
    v = Var('a')
    expr = ModOp(c, FabsFunc(v))
    out = eval_expr(expr, "int", '-2')
    assert_equal(out, '1')

def test_generate_long_type():
    c = Const(5)
    v1 = Var('a', "long")
    v2 = Var('b', "long")
    expr = AddOp(v1, PowFunc(c, v2))
    out = eval_expr(expr, "long", '2', '2')
    assert_equal(out, '27')

    out = eval_expr(expr, "long", '4', '3')
    assert_equal(out, '129')

def test_generate_float_type():
    c = Const(5)
    v1 = Var('a', "float")
    v2 = Var('b', "float")
    expr = AddOp(v1, PowFunc(c, v2))
    out = eval_expr(expr, "float", '2', '2')
    assert_almost_equal(float(out), 27)

    out = eval_expr(expr, "float", '4', '3')
    assert_almost_equal(float(out), 129)

def test_generate_double_type():
    c = Const(5)
    v1 = Var('a', "double")
    v2 = Var('b', "double")
    expr = AddOp(v1, PowFunc(c, v2))
    out = eval_expr(expr, "double", '2', '2')
    assert_equal(out, '27.000000')
    assert_almost_equal(float(out), 27)

    out = eval_expr(expr, "float", '4', '3')
    assert_almost_equal(float(out), 129)

def test_generate_mix_type():
    c = Const(5)
    v1 = Var('a', "double")
    v2 = Var('b', "int")
    expr = AddOp(v1, PowFunc(c, v2))
    out = eval_expr(expr, "int", '2', '2')
    assert_equal(out, '27')

    out = eval_expr(expr, "float", '4', '3')
    assert_equal(out, '129.000000')

def eval_expr(expr, ret_type, *args):
    ccg = CCodeGenerator(expr, ret_type=ret_type)

    c_code = ccg.generate_code().code

    output = eval_c_code(c_code, *args)
    return output.strip().decode('ascii')


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
    p = subprocess.Popen([elf_file_name] + list(args), stdout=subprocess.PIPE)
    p.wait()
    assert p.returncode == 0
    outs = p.stdout.read()

    return outs
