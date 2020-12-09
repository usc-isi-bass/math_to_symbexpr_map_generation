from nose.tools import *
import os
import tempfile
import subprocess
import uuid

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from code_generation.bin_code_generation import CFile


def test_generate_code_01():
    c = Const(1)
    out = eval_expr(c)
    assert_equal(out, '1')

def test_generate_code_02():
    v = Var('a')
    out = eval_expr(v, '1')
    assert_equal(out, '1')

    out = eval_expr(v, '2')
    assert_equal(out, '2')

def test_generate_code_03():
    c = Const(1)
    v = Var('a')
    expr = AddOp(c, v)
    out = eval_expr(expr, '1')
    assert_equal(out, '2')

    out = eval_expr(expr, '2')
    assert_equal(out, '3')

def test_generate_code_04():
    c = Const(5)
    v1 = Var('a')
    v2 = Var('b')
    expr = AddOp(c, MulOp(v1, v2))
    out = eval_expr(expr, '2', '2')
    assert_equal(out, '9')

    out = eval_expr(expr, '2', '3')
    assert_equal(out, '11')

def test_generate_code_05():
    c = Const(5)
    v1 = Var('a')
    v2 = Var('b')
    expr = AddOp(v1, PowFunc(c, v2))
    out = eval_expr(expr, '2', '2')
    assert_equal(out, '27')

    out = eval_expr(expr, '4', '3')
    assert_equal(out, '129')

def test_generate_code_mod_func():
    c = Const(5)
    v = Var('a')
    expr = ModOp(c, FabsFunc(v))
    out = eval_expr(expr, '-2')
    assert_equal(out, '1')


def eval_expr(expr, *args):
    ccg = CCodeGenerator(expr)

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
