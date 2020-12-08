from nose.tools import *
import os
import hashlib
import tempfile
import subprocess

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator


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
    c_file_name = write_c_file(c_code)
    elf_file_name = compile_c_file(c_file_name)

    output = run_elf_file(elf_file_name, *args)

    return output
    

def write_c_file(c_code):
    with tempfile.NamedTemporaryFile(prefix='c_code_generation', suffix='.c', delete=False) as tmp_file:
        tmp_file.write(c_code.encode('ascii'))
        return tmp_file.name

def compile_c_file(c_file_name):
    elf_file_name = os.path.splitext(c_file_name)[0]
    p = subprocess.Popen(['gcc', '-o', elf_file_name, c_file_name, '-lm'])
    p.wait()
    retcode = p.returncode
    assert retcode == 0, "Compilation failed: return code: {}".format(retcode)

    return elf_file_name

def run_elf_file(elf_file_name, *args):
    p = subprocess.Popen([elf_file_name] + list(args), stdout=subprocess.PIPE)
    p.wait()
    assert p.returncode == 0
    outs = p.stdout.read()

    return outs




    

def md5_str(string):
    m = hashlib.md5()
    m.update(string)
    string_md5 = m.digest()
    return string_md5
