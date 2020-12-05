from nose.tools import *

from expression.components import *

def test_const():
    c = Const(5)
    assert_equal(c.to_c(), '5')

def test_var():
    v = Var('x')
    assert_equal(v.to_c(), 'x')

def test_add_op():
    c = Const(1)
    v = Var('a')

    expr = AddOp(c, v)
    assert_equal(expr.to_c(), '(1 + a)')

    expr = AddOp(v, c)
    assert_equal(expr.to_c(), '(a + 1)')

def test_sub_op():
    c = Const(2)
    v = Var('b')

    expr = SubOp(c, v)
    assert_equal(expr.to_c(), '(2 - b)')

    expr = SubOp(v, c)
    assert_equal(expr.to_c(), '(b - 2)')

def test_mul_op():
    c = Const(2)
    v = Var('b')

    expr = MulOp(c, v)
    assert_equal(expr.to_c(), '(2 * b)')

    expr = MulOp(v, c)
    assert_equal(expr.to_c(), '(b * 2)')

def test_div_op():
    c = Const(2)
    v = Var('b')

    expr = DivOp(c, v)
    assert_equal(expr.to_c(), '(2 / b)')

    expr = DivOp(v, c)
    assert_equal(expr.to_c(), '(b / 2)')

def test_mod_op():
    c = Const(2)
    v = Var('b')

    expr = ModOp(c, v)
    assert_equal(expr.to_c(), '(2 % b)')

    expr = ModOp(v, c)
    assert_equal(expr.to_c(), '(b % 2)')

def test_neg_op():
    c = Const(2)
    v = Var('b')

    expr = NegOp(c)
    assert_equal(expr.to_c(), '(-2)')

    expr = NegOp(v)
    assert_equal(expr.to_c(), '(-b)')

def test_pow_func():
    c = Const(2)
    v = Var('b')

    expr = PowFunc(c, v)
    assert_equal(expr.to_c(), 'pow(2, b)')

    expr = PowFunc(v, c)
    assert_equal(expr.to_c(), 'pow(b, 2)')

def test_sqrt_func():
    c = Const(2)
    v = Var('b')

    expr = SqrtFunc(c)
    assert_equal(expr.to_c(), 'sqrt(2)')

    expr = SqrtFunc(v)
    assert_equal(expr.to_c(), 'sqrt(b)')

def test_deep():
    c1 = Const(2)
    c2 = Const(3)
    c3 = Const(4)
    v1 = Var('b')
    v2 = Var('c')
    v3 = Var('d')
    v4 = Var('e')

    expr = AddOp(SubOp(c1,DivOp(v1,NegOp(c2))), MulOp(ModOp(PowFunc(v2,c3),v3),SqrtFunc(v4)))
    assert_equal(expr.to_c(), '((2 - (b / (-3))) + ((pow(c, 4) % d) * sqrt(e)))')


