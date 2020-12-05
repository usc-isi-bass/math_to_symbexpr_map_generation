from nose.tools import *

from expression.components import *

def test_const():
    assert_equal(Const.num_children, 0)

def test_var():
    assert_equal(Var.num_children, 0)
    v = Var(1)
    assert_equal(len(v.children), Var.num_children)

def test_add_op():
    v = Var(1)
    assert_equal(AddOp.num_children, 2)
    e = AddOp(v, v)
    assert_equal(len(e.children), AddOp.num_children)

def test_sub_op():
    v = Var(1)
    assert_equal(SubOp.num_children, 2)
    e = SubOp(v, v)
    assert_equal(len(e.children), SubOp.num_children)

def test_mul_op():
    v = Var(1)
    assert_equal(MulOp.num_children, 2)
    e = MulOp(v, v)
    assert_equal(len(e.children), MulOp.num_children)

def test_div_op():
    v = Var(1)
    assert_equal(DivOp.num_children, 2)
    e = DivOp(v, v)
    assert_equal(len(e.children), DivOp.num_children)

def test_mod_op():
    v = Var(1)
    assert_equal(ModOp.num_children, 2)
    e = ModOp(v, v)
    assert_equal(len(e.children), ModOp.num_children)

def test_neg_op():
    v = Var(1)
    assert_equal(NegOp.num_children, 1)
    e = NegOp(v)
    assert_equal(len(e.children), NegOp.num_children)

def test_pow_op():
    v = Var(1)
    assert_equal(PowFunc.num_children, 2)
    e = PowFunc(v, v)
    assert_equal(len(e.children), PowFunc.num_children)

def test_sqrt_op():
    v = Var(1)
    assert_equal(SqrtFunc.num_children, 1)
    e = SqrtFunc(v)
    assert_equal(len(e.children), SqrtFunc.num_children)

