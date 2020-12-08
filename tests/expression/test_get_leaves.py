from nose.tools import *

from expression.components import *

def test_get_leaves_01():
    c = Const(5)
    leaves = c.get_leaves()
    assert_equal(len(leaves), 1)
    assert_true(isinstance(leaves[0], Const))
    assert_equal(leaves[0].num, 5)

    v = Var('a')
    leaves = v.get_leaves()
    assert_equal(len(leaves), 1)
    assert_true(isinstance(leaves[0], Var))
    assert_equal(leaves[0].name, 'a')

    v = Var('a')
    expr = NegOp(v)
    leaves = expr.get_leaves()
    assert_equal(len(leaves), 1)
    assert_true(isinstance(leaves[0], Var))
    assert_equal(leaves[0].name, 'a')

def test_get_leaves_02():
    c1 = Const(6)
    v2 = Var('b')
    expr = AddOp(c1, v2)
    leaves = expr.get_leaves()
    assert_equal(len(leaves), 2)
    assert_true(isinstance(leaves[0], Const))
    assert_true(isinstance(leaves[1], Var))
    assert_equal(leaves[0].num, 6)
    assert_equal(leaves[1].name, 'b')

def test_get_leaves_03():
    c1 = Const(6)
    v2 = Var('b')
    v3 = Var('c')
    expr = PowFunc(c1, AddOp(v2, FloorFunc(v3)))
    leaves = expr.get_leaves()
    assert_equal(len(leaves), 3)
    assert_true(isinstance(leaves[0], Const))
    assert_true(isinstance(leaves[1], Var))
    assert_true(isinstance(leaves[2], Var))
    assert_equal(leaves[0].num, 6)
    assert_equal(leaves[1].name, 'b')
    assert_equal(leaves[2].name, 'c')

