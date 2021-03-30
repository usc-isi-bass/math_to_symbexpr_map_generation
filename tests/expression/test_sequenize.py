from nose.tools import *

from expression.components import *
from expression.ubitree import expression_to_prefix, expression_to_infix

def test_sequence():
    expr = MulOp(Var('a', "int"), TanFunc(AddOp(Var('b', "int"), Var('c', "double"))))
    pre_exp = expression_to_prefix(expr)
    in_exp = expression_to_infix(expr)

    prefix = ['*', 'tan', '+', 'b', 'c', 'a']
    infix = ['(', 'a', '*', 'tan', '(', '(', 'b', '+', 'c', ')', ')', ')']

    assert_equal(pre_exp, prefix)
    assert_equal(in_exp, infix)
