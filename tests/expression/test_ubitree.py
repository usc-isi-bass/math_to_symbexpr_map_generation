from nose.tools import *

from expression.components import *
from expression.ubitree import *

def test_zero_operator():
    generator = UbiTreeGenerator(0, 1, 5)
    # Test several rounds
    for i in range(5):
        # Should only return a_0
        stack = generator.generate_ubitree_stack(1)
        assert_equal(len(stack), 1)
        assert_equal(stack[0][0], 'a_0')
        assert_equal(stack[0][1], 0)

        obj = prefix_stack_to_expression(stack)
        assert_equal(isinstance(obj, Var), True)

        # Should only return integer 0-4
        stack = generator.generate_ubitree_stack(0)
        assert_equal(len(stack), 1)
        assert(stack[0][0] >= 0 and stack[0][0] <= 4)
        assert_equal(stack[0][1], 0)

        obj = prefix_stack_to_expression(stack)
        assert_equal(isinstance(obj, Const), True)

def test_simple_operator():
    generator = UbiTreeGenerator(3, 3, 5)
    # Simplify generator to only these 2 operators
    generator.all_ops = ["AddOp", "NegOp"]
    generator.una_ops = ["NegOp"]
    generator.bin_ops = ["AddOp"]

    # Test several rounds
    for i in range(5):
        op_count = 0
        stack = generator.generate_ubitree_stack(2)
        for op, num_children in stack:
            if num_children == 0:
                if isinstance(op, str):
                    assert(op == "a_0" or op == "a_1")
                else:
                    assert(op >= 0 and op <= 4)
            elif num_children == 1:
                assert_equal(op, "NegOp")
                op_count += 1
            elif num_children == 2:
                assert_equal(op, "AddOp")
                op_count += 1
            else:
                raise ValueError("stack error value")
        assert_equal(op_count, 3)

        obj = prefix_stack_to_expression(stack)
        assert_equal(isinstance(obj, Operator), True)

def test_integer_only():
    generator = UbiTreeGenerator(max_ops=5, num_leaves=5, max_int=10, int_only=True)
    int_only_ops = ["NegOp", "AddOp", "SubOp", "MulOp", "DivOp", "ModOp", "OrOp", "XorOp", "LshiftOp", "RshiftOp", "AbsFunc"]
    # Check the content of this generator
    for op in generator.all_ops:
        assert(op in int_only_ops)

    # Check if this option functions well
    # Assertions are implemented inside the class already. So if it doesn't raise exception, it should be fine.
    for i in range(5):
        stack = generator.generate_ubitree_stack(2)
        obj = prefix_stack_to_expression(stack)
