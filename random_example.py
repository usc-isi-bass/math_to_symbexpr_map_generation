#!/usr/bin/env python3

from expression.components import *
from expression.ubitree import *

def main():

    # Create a generator. Refer to expression/ubitree.py for parameters
    generator = UbiTreeGenerator(max_ops=5, num_leaves=5, max_int=10)

    # Generate a stack of random expression prefix tree
    #   parameter: number of symbolic values
    #              (Other leaves will be random constant)
    #   stack format:
    #              [(Op name, # of children), ...]
    prefix_stack = generator.generate_ubitree_stack(3)
    print(prefix_stack)

    # Convert the stack into expression.components
    obj = prefix_stack_to_expression(prefix_stack)
    print(type(obj))
    print(obj)

    print("---")
    # Generate another random tree
    prefix_stack2 = generator.generate_ubitree_stack(1)
    obj2 = prefix_stack_to_expression(prefix_stack2)
    print(obj2)

    print("")
    print("--- Integer only:")
    # Create an integer-only generator
    generator = UbiTreeGenerator(max_ops=5, num_leaves=5, max_int=10, int_only=True)
    prefix_stack = generator.generate_ubitree_stack(3)
    obj = prefix_stack_to_expression(prefix_stack)
    print(obj)


if __name__ == '__main__':
    main()
