#!/usr/bin/env python

import angr
import claripy
import logging
from collections import OrderedDict, deque

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.ubitree import *
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
from code_generation.bin_code_generation import CFile

import sys

def sim_prefix_to_infix(prefix):
    stack = []

    # read prefix in reverse order
    i = len(prefix) - 1
    while i >= 0:
        if not (prefix[i] == "+" or \
                prefix[i] == "-" or \
                prefix[i] == "*" or \
                prefix[i] == "Concat"):
            # symbol is operand
            stack.append(prefix[i])
            i -= 1
        else:
            # symbol is operator
            op1 = stack.pop()
            if not isinstance(op1, list):
                op1 = [op1]
            op2 = stack.pop()
            if not isinstance(op2, list):
                op2 = [op2]
            sym = ["("] + op1 + [prefix[i]] + op2 + [")"]
            stack.append(sym)
            i -= 1

    return stack.pop()

def gen_symexpr(expr, wid):
    ccg = CCodeGenerator(expr)
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    
    c_file_name = 'gen_exp_%s.c' % wid
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()
    see  = SymbolicExpressionExtractor(bin_file_name)
    sym_expr = see.extract(target_func, var_names)
    return sym_expr

def gen_loop(math_file_01, sym_file_01, math_file_02, sym_file_02, ops, num_var, wid):
    # Create a generator. Refer to expression/ubitree.py for parameters
    generator = UbiTreeGenerator(max_ops=ops, num_leaves=ops*5, max_int=10, int_only=True)

    for i in range(int(ops * ops / 2)):
        # Convert the stack into expression.components
        prefix_stack = generator.generate_ubitree_stack(num_var, [1,0])
        expr = prefix_stack_to_expression(prefix_stack)
        print("%s-%s" % (ops, i))
        sym_expr = gen_symexpr(expr, wid)

        expr_pre = expression_to_prefix(expr)
        sym_pre = sym_expr.symex_to_prefix()

        expr_seq = expression_to_seq(expr)
        sym_seq = sim_prefix_to_infix(sym_expr.symex_to_prefix())
        print(expr)
        print("+====== infix  ======+")
        print(expr_seq)
        print("--------")
        print(sym_seq)
        print("+====== prefix ======+")
        print(expr_pre)
        print("--------")
        print(sym_pre)
        print("")
        print("")

        with open(math_file_01, "a") as fd:
            fd.write(' '.join([elem for elem in expr_seq]))
            fd.write("\n")

        with open(sym_file_01, "a") as fd:
            fd.write(' '.join([elem for elem in sym_seq]))
            fd.write("\n")

        with open(math_file_02, "a") as fd:
            fd.write(' '.join([elem for elem in expr_pre]))
            fd.write("\n")

        with open(sym_file_02, "a") as fd:
            fd.write(' '.join([elem for elem in sym_pre]))
            fd.write("\n")


def main():
    if len(sys.argv) != 3:
        print("./exp_gendata.py <t_dir> <worker_id 0-9>")
        exit(1)
    t_dir = sys.argv[1]
    wid = int(sys.argv[2])

    math_file_01 = "%s/data_01/math.%02d" % (t_dir, wid)
    sym_file_01  = "%s/data_01/sym.%02d"  % (t_dir, wid)
    math_file_02 = "%s/data_02/math.%02d" % (t_dir, wid)
    sym_file_02  = "%s/data_02/sym.%02d"  % (t_dir, wid)

    for i in range(5,30):
        gen_loop(math_file_01, sym_file_01, math_file_02, sym_file_02,i, i+20, wid)


if __name__ == '__main__':
    main()

