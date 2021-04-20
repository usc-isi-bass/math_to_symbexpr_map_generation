#!/usr/bin/env python3
import logging

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.components import *
from expression.ubitree import expression_to_prefix, expression_to_infix
from code_generation.c_code_generation import CCodeGenerator
from backward_slice.backward_slice_extraction import BackwardVexExtractor, combine_stmt_list
from code_generation.bin_code_generation import CFile
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor, sym_prefix_to_infix


def main():
    see = SymbolicExpressionExtractor("manual")

    target_func = "Quaternion_fromAxisAngle_ret"
    var_names = ["axis", "angle", "output"]
    var_ctypes= ["int", "double", "int"]
    ret_type = "double"
    print("Before:")
    sym_expr = see.extract(target_func, var_names, var_ctypes, ret_type, False)
    print(sym_expr.symex_to_infix())

    target_func = "Quaternion_fromAxisAngle"
    print()
    print("Init memory with args offsets, capture Store instructions:")
    name, sym_expr = see.extract_middle(target_func, var_names, var_ctypes, 0x17cb, 92, False)
    print(name)
    print(sym_expr.symex_to_infix())
    print()
    print()

    print()
    print("-------------------")
    target_func = "Quaternion_rotate"
    var_names = ["q", "v", "output"]
    var_ctypes= ["int", "int", "int"]
    ret_type = "int"
    see = SymbolicExpressionExtractor("manual")
    name, sym_expr = see.extract_middle(target_func, var_names, var_ctypes, 0x1473, 184, False)
    print(name)
    print(sym_expr.symex_to_infix())


if __name__ == "__main__":
    main()

