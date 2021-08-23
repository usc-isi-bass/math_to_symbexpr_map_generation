#!/usr/bin/env python3
import logging

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.components import *
from expression.ubitree import expression_to_prefix, expression_to_infix
from code_generation.c_code_generation import CCodeGenerator
from code_generation.bin_code_generation import CFile
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor


def main():
    elf_file_name = "binaries/test_binaries/branch_symexpr"

    target_func = "branch_double"
    see = SymbolicExpressionExtractor(elf_file_name)
    var_names = ['q1', 'q2']
    var_ctypes = ['double', 'double']
    ret_type = 'double'
    states = see.extract_allstates(target_func, var_names, var_ctypes, ret_type, False)
    for jump_guards, ret_expr in states:
        for g in jump_guards:
            print("".join(e for e in g))
        print("")
        print("".join(e for e in ret_expr))
        print("--")

    exit(0)
    target_func = "branch_int1"
    see = SymbolicExpressionExtractor(elf_file_name)
    var_names = ['q1', 'q2']
    var_ctypes = ['double', 'int']
    ret_type = 'int'
    ret = see.extract(target_func, var_names, var_ctypes, ret_type, False)
    exit(0)
    print(ret.symex_expr)
    print("-")
    print("".join(e for e in ret.symex_to_infix()))
    print()

    exit(0)


    ret = see.extract("branch_int2", var_names, var_ctypes, ret_type, False)
    print(ret.symex_expr)
    print("-")
    print("".join(e for e in ret.symex_to_infix()))
    exit(0)

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
    see = SymbolicExpressionExtractor(elf_file_name)
    name, sym_expr = see.extract_middle(target_func, var_names, var_ctypes, 0x1473, 184, False)
    print(name)
    print(sym_expr.symex_to_infix())


if __name__ == "__main__":
    main()

