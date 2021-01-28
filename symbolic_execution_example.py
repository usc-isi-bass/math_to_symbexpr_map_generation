import angr
import claripy
import logging

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from expression.components import *
from code_generation.c_code_generation import CCodeGenerator
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor
from code_generation.bin_code_generation import CFile

def main():
    c = Const(2)
    v1 = Var('a', "float")
    v2 = Var('b', "int")
    #expr = AddOp(SubOp(c1, DivOp(v1, NegOp(c2))), MulOp(AbsFunc(PowFunc(v2, c3)), SqrtFunc(v4)))
    expr = AddOp(c, MulOp(v1, v2))
    do_expr(expr)


def do_expr(expr):
    print("Natural Expression:")
    print(expr)
    ccg = CCodeGenerator(expr, ret_type="float")
    generated_c_code = ccg.generate_code()
    code = generated_c_code.code
    target_func = generated_c_code.wrapper_func
    var_names = generated_c_code.expr_var_names
    var_ctypes = generated_c_code.expr_var_ctypes
    
    c_file_name = 'example_c.c'
    cfile = CFile(c_file_name, code)
    bin_file_name = cfile.compile()


    print("Symbolic Expression:")
    see  = SymbolicExpressionExtractor(bin_file_name)
    extracted_symexpr = see.extract(target_func, var_names, var_ctypes, "float")
    ast = extracted_symexpr.symex_expr
    print(ast)




if __name__ == "__main__":
    main()
